// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/

#include <linux/module.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include "initiator.h"
#include "network.h"
#include "target.h"

int ethblk_network_route_l3(struct net_device *nd, __be32 daddr, __be32 saddr,
			    unsigned char *mac)
{
	struct rtable *rt = NULL;
	struct neighbour *neigh = NULL;

	rt = ip_route_output(&init_net, daddr, saddr, 0, 0);
	if (IS_ERR(rt))
		return -ENOENT;

	neigh = dst_neigh_lookup(&rt->dst, &daddr);

	if (neigh) {
		rcu_read_lock();
		if (neigh->nud_state & NUD_VALID) {
			ether_addr_copy(mac, neigh->ha);
		} else {
			neigh_event_send(neigh, NULL);
		}
		rcu_read_unlock();
		neigh_release(neigh);
	}

	ip_rt_put(rt);

	return 0;
}

__be32 ethblk_network_if_get_saddr(struct net_device *nd)
{
	struct in_device *in_dev;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	__be32 ret = 0;

	rtnl_lock();
	in_dev = __in_dev_get_rtnl(nd);
	if (in_dev) {
		for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
		     ifap = &ifa->ifa_next) {
			ret = ifa->ifa_address;
			break;
		}
	}
	rtnl_unlock();
	return ret;
}

bool ethblk_network_skb_is_l2(struct sk_buff *skb)
{
	return skb->protocol == htons(eth_p_type);
}

bool ethblk_network_skb_is_l3(struct sk_buff *skb)
{
	if (!pskb_may_pull(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					sizeof(struct udphdr) +
					sizeof(struct ethblk_hdr) - ETH_HLEN))
		return false;

	return ((skb->protocol == htons(ETH_P_IP) &&
		 (ip_hdr(skb)->protocol == IPPROTO_UDP) &&
		 (ntohs(udp_hdr(skb)->dest) >= eth_p_type) &&
		 /* FIXME eth_p_type for control flow.
		  * Taget network init should scan for free range of
		  * 64 ports, reserve it and sends the note to initiators
		  */
		 (ntohs(udp_hdr(skb)->dest)  < eth_p_type + 64)));
}

bool ethblk_network_skb_is_mine(struct sk_buff *skb)
{
	return ethblk_network_skb_is_l2(skb) ||
	       ethblk_network_skb_is_l3(skb);
}

struct ethblk_hdr *ethblk_network_skb_get_hdr(struct sk_buff *skb)
{
	return (struct ethblk_hdr *)(skb_mac_header(skb) +
				     (ethblk_network_skb_is_l2(skb) ?
				      0 :
				      (sizeof(struct ethhdr) +
				       sizeof(struct iphdr) +
				       sizeof(struct udphdr))));
}

void *ethblk_network_skb_get_payload(struct sk_buff *skb)
{
	return ((unsigned char *)ethblk_network_skb_get_hdr(skb)
		+ sizeof(struct ethblk_hdr));
}

static void ethblk_network_run_deferred(struct sk_buff *skb, void *fn)
{
	struct work_struct *work;
	struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);

	if (!clone) {
		dprintk(err, "can't clone skb\n");
		return;
	}

	work = (void *)clone->cb;

	INIT_WORK(work, fn);
	queue_work(system_unbound_wq, work);
}

int ethblk_network_xmit_skb(struct sk_buff *skb)
{
	struct net_device *ifp;
	int ret;
	char *name;

	ifp = skb->dev;
	if (!ifp) {
		dprintk(err, "skb %p dev is NULL\n", skb);
	}
	name = ifp ? ifp->name : "netif";
	ret = dev_queue_xmit(skb);
	if (ret != NET_XMIT_SUCCESS && net_ratelimit()) {
		switch (ret) {
		case NET_XMIT_DROP:
			pr_warn("ethblk: packet dropeed on %s.  %s\n",
				ifp ? ifp->name : "netif",
				"consider increasing tx_queue_len");
			break;
		case NET_XMIT_CN:
			pr_warn("ethblk: congestion detected on %s\n", name);
			break;
		default:
			pr_warn("ethblk: dev_queue_xmit failed on %s: %d\n", name,
				ret);
			break;
		}
	}
	return ret;
}

static int ethblk_network_recv(struct sk_buff *skb, struct net_device *ifp,
			       struct packet_type *pt,
			       struct net_device *orig_dev)
{
	struct ethblk_hdr *rep_hdr;
	int ret = NET_RX_DROP;

	if (!ethblk_network_skb_is_mine(skb))
		goto exit;

	/* don't process in net/core/ipv4 */
	skb->pkt_type = PACKET_OTHERHOST;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (skb == NULL) {
		dprintk(debug, "iface %s skb %p can't share skb\n", ifp->name,
			skb);
		goto exit;
	}

	if (skb_linearize(skb)) {
		dprintk_ratelimit(debug, "drop non-linearized skb %p\n", skb);
		goto exit;
	}

	skb_push(skb, ETH_HLEN);

	rep_hdr = ethblk_network_skb_get_hdr(skb);

	if ((rep_hdr->version != ETHBLK_PROTO_VERSION)) {
		dprintk(err, "iface %s skb %p version 0x%x\n",
			ifp->name, skb, rep_hdr->version);
		goto exit;
	}

	switch (rep_hdr->op) {
	case ETHBLK_OP_READ:
	case ETHBLK_OP_WRITE:
	case ETHBLK_OP_ID:
		dprintk(debug, "iface %s skb %p L%d ETHBLK IO cmd\n", ifp->name, skb,
			ethblk_network_skb_is_l2(skb) ? 2 : 3);
		if (target_mode && !rep_hdr->response) {
			ethblk_target_cmd_deferred(skb);
			skb = NULL;
		} else if (initiator_mode && rep_hdr->response) {
			ethblk_initiator_cmd_response(skb);
			skb = NULL;
		}
		break;
	case ETHBLK_OP_DISCOVER:
		dprintk(debug, "iface %s skb %p DISCOVER cmd\n", ifp->name, skb);
		if (target_mode && !rep_hdr->response) {
			ethblk_target_handle_discover(skb);
			skb = NULL;
		} else if (initiator_mode && rep_hdr->response) {
			ethblk_network_run_deferred(
				skb,
				ethblk_initiator_discover_response_deferred);
		}
		break;
	default:
		dprintk(err, "iface %s unknown ETHBLK command type 0x%02x\n",
			ifp->name, rep_hdr->op);
		break;
	}
	ret = NET_RX_SUCCESS;
exit:
	if (skb)
		consume_skb(skb);
	return ret;
}

static struct packet_type ethblk_pt __read_mostly = {
	.func = ethblk_network_recv,
};

static struct packet_type ethblk_ip_pt __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ethblk_network_recv,
};

struct sk_buff *ethblk_network_new_skb(unsigned long len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len + MAX_HEADER, GFP_ATOMIC);
	if (skb) {
		skb_reserve(skb, MAX_HEADER);
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb->protocol = htons(eth_p_type);
		skb_checksum_none_assert(skb);
	}
	return skb;
}

struct sk_buff *ethblk_network_new_skb_with_payload(unsigned long hdr_len,
						    unsigned long payload_len)
{
	struct sk_buff *skb;
	int err;

	skb = alloc_skb_with_frags(hdr_len + MAX_HEADER, payload_len, 2, &err,
				   GFP_ATOMIC);
	if (skb) {
		skb_reserve(skb, MAX_HEADER);
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb->protocol = htons(eth_p_type);
		skb_checksum_none_assert(skb);
	}
	return skb;
}

void __init ethblk_net_init(void)
{
	ethblk_pt.type = cpu_to_be16(eth_p_type);
	dev_add_pack(&ethblk_pt);
	dev_add_pack(&ethblk_ip_pt);
}

void ethblk_net_exit(void)
{
	dev_remove_pack(&ethblk_ip_pt);
	dev_remove_pack(&ethblk_pt);
}
