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
#include "worker.h"

int ethblk_network_route_l3(struct net_device *nd, __be32 daddr, __be32 saddr,
			    unsigned char *mac)
{
	struct rtable *rt = NULL;
	struct neighbour *neigh = NULL;
	int ret = -ENOENT;

	rt = ip_route_output(&init_net, daddr, saddr, 0, 0);
	if (IS_ERR(rt))
		goto out;

	neigh = dst_neigh_lookup(&rt->dst, &daddr);

	if (neigh) {
		rcu_read_lock();
		if (neigh->nud_state & NUD_VALID) {
			ether_addr_copy(mac, neigh->ha);
			ret = 0;
		} else {
			neigh_event_send(neigh, NULL);
		}
		rcu_read_unlock();
		neigh_release(neigh);
	}

	ip_rt_put(rt);
out:
	return ret;
}

__be32 ethblk_network_if_get_saddr_unlocked(struct net_device *nd)
{
	struct in_device *in_dev;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	__be32 ret = 0;

	in_dev = __in_dev_get_rtnl(nd);
	if (in_dev) {
		for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
		     ifap = &ifa->ifa_next) {
			ret = ifa->ifa_address;
			break;
		}
	}
	return ret;
}

__be32 ethblk_network_if_get_saddr(struct net_device *nd)
{
	__be32 ret;

	rtnl_lock();
	ret = ethblk_network_if_get_saddr_unlocked(nd);
	rtnl_unlock();
	return ret;
}

bool ethblk_network_skb_is_l2(struct sk_buff *skb)
{
	return skb->protocol == htons(eth_p_type);
}

bool ethblk_network_skb_is_l3(struct sk_buff *skb)
{
	struct udphdr *udp_hdr;

	if (!pskb_may_pull(skb,
			   + sizeof(struct ethhdr)
			   + sizeof(struct iphdr)
			   + sizeof(struct udphdr)
			   + sizeof(struct ethblk_hdr)
			   - ETH_HLEN)) {
		return false;
	}

	/* udp_hdr(skb) does not work correctly with cxgb4??? */
	udp_hdr = (struct udphdr *)(ip_hdr(skb) + 1);

	return ((skb->protocol == htons(ETH_P_IP) &&
		 (ip_hdr(skb)->protocol == IPPROTO_UDP) &&
		 (ntohs(udp_hdr->dest) >= eth_p_type) &&
		 (ntohs(udp_hdr->dest)  < eth_p_type + ip_ports)));
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

int ethblk_network_xmit_skb(struct sk_buff *skb)
{
	struct net_device *ifp;
	int ret;
	char *name;

	ifp = skb->dev;
	if (!ifp) {
		dprintk(err, "skb %px dev is NULL\n", skb);
	}
	name = ifp ? ifp->name : "netif";
	dprintk(debug, "skb %px dev %s\n", skb, name);
	ret = dev_queue_xmit(skb);
	if (ret != NET_XMIT_SUCCESS && net_ratelimit()) {
		switch (ret) {
		case NET_XMIT_DROP:
			pr_warn("ethblk: packet dropped on %s, "
				"consider increasing txqueuelen\n",
				name);
			break;
		case NET_XMIT_CN:
			pr_warn("ethblk: congestion detected on %s\n", name);
			break;
		default:
			pr_warn("ethblk: dev_queue_xmit failed on %s: %d\n",
				name, ret);
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
	struct sk_buff *old_skb = skb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (skb == NULL)
		goto exit;

	if (!pskb_may_pull(skb, sizeof(struct ethblk_hdr) - ETH_HLEN))
		goto exit;

	if (!ethblk_network_skb_is_mine(skb))
		goto exit;

	/* don't process in net/core/ipv4 */
	old_skb->pkt_type = PACKET_OTHERHOST;

#ifdef ETHBLK_NETWORK_LINEARIZE_SKB
	if (skb_linearize(skb)) {
		dprintk_ratelimit(debug, "drop non-linearized skb %px\n", skb);
		goto exit;
	}
#endif

	skb_push(skb, ETH_HLEN);

	rep_hdr = ethblk_network_skb_get_hdr(skb);

	if ((rep_hdr->version != ETHBLK_PROTO_VERSION)) {
		dprintk(debug, "iface %s skb %px version 0x%x\n",
			ifp->name, skb, rep_hdr->version);
		goto exit;
	}

	switch (rep_hdr->op) {
	case ETHBLK_OP_READ:
	case ETHBLK_OP_WRITE:
	case ETHBLK_OP_ID:
	case ETHBLK_OP_CHECKSUM:
		dprintk(debug, "iface %s skb %px L%d ETHBLK IO cmd\n", ifp->name, skb,
			ethblk_network_skb_is_l2(skb) ? 2 : 3);
		if (target_mode && !rep_hdr->response) {
			ethblk_target_cmd_deferred(skb);
			skb = NULL;
		} else if (initiator_mode && rep_hdr->response) {
			ethblk_initiator_cmd_deferred(
				skb,
				ETHBLK_WORKER_CB_TYPE_INITIATOR_IO);
			skb = NULL;
		}
		break;
	case ETHBLK_OP_DISCOVER:
		dprintk(debug, "iface %s skb %px DISCOVER cmd\n", ifp->name, skb);
		if (target_mode && !rep_hdr->response) {
			ethblk_target_cmd_deferred(skb);
			skb = NULL;
		} else if (initiator_mode && rep_hdr->response) {
			ethblk_initiator_cmd_deferred(
				skb,
				ETHBLK_WORKER_CB_TYPE_INITIATOR_DISCOVER);
			skb = NULL;
		}
		break;
	case ETHBLK_OP_CFG_CHANGE:
		dprintk(debug, "iface %s skb %px CFG_CHANGE cmd\n", ifp->name, skb);
		if (initiator_mode && !rep_hdr->response) {
			ethblk_initiator_handle_cfg_change(skb);
			skb = NULL;
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
