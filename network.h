// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, 2020 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#ifndef _ETHBLK_NETWORK_H_
#define _ETHBLK_NETWORK_H_

#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include "ethblk.h"

__be32 ethblk_network_if_get_saddr(struct net_device *nd);
__be32 ethblk_network_if_get_saddr_unlocked(struct net_device *nd);
bool ethblk_network_skb_is_l2(struct sk_buff *skb);
bool ethblk_network_skb_is_l3(struct sk_buff *skb);
bool ethblk_network_skb_is_mine(struct sk_buff *skb);
struct ethblk_hdr *ethblk_network_skb_get_hdr(struct sk_buff *skb);
void *ethblk_network_skb_get_payload(struct sk_buff *skb);

int ethblk_network_xmit_skb(struct sk_buff *);
struct sk_buff *ethblk_network_new_skb(ulong len);
struct sk_buff *ethblk_network_new_skb_with_payload(unsigned long hdr_len,
						    unsigned long payload_len);

struct sk_buff *ethblk_network_new_skb_nd(struct net_device *nd, ulong len);

int ethblk_network_route_l3(struct net_device *nd, __be32 daddr, __be32 saddr,
			    unsigned char *mac);

#endif
