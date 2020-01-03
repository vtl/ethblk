// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/
#ifndef _ETHBLK_H_
#define _ETHBLK_H_

#include <linux/atomic.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/udp.h>
#include <net/ip.h>

/* Defragment skb. Uncomment if kernel panics in ethblk_network_recv */
//#define ETHBLK_NETWORK_LINEARIZE_SKB

/* Uncomment for IOPS estimation on a fully zero-copy IO path */
//#define ETHBLK_INITIATOR_FAKE_ZEROCOPY

#define VERSION "0.1"

extern int net_stat;
extern unsigned int eth_p_type;
extern int ip_ports;

extern char *log_buf;
#define LOG_ENTRY_SIZE 256

extern bool target_mode;
extern bool initiator_mode;

#define dprintk(level, fmt, arg...)					\
	do {								\
		int __pid, __cpu;					\
		__pid = task_pid_nr(current);				\
		__cpu = smp_processor_id();				\
		pr_##level(						\
			"%s[%s pid:%d cpu:%d] " fmt,			\
			__func__, current->comm, __pid, __cpu, ##arg);	\
	} while (0)

#define dprintk_ratelimit(level, fmt, arg...)                                  \
	do {                                                                   \
		if (printk_ratelimit()) {                                      \
			dprintk(level, fmt, ##arg);                            \
		}                                                              \
	} while (0)

#define ETHBLK_PROTO_VERSION 1

#define	ETHBLK_OP_READ 0
#define	ETHBLK_OP_WRITE 1
#define	ETHBLK_OP_DISCOVER 2
#define	ETHBLK_OP_ID 3
#define	ETHBLK_OP_CFG_CHANGE 4
#define ETHBLK_OP_CHECKSUM 5

struct ethblk_hdr {
	__u8 dst[ETH_ALEN];
	__u8 src[ETH_ALEN];
	__be16 type;
	__u8 version : 4;
	__u8 status : 3;
	__u8 response : 1;
	__u8 op;
	__be16 drv_id;
	__be64 lba;
	__u8 num_sectors;
	__be32 tag;
/* FIXME need autopadding for target-side word-size DMA alignment */
	__u8 pad[3];
} __attribute__((packed));

struct ethblk_cfg_hdr {
	__be16 q_depth;
	__be16 num_queues;
	__be64 num_sectors;
	__u8 uuid[UUID_SIZE];
} __attribute__((packed));

static inline void ethblk_dump_mac(char *s, int len, unsigned char *mac)
{
	snprintf(s, len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
		 mac[2], mac[3], mac[4], mac[5]);
}

void ethblk_net_init(void);
void ethblk_net_exit(void);

#endif
