// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, 2020 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */
#ifndef _ETHBLK_H_
#define _ETHBLK_H_

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/ip.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 7, 0)
#define SHA_DIGEST_WORDS    SHA1_DIGEST_WORDS
#define SHA_WORKSPACE_WORDS SHA1_WORKSPACE_WORDS
#define sha_init            sha1_init
#define sha_transform       sha1_transform
#endif

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

#define ETHBLK_HDR_MASK_VERSION GENMASK(3, 0)
#define ETHBLK_HDR_MASK_STATUS  GENMASK(6, 4)
#define ETHBLK_HDR_MASK_RESPONSE BIT(7)

#define ETHBLK_HDR_GET_VERSION(hdr) \
	(FIELD_GET(ETHBLK_HDR_MASK_VERSION, hdr->flags[0]))
#define	ETHBLK_HDR_SET_VERSION(hdr, x)		  \
	(hdr->flags[0] &= ETHBLK_HDR_MASK_VERSION, \
	 hdr->flags[0] |= FIELD_PREP(ETHBLK_HDR_MASK_VERSION, x))

#define ETHBLK_HDR_GET_STATUS(hdr) \
	(FIELD_GET(ETHBLK_HDR_MASK_STATUS, hdr->flags[0]))
#define	ETHBLK_HDR_SET_STATUS(hdr, x)		  \
	(hdr->flags[0] &= ETHBLK_HDR_MASK_STATUS, \
	 hdr->flags[0] |= FIELD_PREP(ETHBLK_HDR_MASK_STATUS, x))

#define ETHBLK_HDR_GET_RESPONSE(hdr) \
	(FIELD_GET(ETHBLK_HDR_MASK_RESPONSE, hdr->flags[0]))
#define	ETHBLK_HDR_SET_RESPONSE(hdr, x)		  \
	(hdr->flags[0] &= ETHBLK_HDR_MASK_RESPONSE, \
	 hdr->flags[0] |= FIELD_PREP(ETHBLK_HDR_MASK_RESPONSE, x))

#define ETHBLK_HDR_SET_FLAGS(hdr, v, s, r)				\
	(hdr->flags[0] =						\
	 FIELD_PREP(ETHBLK_HDR_MASK_VERSION, v) |			\
	 FIELD_PREP(ETHBLK_HDR_MASK_STATUS, s) |			\
	 FIELD_PREP(ETHBLK_HDR_MASK_RESPONSE, r))

struct ethblk_hdr {
	__u8 dst[ETH_ALEN];
	__u8 src[ETH_ALEN];
	__be16 type;
	__u8 flags[2];
	__u8 op;
	__be16 drv_id;
	__be64 lba;
	__u8 num_sectors;
	__be32 tag;
/* FIXME need autopadding for target-side word-size DMA alignment */
	__u8 pad[2];
} __attribute__((packed));

struct ethblk_cfg_hdr {
	__be16 q_depth;
	__be16 num_queues;
	__be64 num_sectors;
	__u8 uuid[UUID_SIZE];
} __attribute__((packed));

#define ETHBLK_HDR_SIZE \
	(sizeof(struct ethblk_hdr))

#define ETHBLK_CFG_REPLY_SIZE \
	(sizeof(struct ethblk_hdr) + sizeof(struct ethblk_cfg_hdr))

#define ETHBLK_HDR_L3_SIZE \
	(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))

#define ETHBLK_HDR_SIZE_FROM_CMD(cmd) \
	(ETHBLK_HDR_SIZE + (cmd->l3 ? ETHBLK_HDR_L3_SIZE : 0))

void ethblk_net_init(void);
void ethblk_net_exit(void);

#endif
