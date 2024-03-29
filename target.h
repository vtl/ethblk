// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, 2020 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#ifndef _ETHBLK_TARGET_H_
#define _ETHBLK_TARGET_H_

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/uuid.h>
#include "ethblk.h"

struct ethblk_target_disk_net_stat {
	struct {
		unsigned long long rx_count;
		unsigned long long tx_count;
		unsigned long long rx_bytes;
		unsigned long long tx_bytes;
		unsigned long long err_count;
		unsigned long long rx_dropped;
		unsigned long long tx_dropped;
	} _cnt;
};

struct ethblk_target_disk_ini {
	struct list_head list;
	struct rcu_head rcu;
	unsigned char mac[ETH_ALEN];
	char name[ETH_ALEN * 3 + IFNAMSIZ + 1];
	__be32 ip;
	struct net_device *nd;
	struct ethblk_target_disk *d;
	struct percpu_ref ref;
	struct kobject kobj;
	struct work_struct free_work;
	struct ethblk_target_disk_net_stat __percpu *stat;
	bool net_stat_enabled;
};

struct ethblk_target_disk {
	struct rcu_head rcu;
	unsigned short drv_id;
	struct list_head initiators;
	char name[16];
	struct block_device *bd;
	struct bio_set bs;
	struct mutex initiator_lock;
	struct percpu_ref ref;
	struct kobject kobj;
	struct kobject inis_kobj;
	struct ethblk_target_disk_net_stat __percpu *stat;
	bool net_stat_enabled;
	struct work_struct destroy_work;
	struct work_struct free_work;
	struct completion destroy_completion;
	char *backend_path;
	uuid_t uuid;
};

enum ethblk_target_cmd_work_type {
	ETHBLK_TARGET_CMD_WORK_TYPE_SKB,
	ETHBLK_TARGET_CMD_WORK_TYPE_BIO,
};

struct ethblk_target_cmd {
	struct list_head list;
	enum ethblk_target_cmd_work_type work_type :2;
	bool l3 :1;
	bool in_headroom :1;
	struct ethblk_target_disk_ini *ini;
	struct bio *bio;
	struct sk_buff *req_skb;
	struct ethblk_hdr *req_hdr;
	struct sk_buff *rep_skb;
};

int ethblk_target_start(struct kobject *);
int ethblk_target_stop(void);

void ethblk_target_handle_discover(struct sk_buff *);
void ethblk_target_cmd(struct ethblk_target_cmd *);
void ethblk_target_cmd_deferred(struct sk_buff *);

#endif
