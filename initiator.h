// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/

#ifndef _ETHBLK_INITIATOR_H_
#define _ETHBLK_INITIATOR_H_

#include <linux/blk-mq.h>
#include <linux/genhd.h>
#include <scsi/sg.h>

#include "ethblk.h"

#define ETHBLK_PARTITIONS 16

#define LAT_BUCKETS 64

struct ethblk_initiator_net_stat {
	u32 lat_hist_buckets;
	u32 lat_hist_start;
	u32 lat_hist_bucket_size;
	u16 lat_hist_bucket_grow_factor;
	struct counters {
		unsigned long long rx_count;
		unsigned long long tx_count;
		unsigned long long rx_bytes;
		unsigned long long tx_bytes;
		unsigned long long err_count;
		unsigned long long tx_dropped;
		unsigned long long tx_retry_count;
		unsigned long long rx_err_count;
		unsigned long long rx_late_count;
	} _cnt;
	struct latency {
		u64 read;
		u64 write;
		u64 hist_idx[LAT_BUCKETS];
		u32 hist_read[LAT_BUCKETS];
		u32 hist_write[LAT_BUCKETS];
	} _lat;
};

struct ethblk_initiator_disk_tgt_context {
	int hctx_id;
	int taint;
	int relax_timeout;
} __attribute__((aligned(64)));

struct ethblk_initiator_tgt {
	struct list_head list;
	bool l3;
	unsigned char mac[ETH_ALEN];
	__be32 local_ip;
	__be32 dest_ip;
	bool has_router_mac;
	unsigned char router_mac[ETH_ALEN];
	struct ethblk_initiator_disk *d;
	struct percpu_ref ref;
	struct net_device *nd;
	struct kobject kobj;
	struct ethblk_initiator_disk_tgt_context *ctx;
	int relax_timeout_rearm;
	bool net_stat_enabled;
	bool lat_stat_enabled;
	struct ethblk_initiator_net_stat __percpu *stat;
	char name[ETH_ALEN * 3 + IFNAMSIZ];
};

#define CMD_TIMEOUT_S 30
#define CMD_RETRY_JIFFIES (HZ / 4) /* 250 ms FIXME make RTO */

struct ethblk_initiator_disk_context {
	int hctx_id;
	int current_target_idx;
} __attribute__((aligned(64)));

#define ETHBLK_MAX_TARGETS_PER_DISK 64

struct ethblk_initiator_tgt_array {
	struct rcu_head rcu;
	int nr;
	struct ethblk_initiator_tgt *tgts[ETHBLK_MAX_TARGETS_PER_DISK];
};

struct ethblk_initiator_disk {
	struct list_head list;
	struct rcu_head rcu;
	unsigned short drv_id;
	bool online;
	struct gendisk *gd;
	struct request_queue *queue;
	struct blk_mq_tag_set tag_set;
	sector_t ssize;
	int max_payload;
	int max_possible_payload;
	struct ethblk_initiator_tgt_array __rcu *targets;
	spinlock_t target_lock;
	int seq_id;
	struct work_struct cap_work;
	struct kref ref;
	struct completion destroy_completion;
	int max_cmd;
	struct ethblk_initiator_cmd **cmd;
	struct ethblk_initiator_disk_context *ctx;
	struct kobject kobj;
	struct kobject tgts_kobj;
	bool net_stat_enabled;
	bool lat_stat_enabled;
	struct ethblk_initiator_net_stat __percpu *stat;
	char name[16];
	char uuid[32];
};

struct ethblk_initiator_cmd {
	int id;
	int hctx_idx;
	spinlock_t lock;
	blk_status_t status;
	int retries;
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_tgt *t;
	struct sk_buff *skb;
	unsigned long time_queued;
	unsigned long time_requeued;
	unsigned long time_completed;
	unsigned long gen_id; /* tag generation id */
	bool l3;
	struct ethblk_hdr ethblk_hdr;
} __attribute__((aligned(64)));

void ethblk_initiator_discover_response(struct sk_buff *);
void ethblk_initiator_cmd_response(struct sk_buff *);
void ethblk_initiator_cmd_deferred(struct sk_buff *, int, struct list_head *);
void ethblk_initiator_cmd_deferred_list(struct list_head *);

int ethblk_initiator_start(struct kobject *);
int ethblk_initiator_stop(void);

extern struct ethblk_worker_pool *initiator_workers;

#endif
