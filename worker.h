// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/

#ifndef _ETHBLK_WORKER_H_
#define _ETHBLK_WORKER_H_

#include <linux/kthread.h>
#include <linux/cpumask.h>

enum ethblk_worker_rps_type {
	ETHBLK_WORKER_RPS_SAME,
	ETHBLK_WORKER_RPS_NEIGHBOUR,
	ETHBLK_WORKER_RPS_AUTO,
	ETHBLK_WORKER_RPS_USERSPACE
};

struct ethblk_worker_pool_rps_stat {
	unsigned long long *in;  /* requests scheduled from this cpu */
	unsigned long long *out; /* requests scheduled to this cpu */
};

struct ethblk_worker_pool_rps {
	struct ethblk_worker_pool_rps_stat __percpu *stat;
	int cpu_out[NR_CPUS]; /* TODO change to sorted list */
};

enum ethblk_worker_cb_type {
	ETHBLK_WORKER_CB_TYPE_INITIATOR_IO,
	ETHBLK_WORKER_CB_TYPE_INITIATOR_DISCOVER
};

struct ethblk_worker_cb {
	struct list_head list;
	void (*fn)(struct ethblk_worker_cb *);
	void *data;
	enum ethblk_worker_cb_type type;
};

struct ethblk_worker {
	int idx;
	struct ethblk_worker_pool *pool;
	struct kthread_worker *worker;
	struct kthread_work work;
	bool active;
	spinlock_t lock;
	struct list_head queue;
};

struct ethblk_worker_pool {
	char name[16];
	struct kmem_cache *cb_cache;
	struct cpumask cpumask;
	struct timer_list rps_reconfig_timer;
	struct ethblk_worker worker[NR_CPUS];
	struct ethblk_worker_pool_rps rps;
};

int
ethblk_worker_create_pool(struct ethblk_worker_pool **p, const char *name,
			  kthread_work_func_t fn,
			  const struct cpumask *cpumask);
void ethblk_worker_destroy_pool(struct ethblk_worker_pool *p);
bool ethblk_worker_enqueue(struct ethblk_worker_pool *p,
			   struct list_head *list);

#endif
