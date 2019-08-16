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

enum {
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
void ethblk_worker_enqueue(struct ethblk_worker_pool *p,
			   struct list_head *list);

#endif
