// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/

#include <linux/module.h>
#include "ethblk.h"
#include "worker.h"

struct ethblk_worker_pool *
ethblk_worker_create_pool(const char *name, kthread_work_func_t fn,
			  const struct cpumask *cpumask)
{
	struct ethblk_worker_pool *p = NULL;
	struct ethblk_worker *w;
	char kthread_name[16];
	int i;
	struct cpumask *temp;

	temp = kzalloc(sizeof(struct cpumask), GFP_KERNEL);
	if (!temp) {
		dprintk(err, "can't alloc cpumask\n");
		goto out;
	}
	dprintk(info, "creating worker pool '%s' with %d workers\n", name,
		cpumask_weight(cpumask));
	p = kzalloc(sizeof(struct ethblk_worker_pool), GFP_KERNEL);

	if (!p) {
		dprintk(err, "can't alloc worker pool '%s'\n", name);
		goto out;
	}
	strncpy(p->name, name, sizeof(p->name) - 1);

	cpumask_copy(&p->cpumask, cpumask);

	snprintf(kthread_name, sizeof(kthread_name), "%s/%%u", name);

	for_each_cpu (i, &p->cpumask) {
		w = &p->worker[i];
		w->idx = i;
		w->pool = p;
		cpumask_and(temp, cpumask, cpumask_of_node(cpu_to_node(i)));
		w->neighbour = cpumask_next_wrap(i, temp, i, true);
		dprintk(debug, "pool %s worker %d neighbour %d\n", p->name, i,
			w->neighbour);
		INIT_LIST_HEAD(&w->queue);
		spin_lock_init(&w->lock);
		kthread_init_work(&w->work, fn);
		w->worker = kthread_create_worker_on_cpu(i, 0, kthread_name, i);
		if (IS_ERR(w->worker)) {
			dprintk(err, "can't create worker[%d]: %ld\n", i,
				PTR_ERR(w->worker));
			break;
		}
	}
	dprintk(info, "pool '%s' %p created with %d worker(s)\n", p->name, p,
		cpumask_weight(&p->cpumask));
out:
	kfree(temp);
	return p;
}

void ethblk_worker_destroy_pool(struct ethblk_worker_pool *p)
{
	struct ethblk_worker *w;
	int i;

	dprintk(info, "destroying worker pool '%s' %p:\n", p->name, p);
	for_each_cpu (i, &p->cpumask) {
		w = &p->worker[i];
		kthread_destroy_worker(w->worker);
	}
	kfree(p);
	dprintk(info, "pool %p destroyed\n", p);
}

void ethblk_worker_enqueue(struct ethblk_worker_pool *p, struct list_head *list)
{
	int cpu = smp_processor_id();
	int cpu_worker;
	struct ethblk_worker *w;
	bool ret;
	bool active;

	cpu_worker = p->worker[cpu].neighbour;
	dprintk(debug, "me %d neighbour %d\n", cpu, cpu_worker);
	w = &p->worker[cpu_worker];
	dprintk(debug, "enqueue to worker[%d]\n", w->idx);
	spin_lock(&w->lock);
	list_add_tail(list, &w->queue);
	active = w->active;
	if (!w->active)
		w->active = true;
	spin_unlock(&w->lock);

	if (!active)
		ret = kthread_queue_work(w->worker, &w->work);
}
