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

static int rps = ETHBLK_WORKER_RPS_AUTO;
module_param(rps, int, 0644);
MODULE_PARM_DESC(rps, "Enable request packet CPU steering. 0 - same, "
		      "1 - neighbour (default), 2 - auto, 3 - userspace");

static struct cpumask cpu_zero_mask;

static int ethblk_worker_pool_rps_resteer(struct ethblk_worker_pool *p,
					  /* cpus serving NIC interrupts */
					  const struct cpumask *in_cpumask,
					  /* cpus that ran workers */
					  const struct cpumask *out_cpumask,
					  /* cpus with existing workers */
					  const struct cpumask *w_cpumask)
{
	int ret = 0, cpu, old_cpu, new_cpu;
	struct cpumask *temp = NULL;
	struct cpumask *w = NULL;

	temp = kzalloc(sizeof(struct cpumask), GFP_ATOMIC);
	if (!temp) {
		ret = -ENOMEM;
		goto out;
	}

	w = kzalloc(sizeof(struct cpumask), GFP_ATOMIC);
	if (!w) {
		ret = -ENOMEM;
		goto out;
	}

	cpumask_copy(w, w_cpumask);

	for_each_possible_cpu(cpu) {
		/* cpu does not receive interrupts, no need to resteer */
		if (!cpumask_test_cpu(cpu, in_cpumask))
			continue;

		old_cpu = p->rps.cpu_out[cpu];

		/* check if cpu both receives interrupts and runs worker */

		if (!cpumask_test_cpu(old_cpu, in_cpumask))
			continue;

		/* workers without interrupts */
		cpumask_andnot(temp, w, in_cpumask);
		cpumask_and(temp, temp, cpumask_of_node(cpu_to_node(cpu)));
		new_cpu = cpumask_next_wrap(cpu, temp, nr_cpu_ids, false);

		if (new_cpu == nr_cpu_ids) { /* node is busy */
			cpumask_andnot(temp, w, in_cpumask);
			new_cpu = cpumask_next_wrap(cpu, temp, nr_cpu_ids,
						    false);
			if (new_cpu == nr_cpu_ids) {
				/* hmm, no free cpu */
				continue;
			}
		}

		if (new_cpu != old_cpu) {
			/* no more work for this cpu */
			cpumask_clear_cpu(new_cpu, w);
			dprintk(debug,
				"cpu %d/n%d steers to %d/n%d (was %d/n%d)\n",
				cpu, cpu_to_node(cpu),
				new_cpu, cpu_to_node(new_cpu),
				old_cpu, cpu_to_node(old_cpu));
			p->rps.cpu_out[cpu] = new_cpu;
		}
	}

out:
	kfree(temp);
	kfree(w);
	return ret;
}

static int ethblk_worker_pool_rps_init(struct ethblk_worker_pool *p)
{
	int ret;
	int cpu;
	int _rps = rps;
	struct cpumask *temp;

	temp = kzalloc(sizeof(struct cpumask), GFP_KERNEL);
	if (!temp) {
		dprintk(err, "can't alloc cpumask\n");
		ret = -ENOMEM;
		goto err;
	}

	p->rps.stat = alloc_percpu(struct ethblk_worker_pool_rps_stat);

	if (!p->rps.stat) {
		dprintk(err, "can't alloc rps stat\n");
		ret = -ENOMEM;
		goto err;
	}

	for_each_possible_cpu(cpu) {
		struct ethblk_worker_pool_rps_stat *s =
			per_cpu_ptr(p->rps.stat, cpu);
		s->in = kzalloc(NR_CPUS * 2 * sizeof(typeof(*s->in)), GFP_KERNEL);
		s->out = &s->in[NR_CPUS];
		p->rps.cpu_out[cpu] = 0;
	}

	memset(&cpu_zero_mask, 0, sizeof(cpu_zero_mask));

	switch (_rps) {
	case ETHBLK_WORKER_RPS_USERSPACE:
		dprintk(warn, "RPS steering %d is not yet supported, default to same", rps);
		_rps = ETHBLK_WORKER_RPS_SAME;
		break;
	}

	switch (_rps) {
	case ETHBLK_WORKER_RPS_AUTO:
		/* start as SAME then rebalance */
	case ETHBLK_WORKER_RPS_SAME:
		for_each_possible_cpu(cpu) {
			p->rps.cpu_out[cpu] = cpu;
		}
		break;
	case ETHBLK_WORKER_RPS_NEIGHBOUR:
		for_each_possible_cpu(cpu) {
			int new_cpu;
			cpumask_and(temp, &p->cpumask, cpumask_of_node(cpu_to_node(cpu)));
			new_cpu = cpumask_next_wrap(cpu, temp, nr_cpu_ids, false);
			if (new_cpu == nr_cpu_ids) { /* node is busy */
				continue;
			}
			p->rps.cpu_out[cpu] = new_cpu;
		}
		break;
	}

	for_each_possible_cpu(cpu) {
		dprintk(debug, "cpu %d/n%d steers to %d/n%d\n",
			cpu, cpu_to_node(cpu),
			p->rps.cpu_out[cpu], cpu_to_node(p->rps.cpu_out[cpu]));
	}
	ret = 0;
	goto out;
err:
	kfree(temp);
out:
	return ret;
}

static void ethblk_worker_pool_rps_reconfig(struct timer_list *tl)
{
	struct ethblk_worker_pool *p =
		container_of(tl, struct ethblk_worker_pool, rps_reconfig_timer);
	int cpu, i;
	unsigned long in, out;
	struct cpumask *in_cpumask = NULL, *out_cpumask = NULL;

	if (rps != ETHBLK_WORKER_RPS_AUTO)
		return;

	/* in atomic context */
	in_cpumask = kzalloc(sizeof(struct cpumask), GFP_ATOMIC);
	if (!in_cpumask)
		goto out;

	out_cpumask = kzalloc(sizeof(struct cpumask), GFP_ATOMIC);
	if (!out_cpumask)
		goto out;

	for_each_possible_cpu(cpu) {
		in = out = 0;
		for_each_possible_cpu(i) {
			in  += (per_cpu_ptr(p->rps.stat, i))->in[cpu];
			out += (per_cpu_ptr(p->rps.stat, i))->out[cpu];
		}
		dprintk(debug, "pool %px, cpu %d rcv %08lu, served %08lu, "
			"sending to cpu %d\n",
			p, cpu, in, out, p->rps.cpu_out[cpu]);
		if (in)		/* CPU is serving NIC interrupts */
			cpumask_set_cpu(cpu, in_cpumask);
		if (out)
			cpumask_set_cpu(cpu, out_cpumask);
	}

	ethblk_worker_pool_rps_resteer(p, in_cpumask, out_cpumask, &p->cpumask);

	for_each_possible_cpu(cpu) {
		struct ethblk_worker_pool_rps_stat *s =
			per_cpu_ptr(p->rps.stat, cpu);
		memset(s->in, 0, NR_CPUS * 2 * sizeof(typeof(*s->in)));
	}
out:
	kfree(in_cpumask);
	kfree(out_cpumask);

	mod_timer(tl, jiffies + HZ * 10);
}

int
ethblk_worker_create_pool(struct ethblk_worker_pool **pool,
			  const char *name, kthread_work_func_t fn,
			  const struct cpumask *cpumask)
{
	struct ethblk_worker_pool *p = NULL;
	struct ethblk_worker *w;
	char kthread_name[16];
	int i;
	int ret;

	dprintk(info, "creating worker pool '%s' with %d workers\n", name,
		cpumask_weight(cpumask));
	p = kzalloc(sizeof(struct ethblk_worker_pool), GFP_KERNEL);

	if (!p) {
		dprintk(err, "can't alloc worker pool '%s'\n", name);
		ret = -ENOMEM;
		goto out;
	}

	p->cb_cache = kmem_cache_create(name,
				  sizeof(struct ethblk_worker_cb), 0,
				  SLAB_HWCACHE_ALIGN, NULL);
	if (!p->cb_cache) {
		dprintk(err, "can't create kmem cache\n");
		ret = -ENOMEM;
		goto err;
	}

	strncpy(p->name, name, sizeof(p->name) - 1);

	cpumask_copy(&p->cpumask, cpumask);

	snprintf(kthread_name, sizeof(kthread_name), "%s/%%u", name);

	ret = ethblk_worker_pool_rps_init(p);

	if (ret) {
		dprintk(err, "can't init packet steering\n");
		goto err;
	}

	for_each_cpu (i, &p->cpumask) {
		w = &p->worker[i];
		w->idx = i;
		w->pool = p;
		INIT_LIST_HEAD(&w->queue);
		spin_lock_init(&w->lock);
		kthread_init_work(&w->work, fn);
		w->worker = kthread_create_worker_on_cpu(i, 0, kthread_name, i);
		if (IS_ERR(w->worker)) {
			ret = PTR_ERR(w->worker);
			dprintk(err, "can't create worker[%d]: %d\n", i, ret);
			goto err;
		}
	}

	dprintk(info, "pool '%s' %px created with %d worker(s)\n", p->name, p,
		cpumask_weight(&p->cpumask));
	*pool = p;

	ethblk_worker_pool_rps_resteer(p, &cpu_zero_mask, &cpu_zero_mask, &p->cpumask);
	timer_setup(&p->rps_reconfig_timer, ethblk_worker_pool_rps_reconfig, 0);
	ethblk_worker_pool_rps_reconfig(&p->rps_reconfig_timer);
	ret = 0;
	goto out;
err:
	if (p->cb_cache)
		kmem_cache_destroy(p->cb_cache);

	ethblk_worker_destroy_pool(p);
out:
	return ret;
}

void ethblk_worker_destroy_pool(struct ethblk_worker_pool *p)
{
	struct ethblk_worker *w;
	int cpu;

	dprintk(info, "destroying worker pool '%s' %px:\n", p->name, p);
	del_timer_sync(&p->rps_reconfig_timer);
	for_each_cpu(cpu, &p->cpumask) {
		w = &p->worker[cpu];
		if (w)
			kthread_destroy_worker(w->worker);
	}
/* FIXME sync with dying worker threads */
	for_each_possible_cpu(cpu) {
		kfree((per_cpu_ptr(p->rps.stat, cpu))->in);
	}

	free_percpu(p->rps.stat);
	kmem_cache_destroy(p->cb_cache);
	kfree(p);
	dprintk(info, "pool %px destroyed\n", p);
}

bool ethblk_worker_enqueue(struct ethblk_worker_pool *p, struct list_head *list)
{
	int cpu_in = smp_processor_id();
	int cpu_out;
	struct ethblk_worker *w;
	bool ret = true;
	bool active, empty;
	struct ethblk_worker_pool_rps_stat *s;
	unsigned long flags;

	cpu_out = p->rps.cpu_out[cpu_in];
	w = &p->worker[cpu_out];
	if (!w) {
		dprintk(err, "cpu_in %d cpu_out %d has no worker\n",
			cpu_in, cpu_out);
		ret = false;
		goto out;
	}
	s = per_cpu_ptr(p->rps.stat, cpu_in);
	s->in[cpu_in]++;
	s->out[cpu_out]++;
	dprintk(debug, "enqueue to worker[%d]\n", w->idx);
	spin_lock_irqsave(&w->lock, flags);
	empty = list_empty(&w->queue);
	list_add_tail(list, &w->queue);
	active = w->active;
	if (!w->active)
		w->active = true;
	spin_unlock_irqrestore(&w->lock, flags);

	if (!active)
		ret = kthread_queue_work(w->worker, &w->work);
out:
	return ret;
}
