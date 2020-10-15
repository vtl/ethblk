// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, 2020 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#include <linux/hdreg.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/xarray.h>
#include "ethblk.h"
#include "initiator.h"
#include "network.h"
#include "worker.h"

static bool initiator_running = false;
static struct ethblk_worker_pool *workers;

static int lat_stat = 0;
module_param(lat_stat, int, 0644);
MODULE_PARM_DESC(lat_stat, "Enable per-disk/target latency stats");

static int num_hw_queues = 0;
module_param(num_hw_queues, int, 0644);
MODULE_PARM_DESC(num_hw_queues,
		 "Number of hardware queues (num_online_cpus by default)");

unsigned int eth_p_type = 0x88aa; // FIXME
module_param(eth_p_type, int, 0644);
MODULE_PARM_DESC(eth_p_type, "Ethernet packet type");

static int disk_major = 153;
module_param(disk_major, int, 0644);
MODULE_PARM_DESC(disk_major, "Disk major number (153 by default)");

static int lat_hist_buckets = 64;
static int lat_hist_start = 1000;
static int lat_hist_bucket_size = 1000;
static int lat_hist_bucket_grow_factor = 100;

static int queue_depth = 128;
module_param(queue_depth, int, 0644);
MODULE_PARM_DESC(queue_depth, "Initiator disk queue_depth (128 by default)");

#define CMD_TAG_MASK 0xff

#define TAINT_SCORN (1 > (queue_depth / 4) ? 1 : (queue_depth / 4))
#define TAINT_RELAX 10000

static DEFINE_XARRAY(ethblk_initiator_disks);

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_add_target(struct ethblk_initiator_disk *d,
				 unsigned char *addr, struct net_device *nd,
				 bool l3);
static int ethblk_initiator_disk_remove_target(struct ethblk_initiator_tgt *t);
static void ethblk_initiator_tgt_send_id(struct ethblk_initiator_tgt *t);
static void ethblk_initiator_tgt_free(struct percpu_ref *ref);
static void ethblk_initiator_tgt_free_deferred(struct work_struct *w);

static inline void ethblk_initiator_get_tgt(struct ethblk_initiator_tgt *t)
{
	percpu_ref_get(&t->ref);
}

static inline void ethblk_initiator_put_tgt(struct ethblk_initiator_tgt *t)
{
	percpu_ref_put(&t->ref);
}

static inline void ethblk_initiator_get_disk(struct ethblk_initiator_disk *d)
{
	percpu_ref_get(&d->ref);
}

static inline void ethblk_initiator_put_disk(struct ethblk_initiator_disk *d)
{
	percpu_ref_put(&d->ref);
}

#define NET_STAT_ADD(t, var, val)                                              \
	do {                                                                   \
		if (t) {                                                       \
			if (t->d->net_stat_enabled) {                          \
				struct ethblk_initiator_net_stat *dstat =      \
					this_cpu_ptr(t->d->stat);              \
				dstat->_##var += val;                          \
				if (t->net_stat_enabled) {                     \
					struct ethblk_initiator_net_stat *ts = \
						this_cpu_ptr(t->stat);         \
					ts->_##var += val;                     \
				}                                              \
			}                                                      \
		}                                                              \
	} while (0)

#define NET_STAT_INC(t, var) NET_STAT_ADD(t, var, 1)

#define NET_STAT_GET(struc, var)                                               \
	({                                                                     \
		int cpu;                                                       \
		unsigned long long acc = 0;                                    \
		for_each_possible_cpu (cpu) {                                  \
			acc += (per_cpu_ptr(struc, cpu))->_##var;              \
		}                                                              \
		acc;                                                           \
	})

static struct kobject ethblk_sysfs_initiator_kobj;

#define N_DEVS ((1U << MINORBITS) / ETHBLK_PARTITIONS)

static DEFINE_IDA(ethblk_used_minors);

static long ethblk_initiator_alloc_minor(void)
{
	int ret;

	ret = ida_simple_get(&ethblk_used_minors, 0, N_DEVS, GFP_KERNEL);

	if (ret < 0)
		return ret;

	return ret * ETHBLK_PARTITIONS;
}

static void ethblk_initiator_free_minor(long minor)
{
	minor /= ETHBLK_PARTITIONS;
	WARN_ON(minor >= N_DEVS);

	ida_simple_remove(&ethblk_used_minors, minor);
}

static void
ethblk_initiator_cmd_dump_to_string(struct ethblk_initiator_cmd *cmd, char *ptr,
				    int n)
{
	struct request *req = blk_mq_rq_from_pdu(cmd);
	char *req_name;
	int ret;
	bool has_lba = false;

	switch (req_op(req)) {
	case REQ_OP_READ:
		req_name = "READ";
		has_lba = true;
		break;
	case REQ_OP_WRITE:
		req_name = "WRITE";
		has_lba = true;
		break;
	case REQ_OP_DRV_IN:
		req_name = "PRIVATE";
		has_lba = 1;
		break;
	default:
		req_name = "???";
		break;
	}
	ret = snprintf(ptr, n,
		       "cmd[%d] %px req %px t %px hctx_idx %d gen_id %lu "
		       "retries %d disk %s op %d (%s)",
		       cmd->id, cmd, req, cmd->t, cmd->hctx_idx, cmd->gen_id,
		       cmd->retries, cmd->d->name, req_op(req), req_name);
	if (has_lba) {
		snprintf(ptr + ret, n - ret, " lba %llu len %u",
			 be64_to_cpu(cmd->ethblk_hdr.lba),
			 cmd->ethblk_hdr.num_sectors);
	}
}

#define dynamic_pr_debug1(descriptor, fmt, ...)                                \
	do {                                                                   \
		__dynamic_pr_debug(descriptor, pr_fmt(fmt), ##__VA_ARGS__);    \
	} while (0)

#define DEBUG_INI_CMD(level, cmd, fmt, arg...)                                 \
	do {                                                                   \
		int pid = task_pid_nr(current);                                \
		int cpu = smp_processor_id();                                  \
		char *__buf__##__line__ = &log_buf[cpu * LOG_ENTRY_SIZE];      \
		char __attribute__((unused)) _debug, _err, _info;              \
		if (&_##level == &_debug) {                                    \
			DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);        \
			if (DYNAMIC_DEBUG_BRANCH(descriptor)) {                \
				ethblk_initiator_cmd_dump_to_string(           \
					cmd, __buf__##__line__,                \
					LOG_ENTRY_SIZE - 1);                   \
				dynamic_pr_debug1(&descriptor,                 \
						  "%s[%s pid:%d cpu:%d] " fmt  \
						  ": %s\n",                    \
						  __func__, current->comm,     \
						  pid, cpu, ##arg,             \
						  __buf__##__line__);          \
			}                                                      \
		} else {                                                       \
			ethblk_initiator_cmd_dump_to_string(                   \
				cmd, __buf__##__line__, LOG_ENTRY_SIZE - 1);   \
			pr_##level("%s[%s pid:%d cpu:%d] " fmt ": %s\n",       \
				   __func__, current->comm, pid, cpu, ##arg,   \
				   __buf__##__line__);                         \
		}                                                              \
	} while (0)

static int ethblk_initiator_net_stat_prepare_latency_hist(
	struct ethblk_initiator_net_stat *stat, unsigned lat_hist_buckets,
	unsigned lat_hist_start, unsigned lat_hist_bucket_size,
	unsigned lat_hist_bucket_grow_factor)
{
	uint64_t p, b;
	int i;

	if (lat_hist_buckets == 0 || lat_hist_buckets > LAT_BUCKETS)
		return -EINVAL;
	if (lat_hist_start == 0)
		return -EINVAL;
	if (lat_hist_bucket_size == 0)
		return -EINVAL;
	if (lat_hist_bucket_grow_factor < 100 ||
	    lat_hist_bucket_grow_factor > 200)
		return -EINVAL;

	stat->lat_hist_buckets = lat_hist_buckets;
	stat->lat_hist_start = lat_hist_start;
	stat->lat_hist_bucket_size = lat_hist_bucket_size;
	stat->lat_hist_bucket_grow_factor = lat_hist_bucket_grow_factor;

	b = stat->lat_hist_bucket_size;
	for (i = 0, p = stat->lat_hist_start; i < stat->lat_hist_buckets; i++) {
		stat->_lat.hist_idx[i] = p;
		p += b;
		b *= stat->lat_hist_bucket_grow_factor;
		do_div(b, 100);
	}

	return 0;
}

static void
ethblk_initiator_net_stat_clear(struct ethblk_initiator_net_stat __percpu *stat)
{
	int cpu;

	for_each_possible_cpu (cpu) {
		memset(&per_cpu_ptr(stat, cpu)->_cnt, 0, sizeof(stat->_cnt));
		memset(&per_cpu_ptr(stat, cpu)->_lat, 0, sizeof(stat->_lat));
	}
}

static void ethblk_initiator_disk_tgt_stat_clear(struct ethblk_initiator_tgt *t)
{
	dprintk(info, "tgt %s %px\n", t->name, t);

	ethblk_initiator_net_stat_clear(t->stat);
}

static int ethblk_initiator_disk_tgt_stat_hist_init(
	struct ethblk_initiator_tgt *t, int lat_hist_buckets,
	int lat_hist_start, int lat_hist_bucket_size,
	int lat_hist_bucket_grow_factor)
{
	int cpu;

	dprintk(info, "tgt %s buckets:%u start:%u size:%u grow:%u/100\n",
		t->name, lat_hist_buckets,
		lat_hist_start, lat_hist_bucket_size,
		lat_hist_bucket_grow_factor);

	for_each_possible_cpu (cpu) {
		if (ethblk_initiator_net_stat_prepare_latency_hist(
			    per_cpu_ptr(t->stat, cpu), lat_hist_buckets,
			    lat_hist_start, lat_hist_bucket_size,
			    lat_hist_bucket_grow_factor))
			return -EINVAL;
	}
	return 0;
}

static void ethblk_initiator_disk_stat_clear(struct ethblk_initiator_disk *d)
{
	struct ethblk_initiator_tgt *t;
	struct ethblk_initiator_tgt_array *ta;
	int i;

	dprintk(info, "%s\n", d->name);

	ethblk_initiator_net_stat_clear(d->stat);

	rcu_read_lock();
	ta = rcu_dereference(d->targets);
	for (i = 0; i < ta->nr; i++) {
		t = ta->tgts[i];
		ethblk_initiator_disk_tgt_stat_clear(t);
	}
	rcu_read_unlock();
}

static int ethblk_initiator_disk_stat_hist_init(struct ethblk_initiator_disk *d,
						int lat_hist_buckets,
						int lat_hist_start,
						int lat_hist_bucket_size,
						int lat_hist_bucket_grow_factor)
{
	struct ethblk_initiator_tgt *t;
	struct ethblk_initiator_tgt_array *ta;
	int i, cpu, ret;

	dprintk(info, "%s %u %u %u %u\n", d->name, lat_hist_buckets,
		lat_hist_start, lat_hist_bucket_size,
		lat_hist_bucket_grow_factor);

	for_each_possible_cpu (cpu) {
		ret = ethblk_initiator_net_stat_prepare_latency_hist(
			per_cpu_ptr(d->stat, cpu), lat_hist_buckets,
			lat_hist_start, lat_hist_bucket_size,
			lat_hist_bucket_grow_factor);
		if (ret)
			return ret;
	}
	rcu_read_lock();
	ta = rcu_dereference(d->targets);
	for (i = 0; i < ta->nr; i++) {
		t = ta->tgts[i];
		t->net_stat_enabled = d->net_stat_enabled;
		t->lat_stat_enabled = d->lat_stat_enabled;
		ret = ethblk_initiator_disk_tgt_stat_hist_init(
			t, lat_hist_buckets, lat_hist_start,
			lat_hist_bucket_size, lat_hist_bucket_grow_factor);
		if (ret)
			goto out;
	}
	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

static void ethblk_initiator_disk_stat_free(struct ethblk_initiator_disk *d)
{
	if (d->stat)
		free_percpu(d->stat);
}

static int ethblk_initiator_disk_stat_init(struct ethblk_initiator_disk *d)
{
	d->stat = alloc_percpu(struct ethblk_initiator_net_stat);

	if (!d->stat) {
		dprintk(err, "can't alloc net stat\n");
		goto err;
	}

	ethblk_initiator_disk_stat_clear(d);
	ethblk_initiator_disk_stat_hist_init(d, lat_hist_buckets,
					     lat_hist_start,
					     lat_hist_bucket_size,
					     lat_hist_bucket_grow_factor);
	return 0;
err:
	ethblk_initiator_disk_stat_free(d);
	return -ENOMEM;
}

static void ethblk_initiator_tgt_stat_free(struct ethblk_initiator_tgt *t)
{
	if (t->stat)
		free_percpu(t->stat);
}

static int ethblk_initiator_tgt_stat_init(struct ethblk_initiator_tgt *t)
{
	int cpu;

	t->stat = alloc_percpu(struct ethblk_initiator_net_stat);

	if (!t->stat) {
		dprintk(err, "can't alloc net stat\n");
		goto err;
	}

	for_each_possible_cpu (cpu) {
		struct ethblk_initiator_net_stat *stat =
			per_cpu_ptr(t->stat, cpu);

		memset(stat, 0, sizeof(struct ethblk_initiator_net_stat));

		ethblk_initiator_net_stat_prepare_latency_hist(
			stat, lat_hist_buckets, lat_hist_start,
			lat_hist_bucket_size, lat_hist_bucket_grow_factor);
	}

	return 0;
err:
	ethblk_initiator_tgt_stat_free(t);
	return -ENOMEM;
}

static void ethblk_initiator_cmd_stat_account(struct ethblk_initiator_cmd *cmd)
{
	struct request *req = blk_mq_rq_from_pdu(cmd);
	struct ethblk_initiator_net_stat *stat;
	unsigned long lat;
	int i;

	if (!cmd->t)
		return;

	if (cmd->status == BLK_STS_OK) {
		NET_STAT_INC(cmd->t, cnt.rx_count);
		if (rq_data_dir(req) == READ)
			NET_STAT_ADD(cmd->t, cnt.rx_bytes, blk_rq_bytes(req));
	} else {
		NET_STAT_INC(cmd->t, cnt.err_count);
	}

	if (cmd->cpu_submitted == cmd->cpu_completed)
		NET_STAT_INC(cmd->t, cnt.rxtx_same_cpu);
	else
		NET_STAT_INC(cmd->t, cnt.rxtx_other_cpu);

	if (!cmd->t->lat_stat_enabled)
		return;

	stat = this_cpu_ptr(cmd->t->stat);
	lat = cmd->time_completed - cmd->time_queued;

	for (i = 0; i < stat->lat_hist_buckets; i++) {
		if (lat <= stat->_lat.hist_idx[i])
			break;
	}

	if (i >= stat->lat_hist_buckets)
		i = stat->lat_hist_buckets - 1;

	switch (req_op(req)) {
	case REQ_OP_READ:
		NET_STAT_ADD(cmd->t, lat.read, lat);
		NET_STAT_INC(cmd->t, lat.hist_read[i]);
		break;
	case REQ_OP_WRITE:
		NET_STAT_ADD(cmd->t, lat.write, lat);
		NET_STAT_INC(cmd->t, lat.hist_write[i]);
		break;
	default:
		DEBUG_INI_CMD(err, cmd, "unknown req op %d\n", req_op(req));
		break;
	}
}

static int
ethblk_initiator_net_stat_dump(char *buf, int len,
			       struct ethblk_initiator_net_stat __percpu *stat)
{
	int i, ret = 0;
	unsigned long long tmp;

	ret = snprintf(buf, len,
		       "rx-count %llu\ntx-count %llu\nrx-bytes %llu\n"
		       "tx-bytes %llu\ntx-dropped %llu\nerr-count %llu\n"
		       "tx-retry-count %llu\nrx-late-count %llu\n"
		       "rx-tx-same-cpu %llu\nrx-tx-other-cpu %llu\n",
		       NET_STAT_GET(stat, cnt.rx_count),
		       NET_STAT_GET(stat, cnt.tx_count),
		       NET_STAT_GET(stat, cnt.rx_bytes),
		       NET_STAT_GET(stat, cnt.tx_bytes),
		       NET_STAT_GET(stat, cnt.tx_dropped),
		       NET_STAT_GET(stat, cnt.err_count),
		       NET_STAT_GET(stat, cnt.tx_retry_count),
		       NET_STAT_GET(stat, cnt.rx_late_count),
		       NET_STAT_GET(stat, cnt.rxtx_same_cpu),
		       NET_STAT_GET(stat, cnt.rxtx_other_cpu));

	ret += snprintf(buf + ret, len - ret, "rlat-total %llu\n",
			NET_STAT_GET(stat, lat.read));
	ret += snprintf(buf + ret, len - ret, "wlat-total %llu\n",
			NET_STAT_GET(stat, lat.write));
	ret += snprintf(
		buf + ret, len - ret, "rlat-avg %llu\n",
		(tmp = NET_STAT_GET(stat, lat.read),
		 do_div(tmp, max(1ULL, NET_STAT_GET(stat, cnt.tx_count))),
		 tmp));
	ret += snprintf(
		buf + ret, len - ret, "wlat-avg %llu\n",
		(tmp = NET_STAT_GET(stat, lat.write),
		 do_div(tmp, max(1ULL, NET_STAT_GET(stat, cnt.tx_count))),
		 tmp));

	for (i = 0; i < this_cpu_ptr(stat)->lat_hist_buckets - 1; i++) {
		ret += snprintf(buf + ret, PAGE_SIZE - ret,
				"[%d] < %llu ns = r:%llu w:%llu\n", i,
				this_cpu_ptr(stat)->_lat.hist_idx[i],
				NET_STAT_GET(stat, lat.hist_read[i]),
				NET_STAT_GET(stat, lat.hist_write[i]));
	}

	ret += snprintf(buf + ret, len - ret, "[%d] rest = r:%llu w:%llu\n", i,
			NET_STAT_GET(stat, lat.hist_read[i]),
			NET_STAT_GET(stat, lat.hist_write[i]));

	return ret;
}

static ssize_t ethblk_initiator_disk_stat_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct ethblk_initiator_disk *d =
		container_of(kobj, struct ethblk_initiator_disk, kobj);
	int ret;

	ret = ethblk_initiator_net_stat_dump(buf, PAGE_SIZE, d->stat);

	return min((int)PAGE_SIZE, ret);
}

static ssize_t ethblk_initiator_disk_stat_store(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct ethblk_initiator_disk *d =
		container_of(kobj, struct ethblk_initiator_disk, kobj);
	unsigned param[4];
	int ret;

	ret = sscanf(buf, "%u %u %u %u\n", &param[0], &param[1], &param[2],
		     &param[3]);

	dprintk(info, "got %d params\n", ret);

	switch (ret) {
	case 0: /* clear counters */
		ethblk_initiator_disk_stat_clear(d);
		break;
	case 2:
		d->net_stat_enabled = param[0];
		d->lat_stat_enabled = param[1];
		break;
	case 1:
		d->net_stat_enabled = param[0];
		break;
	case 4: /* set new histogram */
		d->lat_stat_enabled = true;
		d->net_stat_enabled = true;
		ethblk_initiator_disk_stat_clear(d);
		ret = ethblk_initiator_disk_stat_hist_init(
			d, param[0], param[1], param[2], param[3]);
		if (ret)
			return ret;
		break;
	default:
		dprintk(err, "can't parse %d params (%s)\n", ret, buf);
		return -EINVAL;
	}

	return count;
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_cmd_get_next_tgt(struct ethblk_initiator_cmd *cmd);
static void
ethblk_initiator_disk_remove_all_targets(struct ethblk_initiator_disk *d);
static inline void ethblk_initiator_put_disk(struct ethblk_initiator_disk *d);

struct ethblk_initiator_put_disk_struct {
	struct work_struct w;
	struct ethblk_initiator_disk *d;
};

static void ethblk_initiator_put_disk_work(struct work_struct *w)
{
	struct ethblk_initiator_put_disk_struct *pds =
		container_of(w, struct ethblk_initiator_put_disk_struct, w);
	ethblk_initiator_put_disk(pds->d);
	kfree(pds);
}

static void ethblk_initiator_put_disk_delayed(struct ethblk_initiator_disk *d)
{
	struct ethblk_initiator_put_disk_struct *pds;

	pds = kmalloc(sizeof(struct ethblk_initiator_put_disk_struct),
		      GFP_KERNEL);
	if (!pds) {
		dprintk(err, "Can't allocate memory for delayed put_disk work. "
			     "Trying to put disk inline (may hang)...\n");
		ethblk_initiator_put_disk(d);
	} else {
		INIT_WORK(&pds->w, ethblk_initiator_put_disk_work);
		pds->d = d;
		schedule_work(&pds->w);
	}
}

static ssize_t
ethblk_initiator_disk_disconnect_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct ethblk_initiator_disk *d =
		container_of(kobj, struct ethblk_initiator_disk, kobj);

	dprintk(info, "disconnecting disk %s %px\n", d->name, d);
	ethblk_initiator_disk_remove_all_targets(d);

	/* this sysfs file needs to be closed for the complete disk removal */
	ethblk_initiator_get_disk(d);
	percpu_ref_kill(&d->ref);
	synchronize_rcu();
	ethblk_initiator_put_disk_delayed(d);

	return count;
}

static struct kobj_attribute ethblk_initiator_disk_disconnect_attr =
	__ATTR(disconnect, 0220, NULL, ethblk_initiator_disk_disconnect_store);

static struct kobj_attribute ethblk_initiator_disk_stat_attr =
	__ATTR(stat, 0660, ethblk_initiator_disk_stat_show,
	       ethblk_initiator_disk_stat_store);

static struct attribute *ethblk_initiator_disk_attrs[] = {
	&ethblk_initiator_disk_disconnect_attr.attr,
	&ethblk_initiator_disk_stat_attr.attr, NULL
};

static struct attribute_group ethblk_initiator_disk_group = {
	.attrs = ethblk_initiator_disk_attrs,
};

static struct kobj_type ethblk_initiator_disk_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static ssize_t ethblk_initiator_disk_tgt_stat_show(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   char *buf)
{
	struct ethblk_initiator_tgt *t =
		container_of(kobj, struct ethblk_initiator_tgt, kobj);
	int ret;

	ret = ethblk_initiator_net_stat_dump(buf, PAGE_SIZE, t->stat);

	return min((int)PAGE_SIZE, ret);
}

static ssize_t ethblk_initiator_disk_tgt_stat_store(struct kobject *kobj,
						    struct kobj_attribute *attr,
						    const char *buf,
						    size_t count)
{
	struct ethblk_initiator_tgt *t =
		container_of(kobj, struct ethblk_initiator_tgt, kobj);
	unsigned param[4];
	int ret;

	ret = sscanf(buf, "%u %u %u %u\n", &param[0], &param[1], &param[2],
		     &param[3]);

	dprintk(info, "got %d params\n", ret);

	switch (ret) {
	case 0: /* clear counters */
		ethblk_initiator_disk_tgt_stat_clear(t);
		break;
	case 2:
		t->lat_stat_enabled = param[1];
		t->net_stat_enabled = param[0];
		break;
	case 1:
		t->net_stat_enabled = param[0];
		break;
	case 4: /* set new histogram */
		ethblk_initiator_disk_tgt_stat_clear(t);
		ret = ethblk_initiator_disk_tgt_stat_hist_init(
			t, param[0], param[1], param[2], param[3]);
		if (ret)
			return ret;
		t->lat_stat_enabled = true;
		t->net_stat_enabled = true;
		break;
	default:
		dprintk(err, "can't parse %d params (%s)\n", ret, buf);
		return -EINVAL;
	}

	return count;
}

static ssize_t
ethblk_initiator_disk_tgt_disconnect_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	struct ethblk_initiator_tgt *t =
		container_of(kobj, struct ethblk_initiator_tgt, kobj);
	int ret;

	dprintk(info, "disk %s disconnecting tgt %s\n", t->d->name, t->name);

	ret = ethblk_initiator_disk_remove_target(t);

	return ret ? ret : count;
}

static ssize_t ethblk_initiator_disk_tgts_add_store(struct kobject *kobj,
						    struct kobj_attribute *attr,
						    const char *buf,
						    size_t count)
{
	struct ethblk_initiator_disk *d =
		container_of(kobj, struct ethblk_initiator_disk, tgts_kobj);
	struct ethblk_initiator_tgt *t;
	struct net_device *nd;
	unsigned char mac[ETH_ALEN];
	unsigned char ip[4];
	char iface[IFNAMSIZ];
	char s[ETH_ALEN * 3 + 1];
	int ret;
	bool l3 = false;
	int i;

	ret = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %s",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],
		     iface);
	if (ret == 7) /* L2 target */
		goto create;

	ret = sscanf(buf, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3],
		     iface);

	if (ret != 5) {
		dprintk(err, "can't parse (%d): %s\n", ret, buf);
		return -EINVAL;
	}
	for (i = 0; i < 4; i++)
		mac[i] = (unsigned char)ip[i];
	l3 = true;

create:
	nd = dev_get_by_name(&init_net, iface);
	if (!nd) {
		dprintk(err, "no network interface %s\n", iface);
		return -EINVAL;
	}

	t = ethblk_initiator_disk_add_target(d, mac, nd, l3);
	dev_put(nd);
	if (!t) {
		dprintk(err, "disk %s can't add target %s_%s (see logs)\n",
			d->name, iface, s);
		return -EINVAL;
	}
	ethblk_initiator_tgt_send_id(t);
	return count;
}

static struct kobj_attribute ethblk_initiator_disk_tgts_add_attr =
	__ATTR(add, 0220, NULL, ethblk_initiator_disk_tgts_add_store);

static struct attribute *ethblk_initiator_disk_tgts_attrs[] = {
	&ethblk_initiator_disk_tgts_add_attr.attr, NULL
};

static struct attribute_group ethblk_initiator_disk_tgts_group = {
	.attrs = ethblk_initiator_disk_tgts_attrs,
};

static struct kobj_type ethblk_initiator_disk_tgts_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static struct kobj_attribute ethblk_initiator_disk_tgt_stat_attr =
	__ATTR(stat, 0660, ethblk_initiator_disk_tgt_stat_show,
	       ethblk_initiator_disk_tgt_stat_store);

static struct kobj_attribute ethblk_initiator_disk_tgt_disconnect_attr = __ATTR(
	disconnect, 0220, NULL, ethblk_initiator_disk_tgt_disconnect_store);

static struct attribute *ethblk_initiator_disk_tgt_attrs[] = {
	&ethblk_initiator_disk_tgt_stat_attr.attr,
	&ethblk_initiator_disk_tgt_disconnect_attr.attr, NULL
};

static struct attribute_group ethblk_initiator_disk_tgt_group = {
	.attrs = ethblk_initiator_disk_tgt_attrs,
};

static struct kobj_type ethblk_initiator_disk_tgt_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static void ethblk_initiator_disk_set_capacity_work(struct work_struct *w)
{
	struct ethblk_initiator_disk *d =
		container_of(w, struct ethblk_initiator_disk, cap_work);
	struct block_device *bd = bdget_disk(d->gd, 0);

	if (bd) {
		loff_t size = (loff_t)get_capacity(d->gd) << SECTOR_SHIFT;
		dprintk(info, "disk %s new size is %lld bytes\n", d->name,
			size);
		inode_lock(bd->bd_inode);
		i_size_write(bd->bd_inode, size);
		inode_unlock(bd->bd_inode);
		bdput(bd);
	}
}

static void ethblk_initiator_disk_free(struct percpu_ref *ref)
{
	struct ethblk_initiator_disk *d =
		container_of(ref, struct ethblk_initiator_disk, ref);

	dprintk(info, "freeing disk %s %px\n", d->name, d);

	ethblk_initiator_disk_remove_all_targets(d);
	sysfs_remove_group(&d->kobj, &ethblk_initiator_disk_group);
	kobject_del(&d->kobj);
	blk_mq_stop_hw_queues(d->queue);
	flush_work(&d->cap_work);
	ethblk_initiator_free_minor(d->gd->first_minor);
	del_gendisk(d->gd);
	blk_cleanup_queue(d->queue);
	blk_mq_free_tag_set(&d->tag_set);
	bioset_exit(&d->bio_set);
	put_disk(d->gd);
	xa_erase(&ethblk_initiator_disks, d->drv_id);
	sysfs_remove_group(&d->tgts_kobj, &ethblk_initiator_disk_tgts_group);
	kobject_del(&d->tgts_kobj);
	kfree(d->cmd);
	kfree(d->ctx);
	ethblk_initiator_disk_stat_free(d);
	percpu_ref_exit(&d->ref);
	complete(&d->destroy_completion);
	kfree_rcu(d, rcu);
	dprintk(info, "disk %px eda%d freed\n", d, d->drv_id);
}

static int ethblk_blk_open(struct block_device *bdev, fmode_t mode)
{
	struct ethblk_initiator_disk *d = bdev->bd_disk->private_data;
	dprintk(debug, "disk %s opened by %s\n", d->name, current->comm);
	ethblk_initiator_get_disk(d);
	return 0;
}

static void ethblk_blk_release(struct gendisk *disk, fmode_t mode)
{
	struct ethblk_initiator_disk *d = disk->private_data;
	dprintk(debug, "disk %s closed by %s\n", d->name, current->comm);
	ethblk_initiator_put_disk_delayed(d);
}

static int ethblk_blk_ioctl(struct block_device *bdev, fmode_t mode,
			    unsigned int cmd, unsigned long arg)
{
	struct ethblk_initiator_disk *d;

	if (!arg)
		return -EINVAL;

	d = bdev->bd_disk->private_data;

	switch (cmd) {
	case HDIO_GET_IDENTITY:
		if (!copy_to_user((void __user *)arg, &d->uuid,
				  sizeof(d->uuid)))
			return 0;
		return -EFAULT;
	case BLKFLSBUF:
		return 0;
	default:
		break;
	}

	return -ENOTTY;
}

static int ethblk_blk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
// FIXME
	/* struct ethblk_initiator_disk *d = bdev->bd_disk->private_data; */
	/* geo->cylinders = d->geo.cylinders; */
	/* geo->heads = d->geo.heads; */
	/* geo->sectors = d->geo.sectors; */
	return 0;
}

static const struct block_device_operations ethblk_bdops = {
	.open = ethblk_blk_open,
	.release = ethblk_blk_release,
	.ioctl = ethblk_blk_ioctl,
	.getgeo = ethblk_blk_getgeo,
	.owner = THIS_MODULE,
};

static void
ethblk_initiator_cmd_fill_skb_headers(struct ethblk_initiator_cmd *cmd,
				      struct sk_buff *skb)
{
	if (cmd->l3) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
		struct iphdr *ip = (struct iphdr *)(eth + 1);
		struct udphdr *udp = (struct udphdr *)(ip + 1);
		struct request *req = blk_mq_rq_from_pdu(cmd);
		struct ethblk_initiator_disk_tgt_context *tctx = &cmd->t->ctx[cmd->hctx_idx];
		int port;

		/* FIXME make tunable per-disk */
		if (blk_rq_bytes(req) > cmd->t->max_payload)
			port = (tctx->port++ >> 3) % cmd->t->num_queues;
		else
			port = smp_processor_id() % cmd->t->num_queues;

		skb_put(skb, ETHBLK_HDR_L3_SIZE);
		skb->protocol = htons(ETH_P_IP);
		eth->h_proto = htons(ETH_P_IP);
		ip->version = 4;
		ip->ihl = 5;
		ip->ttl = 255;
		ip->protocol = IPPROTO_UDP;
		ip->frag_off = htons(IP_DF);
		ip->id = 0;
		/* NOTE to fool Mellanox packet steering we have to
		 * use semi-random source/dest ports */
		udp->source = htons(eth_p_type + port);
		udp->dest = htons(eth_p_type);
	} else {
		skb->protocol = htons(eth_p_type);
	}
}

static void
ethblk_initiator_cmd_finalize_skb_headers(struct ethblk_initiator_cmd *cmd,
					  struct sk_buff *skb)
{
	if (cmd->l3) {
		struct ethblk_hdr *h = &cmd->ethblk_hdr;
		struct ethhdr *eth = eth_hdr(skb);
		struct iphdr *ip = (struct iphdr *)(eth + 1);
		struct udphdr *udp = (struct udphdr *)(ip + 1);
		int tot_len;

		ether_addr_copy(eth->h_source, h->src);
		ip->saddr = cmd->t->local_ip;
		ip->daddr = cmd->t->dest_ip;

		if (!cmd->t->has_router_mac) {
			if (ethblk_network_route_l3(cmd->t->nd,
						    ip->daddr, ip->saddr,
						    cmd->t->router_mac) == 0)
				cmd->t->has_router_mac = true;
		}

		if (cmd->t->has_router_mac) {
			ether_addr_copy(eth->h_dest, cmd->t->router_mac);
		} else {
			ether_addr_copy(eth->h_dest, h->dst);
		}

		tot_len = skb->len - sizeof(struct ethhdr);
		ip->tot_len = htons(tot_len);
		udp->len = htons(tot_len - sizeof(struct iphdr));
		udp->check = 0;
		ip_send_check(ip);
	}
}

static void ethblk_initiator_cmd_hdr_init(struct ethblk_initiator_cmd *cmd,
					  struct ethblk_hdr *h,
					  int skb_idx)
{
	struct ethblk_initiator_disk *d = cmd->d;
	struct ethblk_initiator_tgt *t = cmd->t;
	unsigned int gen_id = cmd->gen_id & CMD_TAG_MASK;
	unsigned int host_tag = (skb_idx << 24) | (gen_id << 16) | cmd->id;

//	DEBUG_INI_CMD(debug, cmd, "host_tag = %d", host_tag);
	ether_addr_copy(h->src, t->nd->dev_addr);
	ether_addr_copy(h->dst, t->mac);
	h->type = cpu_to_be16(eth_p_type);
	ETHBLK_HDR_SET_FLAGS(h, ETHBLK_PROTO_VERSION, 0, 0);
	h->drv_id = cpu_to_be16(d->drv_id);
	h->tag = cpu_to_be32(host_tag);
}

static blk_status_t
ethblk_initiator_cmd_id(struct ethblk_initiator_cmd *cmd)
{
	struct sk_buff *skb;
	struct ethblk_hdr *h;
	struct ethblk_initiator_tgt *t;

	t = ethblk_initiator_disk_cmd_get_next_tgt(cmd);
	if (!t)
		return BLK_STS_NEXUS;

	cmd->t = t; /* this is just for hdr_init */
	cmd->l3 = t->l3;

	skb = ethblk_network_new_skb(ETH_ZLEN);

	DEBUG_INI_CMD(debug, cmd, "skb = %px", skb);

	ethblk_initiator_cmd_fill_skb_headers(cmd, skb);
	skb_put(skb, ETHBLK_HDR_SIZE);

	h = ethblk_network_skb_get_hdr(skb);

	cmd->gen_id++;
	ethblk_initiator_cmd_hdr_init(cmd, &cmd->ethblk_hdr, 0);
	memcpy(h, &cmd->ethblk_hdr, ETHBLK_HDR_SIZE);

	skb->dev = t->nd;

	ethblk_initiator_cmd_finalize_skb_headers(cmd, skb);
	cmd->t = NULL;

	if (ethblk_network_xmit_skb(skb) == NET_XMIT_DROP) {
		NET_STAT_INC(t, cnt.tx_dropped);
	} else {
		NET_STAT_INC(t, cnt.tx_count);
	}

	ethblk_initiator_put_tgt(t);

	return BLK_STS_OK;
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_find_tgt_by_id(struct ethblk_initiator_disk *d, int id)
{
	struct ethblk_initiator_tgt *t = NULL;
	struct ethblk_initiator_tgt_array *ta;
	int i;

	rcu_read_lock();
	ta = rcu_dereference(d->targets);

	for (i = 0; i < ta->nr; i++) {
		if (id == ta->tgts[i]->id) {
			t = ta->tgts[i];
			ethblk_initiator_get_tgt(t);
			break;
		}
	}
	rcu_read_unlock();
	return t;
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_cmd_get_next_tgt(struct ethblk_initiator_cmd *cmd)
{
	struct ethblk_initiator_disk *d = cmd->d;
	struct ethblk_initiator_tgt *t = NULL;
	struct ethblk_initiator_tgt_array *ta;
	struct ethblk_initiator_disk_context *ctx = &d->ctx[cmd->hctx_idx];
	struct ethblk_initiator_disk_tgt_context *tctx;
	int i;

	rcu_read_lock();
	ta = rcu_dereference(d->targets);
	if (ta->nr == 0) {
		goto out_notgt;
	}

	i = ctx->current_target_idx;

	if (ta->nr == 1) {
		t = ta->tgts[0];
		goto out;
	}

	do {
		i++;
		if (i >= ta->nr)
			i = 0;
		dprintk(debug,
			"looping over to %d (current_target_idx %d, "
			"ta->nr %d)\n",
			i, ctx->current_target_idx, ta->nr);
		t = ta->tgts[i];
		tctx = &t->ctx[cmd->hctx_idx];

		if (tctx->taint < TAINT_SCORN) {
			dprintk(debug, "tgt[%d] taint %d < %d, take it\n", i,
				tctx->taint, TAINT_SCORN);
			break;
		}
		tctx->relax_timeout--;
		if (tctx->relax_timeout == 0) {
			tctx->relax_timeout = t->relax_timeout_rearm;
			tctx->taint = max(tctx->taint - 1, 0);
			dprintk(debug,
				"tgt[%d] taint %d > %d, but it relaxed "
				"for %d rounds, take it\n",
				i, tctx->taint, TAINT_SCORN,
				tctx->relax_timeout);
			break;
		}
	} while (i != ctx->current_target_idx);

out:
	dprintk(debug,
		"disk %s has %d target(s) at %px ctx %d prev tgt[%d] %s "
		"next tgt[%d] %s\n",
		d->name, ta->nr, ta, d->ctx->hctx_id, ctx->current_target_idx,
		ta->tgts[ctx->current_target_idx]->name, i, t->name);
	ctx->current_target_idx = i;

	ethblk_initiator_get_tgt(t);
out_notgt:
	rcu_read_unlock();
	return t;
}

static struct bio*
ethblk_initiator_cmd_rw_split_bio(struct ethblk_initiator_cmd *cmd,
				  struct bio *bio)
{
	struct bio *split = NULL;
	int skb_bytes;
	int bio_size = bio_sectors(bio) << SECTOR_SHIFT;

	if (cmd->nr_skbs == ETHBLK_INITIATOR_CMD_MAX_SKB)
		goto out;

	skb_bytes = min(cmd->t->max_payload, bio_size);

	if (bio_size > skb_bytes) {
		dprintk(debug, "bio %px size %d > %d, splitting\n", bio, bio_size, skb_bytes);
		split = bio_split(bio, skb_bytes / SECTOR_SIZE, GFP_ATOMIC, &cmd->d->bio_set);
		if (!split) {
			dprintk_ratelimit(err, "can't split bio\n");
			goto out;
		}
	} else {
		split = bio;
	}

	DEBUG_INI_CMD(debug, cmd, "skb_idx %d, nr_skbs %d, offset %d, bio %px", cmd->skb_idx, cmd->nr_skbs, cmd->offset, split);
	cmd->offsets[cmd->skb_idx] = cmd->offset;
	cmd->offset += skb_bytes;
	cmd->skb_idx++;
	cmd->nr_skbs++;
out:
	return split;
}

static struct sk_buff *
ethblk_initiator_cmd_rw_prepare_skb(struct ethblk_initiator_cmd *cmd,
				    int skb_idx)
{
	struct request *req = blk_mq_rq_from_pdu(cmd);
	struct ethblk_hdr *hdr;
	struct sk_buff *skb = NULL;
	int skb_bytes;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct bio *bio = cmd->bios[skb_idx];

	if (!bio)
		goto out;

	skb = cmd->skbs[skb_idx];
	if (skb) {
		skb->truesize -= skb->data_len;
		skb_shinfo(skb)->nr_frags = skb->data_len = 0;
		skb_trim(skb, 0);
	} else {
		skb = ethblk_network_new_skb(ETHBLK_HDR_SIZE_FROM_CMD(cmd));
		if (!skb)
			goto out;
		cmd->skbs[skb_idx] = skb;
	}

	skb_get(skb);

	eth = (struct ethhdr *)skb_mac_header(skb);
	ip = (struct iphdr *)(eth + 1);
	udp = (struct udphdr *)(ip + 1);

	ethblk_initiator_cmd_fill_skb_headers(cmd, skb);
	skb_put(skb, ETHBLK_HDR_SIZE);

	hdr = ethblk_network_skb_get_hdr(skb);
	skb_bytes = bio_sectors(bio) * SECTOR_SIZE;

	hdr->num_sectors = bio_sectors(bio);
	hdr->lba = cpu_to_be64(blk_rq_pos(req) + (cmd->offsets[skb_idx] / SECTOR_SIZE));

	if (rq_data_dir(req) == WRITE) {
		struct bvec_iter bi = bio->bi_iter;
		struct bio_vec bv;
		int skb_bytes_remaining = skb_bytes;
		int frag = 0;

		do {
			while (bi.bi_size && skb_bytes_remaining) {
				int bv_bytes;

				bv = bio_iter_iovec(bio, bi);
				bv_bytes = min((int)bv.bv_len, skb_bytes_remaining);

				dprintk(debug,
					"skb fill frag %d page %px offset %d len %d\n",
					frag, bv.bv_page, bv.bv_offset, bv_bytes);
				skb_fill_page_desc(skb, frag++, bv.bv_page,
						   bv.bv_offset, bv_bytes);
				get_page(bv.bv_page);
				skb_bytes_remaining -= bv_bytes;
				bio_advance_iter(bio, &bi, bv_bytes);
			}

			dprintk(debug, "cmd bi.bi_size %d, skb_bytes_remaining %d\n", bi.bi_size, skb_bytes_remaining);
		} while (bi.bi_size && skb_bytes_remaining);

		skb->len += skb_bytes;
		skb->data_len = skb_bytes;
		skb->truesize += skb_bytes;
		hdr->op = ETHBLK_OP_WRITE;
	} else {
		hdr->op = ETHBLK_OP_READ;
	}

	ethblk_initiator_cmd_hdr_init(cmd, hdr, skb_idx);

	skb->dev = cmd->t->nd;

	ethblk_initiator_cmd_finalize_skb_headers(cmd, skb);

	dprintk(debug, "cmd[%d] tag %u skb_idx %d offset %d\n",
		cmd->id, hdr->tag, skb_idx, cmd->offsets[skb_idx]);
out:
	return skb;
}

static bool
ethblk_initiator_cmd_rw_prepare_skbs(struct ethblk_initiator_cmd *cmd,
				     struct sk_buff_head *queue)
{
	bool ret = false;
	struct sk_buff *skb;
	int i;

	for (i = 0; i < cmd->nr_skbs; i++) {
		if (!(skb = ethblk_initiator_cmd_rw_prepare_skb(cmd, i))) {
			dprintk_ratelimit(err, "can't alloc skb\n");
			goto out;
		}
		__skb_queue_tail(queue, skb);
	}
	ret = true;
out:
	return ret;
}

static bool
ethblk_initiator_cmd_rw_xmit_skbs(struct ethblk_initiator_cmd *cmd,
				  struct sk_buff_head *queue)
{
	struct request *req = blk_mq_rq_from_pdu(cmd);
	struct sk_buff *skb;
	bool ret = false;

	/* xmit skbs */
	while ((skb = skb_dequeue(queue))) {
		struct ethblk_hdr *hdr = ethblk_network_skb_get_hdr(skb);
		int wlen = hdr->num_sectors << SECTOR_SHIFT;
		int ret;

		ret = ethblk_network_xmit_skb(skb);
		if ((ret == NET_XMIT_DROP) || (ret == NET_XMIT_CN)) {
			NET_STAT_INC(cmd->t, cnt.tx_dropped);
			goto out;
		}
		NET_STAT_INC(cmd->t, cnt.tx_count);
		if (rq_data_dir(req) == WRITE)
			NET_STAT_ADD(cmd->t, cnt.tx_bytes, wlen);
	}
	ret = true;
out:
	return ret;
}

static blk_status_t
ethblk_initiator_cmd_rw(struct ethblk_initiator_cmd *cmd)
	__must_hold(&cmd->lock)
{
	struct request *req = blk_mq_rq_from_pdu(cmd);
	blk_status_t status;
	struct sk_buff *skb;
	struct sk_buff_head queue;
	struct bio *bio;
	int i;

	if (!req->bio) {
		status = BLK_STS_NOTSUPP;
		goto out;
	}

	skb_queue_head_init(&queue);

	cmd->t = ethblk_initiator_disk_cmd_get_next_tgt(cmd);

	if (!cmd->t) {
		DEBUG_INI_CMD(err, cmd, "no target");
		status = BLK_STS_NEXUS;
		goto out;
	}
	cmd->l3 = cmd->t->l3;

	cmd->gen_id++;
	cmd->skb_idx = 0;
	cmd->nr_skbs = 0;
	cmd->offset = 0;
	if (blk_rq_bytes(req) > cmd->t->max_payload) {
		bio = bio_clone_fast(req->bio, GFP_ATOMIC, &cmd->d->bio_set);
	} else {
		bio = req->bio;
		bio_get(bio);
	}

	cmd->ethblk_hdr.num_sectors = blk_rq_bytes(req) / SECTOR_SIZE;
	cmd->ethblk_hdr.lba = cpu_to_be64(blk_rq_pos(req));
	cmd->ethblk_hdr.op = rq_data_dir(req) == WRITE ?
			      ETHBLK_OP_WRITE : ETHBLK_OP_READ;

	ethblk_initiator_cmd_hdr_init(cmd, &cmd->ethblk_hdr, 0);

	/* split bio */
	for (i = 0; cmd->offset < blk_rq_bytes(req); i++) {
		if (cmd->bios[i])
			bio_put(cmd->bios[i]);
		if (!(cmd->bios[i] = ethblk_initiator_cmd_rw_split_bio(cmd, bio))) {
			dprintk_ratelimit(err, "can't alloc bio\n");
			status = BLK_STS_RESOURCE;
			goto out_err;
		}
	}

	if (!ethblk_initiator_cmd_rw_prepare_skbs(cmd, &queue)) {
		status = BLK_STS_RESOURCE;
		goto out_err;
	}

	if (!ethblk_initiator_cmd_rw_xmit_skbs(cmd, &queue)) {
		status = BLK_STS_RESOURCE;
		goto out_err;
	}
	status = BLK_STS_OK;
	goto out;
out_err:
	while ((skb = skb_dequeue(&queue)))
		consume_skb(skb);
	ethblk_initiator_put_tgt(cmd->t);
out:
	return status;
}

static blk_status_t
ethblk_initiator_cmd_rw_partial_retry(struct ethblk_initiator_cmd *cmd)
	__must_hold(&cmd->lock)
{
	blk_status_t status = BLK_STS_RESOURCE;
	struct sk_buff_head queue;
	struct sk_buff *skb;
	int i, ni;
	unsigned short *old_offsets = cmd->offsets;
	struct bio **old_bios = cmd->bios;
	int old_offset = cmd->offset;
	int old_skb_idx = cmd->skb_idx;
	int old_nr_skbs = cmd->nr_skbs;
	struct ethblk_initiator_tgt *old_t = cmd->t;

	cmd->t = ethblk_initiator_disk_cmd_get_next_tgt(cmd);

	if (!cmd->t) {
		DEBUG_INI_CMD(err, cmd, "no target");
		status = BLK_STS_NEXUS;
		goto out_err;
	}

	cmd->offsets = kcalloc(ETHBLK_INITIATOR_CMD_MAX_SKB,
			       sizeof(*cmd->offsets), GFP_ATOMIC);
	if (!cmd->offsets)
		goto out_err;

	cmd->bios = kcalloc(ETHBLK_INITIATOR_CMD_MAX_SKB,
			    sizeof(*cmd->bios), GFP_ATOMIC);
	if (!cmd->bios)
		goto out_err;

	skb_queue_head_init(&queue);

	cmd->l3 = cmd->t->l3;
	cmd->gen_id++;
	cmd->skb_idx = 0;
	cmd->nr_skbs = 0;

	/*
	  iterate over unfinished sub-bios, split according to
	  payload of new tgt
	 */
	for (i = ni = 0; i < ETHBLK_INITIATOR_CMD_MAX_SKB; i++) {
		struct bio *bio = old_bios[i];

		if (!bio)
			continue;

		dprintk(debug, "cmd[%d] found unfinished bio[%d] offset %d", cmd->id, i, old_offsets[i]);

		cmd->offset = old_offsets[i];

		do {
			struct bio *split = ethblk_initiator_cmd_rw_split_bio(cmd, bio);

			if (!split) {
				dprintk_ratelimit(err, "can't alloc bio\n");
				goto out_err;
			}

			cmd->bios[ni++] = split;

			if (split == bio) /* no split */
				break;
		} while (ni < ETHBLK_INITIATOR_CMD_MAX_SKB);
		old_bios[i] = NULL;
	}

	if (!ethblk_initiator_cmd_rw_prepare_skbs(cmd, &queue)) {
		status = BLK_STS_RESOURCE;
		goto out_err;
	}

	if (!ethblk_initiator_cmd_rw_xmit_skbs(cmd, &queue)) {
		status = BLK_STS_RESOURCE;
		goto out_err;
	}

	kfree(old_offsets);
	kfree(old_bios);

	if (old_t)
		ethblk_initiator_put_tgt(old_t);

	status = BLK_STS_OK;
	goto out;

out_err:
	while ((skb = skb_dequeue(&queue)))
		consume_skb(skb);
	for (i = 0; i < ETHBLK_INITIATOR_CMD_MAX_SKB; i++) {
		if (cmd->bios[i])
			bio_put(cmd->bios[i]);
	}
	kfree(cmd->offsets);
	kfree(cmd->bios);
	cmd->offsets = old_offsets;
	cmd->bios = old_bios;
	cmd->offset = old_offset;
	cmd->skb_idx = old_skb_idx;
	cmd->nr_skbs = old_nr_skbs;
	if (cmd->t)
		ethblk_initiator_put_tgt(cmd->t);
	cmd->t = old_t;
out:
	return status;
}

static blk_status_t
ethblk_initiator_blk_queue_request(struct blk_mq_hw_ctx *hctx,
				   const struct blk_mq_queue_data *bd)
{
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);
	blk_status_t status = BLK_STS_NOTSUPP;
	unsigned long current_time;

	if (!cmd->d->online) {
		status = BLK_STS_NEXUS;
		goto out;
	}

	spin_lock_bh(&cmd->lock);

	if (cmd->retries)
		dprintk(info,
			"cmd[%d] req %px req_op %d lba %llu len %u retries %d\n",
			cmd->id, bd->rq, req_op(bd->rq),
			(unsigned long long)blk_rq_pos(bd->rq),
			blk_rq_bytes(bd->rq), cmd->retries);
	else
		dprintk(debug,
			"cmd[%d] req %px req_op %d lba %llu len %u retries %d\n",
			cmd->id, bd->rq, req_op(bd->rq),
			(unsigned long long)blk_rq_pos(bd->rq),
			blk_rq_bytes(bd->rq), cmd->retries);
	cmd->retries = 0;
	cmd->time_queued = cmd->time_requeued = current_time = ktime_get_ns();
	cmd->cpu_submitted = smp_processor_id();

	blk_mq_start_request(bd->rq);

	if (!blk_rq_is_passthrough(bd->rq)) {
		status = ethblk_initiator_cmd_rw(cmd);
	} else {
		status = ethblk_initiator_cmd_id(cmd);
	}

	spin_unlock_bh(&cmd->lock);
out:
	return status;
}

static int ethblk_initiator_blk_init_request(struct blk_mq_tag_set *set,
					     struct request *req,
					     unsigned int hctx_idx,
					     unsigned int numa_node)
{
	int ret = -ENOMEM;
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(req);
	int id_size = 1UL << (8 * (sizeof_field(struct ethblk_hdr, tag) / 2));

	cmd->d = set->driver_data;
	cmd->hctx_idx = hctx_idx;
	cmd->id = cmd->d->max_cmd++;
	if (cmd->id >= id_size) {
		dprintk(err, "cmd[%d] hctx %d would not fit in ETHBLK TAG\n",
			cmd->id, hctx_idx);
		goto out;
	}
	cmd->retries = 0;
	cmd->gen_id = 0;
	cmd->time_queued = cmd->time_completed = 0;
	spin_lock_init(&cmd->lock);
	cmd->d->cmd[cmd->id] = cmd;
	if (cmd->d->max_cmd < cmd->id)
		cmd->d->max_cmd = cmd->id;
	cmd->offsets = kcalloc(ETHBLK_INITIATOR_CMD_MAX_SKB,
			       sizeof(*cmd->offsets), GFP_KERNEL);
	if (!cmd->offsets)
		goto out;

	cmd->bios = kcalloc(ETHBLK_INITIATOR_CMD_MAX_SKB,
			    sizeof(*cmd->bios), GFP_KERNEL);
	if (!cmd->bios)
		goto offsets;

	cmd->skbs = kcalloc(ETHBLK_INITIATOR_CMD_MAX_SKB, sizeof(*cmd->skbs),
			    GFP_KERNEL);
	if (!cmd->skbs)
		goto bios;

	ret = 0;
	goto out;
bios:
	kfree(cmd->bios);
	cmd->bios = NULL;
offsets:
	kfree(cmd->offsets);
	cmd->offsets = NULL;
out:
	return ret;
}

static void ethblk_initiator_blk_exit_request(struct blk_mq_tag_set *set,
					      struct request *req,
					      unsigned int hctx_idx)
{
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(req);
	int i;

	for (i = 0; i < ETHBLK_INITIATOR_CMD_MAX_SKB; i++) {
		if (cmd->bios[i])
			bio_put(cmd->bios[i]);
		if (cmd->skbs[i])
			consume_skb(cmd->skbs[i]);
	}
	kfree(cmd->offsets);
	kfree(cmd->bios);
	kfree(cmd->skbs);
}

static void ethblk_initiator_blk_complete_request_locked(struct request *req)
	__must_hold(&cmd->lock)
{
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(req);

	cmd->time_completed = ktime_get_ns();
	ethblk_initiator_cmd_stat_account(cmd);
	cmd->time_queued = 0; /* prepare for the next round */

	DEBUG_INI_CMD(debug, cmd, "status %d", cmd->status);
	cmd->retries = 0;
	if (cmd->t) {
		if (cmd->status == BLK_STS_OK) {
			struct ethblk_initiator_disk_tgt_context *tctx =
				&cmd->t->ctx[cmd->hctx_idx];
			tctx->taint = max_t(int, tctx->taint - 1, 0);
		}
		ethblk_initiator_put_tgt(cmd->t);
		cmd->t = NULL;
	}

	blk_mq_end_request(req, cmd->status);
}

static void ethblk_initiator_blk_complete_request(struct request *req)
{
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(req);

	/* This only called from blk_mq_complete request, no BH is needed  */
	spin_lock(&cmd->lock);
	ethblk_initiator_blk_complete_request_locked(req);
	spin_unlock(&cmd->lock);
}

static enum blk_eh_timer_return
ethblk_initiator_blk_request_timeout(struct request *req, bool reserved)
{
	struct ethblk_initiator_cmd *cmd = blk_mq_rq_to_pdu(req);
	enum blk_eh_timer_return status = BLK_EH_DONE;
	unsigned long current_time = ktime_get_ns();

	spin_lock_bh(&cmd->lock);

	/* was just completed? */
	if (cmd->time_completed != 0 && cmd->time_queued == 0) {
		goto out_unlock;
	}

	if (!cmd->d->online) {
		status = BLK_EH_DONE;
		cmd->status = BLK_STS_NEXUS;
		dprintk_ratelimit(
			err, "cmd[%d] hctx %d req %px disk is offline, abort\n",
			cmd->id, cmd->hctx_idx, req);
		goto out_unlock;
	}

	if (nsecs_to_jiffies(current_time - cmd->time_queued) < (HZ * CMD_TIMEOUT_S)) {
		struct ethblk_initiator_disk_tgt_context *tctx;

		DEBUG_INI_CMD(debug, cmd, "rexmit");
		cmd->retries++;
		cmd->time_requeued = current_time;
		NET_STAT_INC(cmd->t, cnt.tx_retry_count);
		if (cmd->t) {
			tctx = &cmd->t->ctx[cmd->hctx_idx];
			tctx->taint = min(tctx->taint + 1, 1000);
		}
	        ethblk_initiator_cmd_rw_partial_retry(cmd);
		goto out_unlock;
	}

	dprintk(err,
		"cmd[%d] hctx %d req %px timed out %d times, abort\n",
		cmd->id, cmd->hctx_idx, req, cmd->retries);
	cmd->status = BLK_STS_TIMEOUT;
	ethblk_initiator_blk_complete_request_locked(req);
out_unlock:
	spin_unlock_bh(&cmd->lock);
	return status;
}

static struct blk_mq_ops ethblk_ops = {
//	.map_queues = blk_mq_map_queues,
	.queue_rq = ethblk_initiator_blk_queue_request,
	.init_request = ethblk_initiator_blk_init_request,
	.exit_request = ethblk_initiator_blk_exit_request,
	.complete = ethblk_initiator_blk_complete_request,
	.timeout = ethblk_initiator_blk_request_timeout
};

static int ethblk_initiator_calc_max_payload(int mtu)
{
	return ALIGN_DOWN(mtu - ETHBLK_HDR_L3_SIZE, SECTOR_SIZE);
}

static int ethblk_initiator_create_gendisk(struct ethblk_initiator_disk *d)
{
	struct gendisk *gd;
	struct request_queue *q;
	int err;
	int i;
	int first_minor;

	dprintk(info, "drv_id %d\n", d->drv_id);

	first_minor = ethblk_initiator_alloc_minor();
	if (first_minor < 0) {
		dprintk(err,
			"cannot allocate kdev_t minor for %s "
			"(serving too much disks?)\n",
			d->name);
		err = -ENOMEM;
		goto err;
	}

	d->cmd = kmalloc((num_hw_queues + 1) * queue_depth * sizeof(void *),
			 GFP_KERNEL);
	if (d->cmd == NULL) {
		dprintk(err, "cannot allocate cmd area for %s\n", d->name);
		err = -ENOMEM;
		goto err;
	}
	d->ctx = kzalloc((num_hw_queues + 1) *
				 sizeof(struct ethblk_initiator_disk_context),
			 GFP_KERNEL);
	if (!d->ctx) {
		dprintk(err, "cannot allocate disk contexts\n");
		kfree(d->cmd);
		err = -ENOMEM;
		goto err;
	}
	d->targets = (struct ethblk_initiator_tgt_array __rcu *)kzalloc(
		sizeof(struct ethblk_initiator_tgt_array), GFP_KERNEL);
	if (!d->targets) {
		dprintk(err, "cannot allocate disk targets\n");
		kfree(d->cmd);
		kfree(d->ctx);
		err = -ENOMEM;
		goto err;
	}
	for (i = 0; i <= num_hw_queues; i++) {
		d->ctx[i].hctx_id = i;
		d->ctx[i].current_target_idx = 0;
	}

	if (ethblk_initiator_disk_stat_init(d) != 0) {
		dprintk(err, "cannot allocate disk stats\n");
		err = -ENOMEM;
		goto err_cmd;
	}
	gd = alloc_disk(ETHBLK_PARTITIONS);
	if (gd == NULL) {
		dprintk(err, "cannot allocate gendisk structure for %s\n",
			d->name);
		err = -ENOMEM;
		goto err_cmd;
	}
	d->gd = gd;
	memset(&d->tag_set, 0, sizeof(struct blk_mq_tag_set));
	d->tag_set.ops = &ethblk_ops;
	d->tag_set.nr_hw_queues = num_hw_queues;
	d->tag_set.queue_depth = queue_depth;
	/* FIXME have a way for user to specify */
	d->tag_set.numa_node = NUMA_NO_NODE;
	d->tag_set.cmd_size = sizeof(struct ethblk_initiator_cmd);
//	d->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	d->tag_set.driver_data = d;
	d->tag_set.timeout = CMD_RETRY_JIFFIES;

	err = blk_mq_alloc_tag_set(&d->tag_set);
	if (err) {
		dprintk(err, "cannot allocate blk_mq_tag_set for %s: %d\n",
			d->name, err);
		goto err_gd;
	}
	q = blk_mq_init_queue(&d->tag_set);
	if (IS_ERR_OR_NULL(q)) {
		err = PTR_ERR(q);
		goto err_tag_set;
	}

	err = bioset_init(&d->bio_set, BIO_POOL_SIZE, 0, 0);
	if (err)
		goto err_bio_set;

	blk_queue_logical_block_size(q, SECTOR_SIZE);
	blk_queue_physical_block_size(q, SECTOR_SIZE);
	blk_queue_io_min(q, SECTOR_SIZE);
	blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);

	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, q);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, q);
	blk_queue_flag_set(QUEUE_FLAG_NOXMERGES, q);

	q->nr_requests = d->tag_set.queue_depth;
	d->queue = gd->queue = q;

	q->limits.max_dev_sectors = ETHBLK_INITIATOR_MAX_PAYLOAD / SECTOR_SIZE;
	blk_queue_io_opt(q, PAGE_SIZE);
	blk_queue_max_hw_sectors(q, ETHBLK_INITIATOR_MAX_PAYLOAD / SECTOR_SIZE);
	blk_queue_max_segments(q, ETHBLK_INITIATOR_MAX_PAYLOAD / SECTOR_SIZE);
	blk_queue_max_segment_size(q, ETHBLK_INITIATOR_MAX_PAYLOAD);

	blk_queue_rq_timeout(q, CMD_RETRY_JIFFIES);

	gd->major = disk_major;
	gd->first_minor = first_minor;
	gd->fops = &ethblk_bdops;
	gd->private_data = d;
	set_capacity(gd, d->ssize);
	snprintf(gd->disk_name, sizeof(gd->disk_name), "eda%d", d->drv_id);
	dprintk(info, "disk %s %px, gd %p\n", d->name, d, gd);
	add_disk(gd);
	return 0;

err_bio_set:
err_tag_set:
	blk_mq_free_tag_set(&d->tag_set);
err_gd:
	put_disk(gd);
err_cmd:
	ethblk_initiator_disk_stat_free(d);
	ethblk_initiator_free_minor(first_minor);
	kfree(d->cmd);
	kfree(d->ctx);
err:
	return err;
}

static struct ethblk_initiator_disk *
ethblk_initiator_find_disk(unsigned short drv_id, bool create)
{
	struct ethblk_initiator_disk *d;
	int ret;

	dprintk(debug, "drv_id %d create %d\n", drv_id, create);
	d = xa_load(&ethblk_initiator_disks, drv_id);
	if (d) {
		ethblk_initiator_get_disk(d);
		dprintk(debug, "found disk %px %s\n", d, d->name);
		goto out;
	}

	if (!create)
		goto out;

	dprintk(debug, "allocating new disk eda%d\n", drv_id);
	d = kzalloc(sizeof(struct ethblk_initiator_disk), GFP_ATOMIC);
	if (!d) {
		dprintk(err, "can't alloc new disk");
		goto out_err;
	}
	ret = percpu_ref_init(&d->ref, ethblk_initiator_disk_free, 0,
			      GFP_KERNEL);
	if (ret) {
		dprintk(err, "can't init d->ref\n");
		goto out_err;
	}

	d->drv_id = drv_id;
	snprintf(d->name, sizeof(d->name), "eda%d", d->drv_id);
	d->net_stat_enabled = net_stat;
	d->lat_stat_enabled = lat_stat;
	d->online = true;
	d->seq_id = 0;

	ret = kobject_init_and_add(&d->kobj, &ethblk_initiator_disk_kobj_type,
				   &ethblk_sysfs_initiator_kobj, "%s", d->name);
	if (ret) {
		dprintk(err, "can't add kobj\n");
		goto out_err_disk;
	}
	INIT_WORK(&d->cap_work, ethblk_initiator_disk_set_capacity_work);
	init_completion(&d->destroy_completion);
	ret = ethblk_initiator_create_gendisk(d);
	if (ret) {
		dprintk(err, "can't create gendisk\n");
		goto out_err_kobj;
	}
// FIXME check needed?
	xa_store(&ethblk_initiator_disks, d->drv_id, d, GFP_ATOMIC);
	ethblk_initiator_get_disk(d);

	ret = sysfs_create_group(&d->kobj, &ethblk_initiator_disk_group);
	if (ret) {
		dprintk(err, "disk %s can't create sysfs: %d\n", d->name, ret);
		goto out_err_put_disk;
	}

	ret = kobject_init_and_add(&d->tgts_kobj,
				   &ethblk_initiator_disk_tgts_kobj_type,
				   &d->kobj, "targets");
	if (ret) {
		dprintk(err, "can't add kobj tgts\n");
		goto out_err_sysfs;
	}
	ret = sysfs_create_group(&d->tgts_kobj,
				 &ethblk_initiator_disk_tgts_group);
	if (ret) {
		dprintk(err, "disk %s can't create sysfs tgts: %d\n", d->name,
			ret);
		goto out_err_kobj_tgts;
	}
out:
	return d;

out_err_kobj_tgts:
	kobject_del(&d->tgts_kobj);
out_err_sysfs:
	sysfs_remove_group(&d->kobj, &ethblk_initiator_disk_group);
out_err_put_disk:
	ethblk_initiator_put_disk(d);
out_err_kobj:
	kobject_del(&d->kobj);
out_err_disk:
	kfree(d);
out_err:
	return NULL;
}

static void ethblk_initiator_destroy_all_disks(void)
{
	struct ethblk_initiator_disk *d;
	unsigned long drv_id;

	xa_for_each(&ethblk_initiator_disks, drv_id, d) {
		dprintk(info, "destroying %s %px\n", d->name, d);
		ethblk_initiator_disk_remove_all_targets(d);

		/* last ref needs to be dropped in a process ctx */
		ethblk_initiator_get_disk(d);
		percpu_ref_kill(&d->ref);
		synchronize_rcu();
		ethblk_initiator_put_disk(d);

		wait_for_completion(&d->destroy_completion);
	}
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_find_target(struct ethblk_initiator_disk *d,
				  unsigned char *p, struct net_device *nd,
				  bool l3)
{
	struct ethblk_initiator_tgt *t = NULL;
	struct ethblk_initiator_tgt_array *ta;
	int i;
	__be32 ip = *(__be32 *)p;

	if (l3) {
		dprintk(debug,
			"disk %s searching target "
			"%s_%pI4\n",
			d->name, nd->name, p);
	} else {
		dprintk(debug,
			"disk %s searching target "
			"%s_%pM\n",
			d->name, nd->name, p);
	}
	rcu_read_lock();
	ta = rcu_dereference(d->targets);
	for (i = 0; i < ta->nr; i++) {
		t = ta->tgts[i];
		if ((nd == t->nd) && (l3 ? (t->dest_ip == ip) :
					   ether_addr_equal(t->mac, p))) {
			dprintk(debug, "disk %s found target[%d] %s %px\n",
				d->name, i, t->name, t);
			ethblk_initiator_get_tgt(t);
			goto out_unlock;
		}
	}
	t = NULL;
out_unlock:
	rcu_read_unlock();
	return t;
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_find_target_by_skb(struct sk_buff *skb)
{
	struct ethblk_hdr *req_hdr = ethblk_network_skb_get_hdr(skb);
	struct ethblk_initiator_disk *d;
	unsigned short drv_id;
	bool l3 = ethblk_network_skb_is_l3(skb);
	unsigned char *p = l3 ? (unsigned char *)&ip_hdr(skb)->saddr : req_hdr->src;
	struct ethblk_initiator_tgt *t = NULL;

	drv_id = be16_to_cpu(req_hdr->drv_id);
	d = ethblk_initiator_find_disk(drv_id, false);
	if (!d) {
		dprintk(err, "unknown drv_id %d\n", drv_id);
		goto out;
	}

	t = ethblk_initiator_disk_find_target(d, p, skb->dev, l3);
out:
	if (d)
		ethblk_initiator_put_disk(d);
	return t;
}

static struct ethblk_initiator_tgt *
ethblk_initiator_disk_add_target(struct ethblk_initiator_disk *d,
				 unsigned char *addr, struct net_device *nd,
				 bool l3)
{
	struct ethblk_initiator_tgt *tn;
	struct ethblk_initiator_tgt_array *t, *to;
	unsigned long flags;
	int i, ret;

	tn = kzalloc(sizeof(struct ethblk_initiator_tgt), GFP_KERNEL);
	if (!tn) {
		dprintk(err, "can't allocate memory for new target\n");
		goto out;
	}

	tn->ctx =
		kzalloc((num_hw_queues +
			 1) * sizeof(struct ethblk_initiator_disk_tgt_context),
			GFP_KERNEL);
	if (!tn->ctx) {
		dprintk(err, "cannot allocate disk tgt contexts\n");
		goto out_tn;
	}

	t = kzalloc(sizeof(struct ethblk_initiator_tgt_array), GFP_KERNEL);
	if (!t) {
		dprintk(err, "can't allocate memory for new targets array\n");
		goto out_ctx;
	}

	tn->d = d;
	dev_hold(nd);
	tn->nd = nd;
	tn->net_stat_enabled = d->net_stat_enabled;
	tn->lat_stat_enabled = d->lat_stat_enabled;
	tn->l3 = l3;
	tn->local_ip = ethblk_network_if_get_saddr(tn->nd);
	tn->num_queues = 1;
	tn->id = d->seq_id++;

	if (tn->l3) {
		tn->dest_ip = (__be32 __force) * (unsigned int *)addr;
		snprintf(tn->name, sizeof(tn->name), "%s_%pI4",
			 nd->name, addr);
		if (ethblk_network_route_l3(tn->nd, tn->dest_ip,
					    tn->local_ip,
					    tn->router_mac) == 0)
			tn->has_router_mac = true;
		else
			tn->has_router_mac = false;
	} else {
		ether_addr_copy(tn->mac, addr);
		snprintf(tn->name, sizeof(tn->name),
			 "%s_%pM", nd->name, addr);
	}

	dprintk(info, "disk %s creating target %s %px\n", d->name, tn->name, tn);

	INIT_LIST_HEAD(&tn->list);
	INIT_WORK(&tn->free_work, ethblk_initiator_tgt_free_deferred);

	if (ethblk_initiator_tgt_stat_init(tn) != 0) {
		dprintk(err, "cannot allocate tgt stats\n");
		goto out_t;
	}

	ret = kobject_init_and_add(&tn->kobj,
				   &ethblk_initiator_disk_tgt_kobj_type,
				   &d->tgts_kobj, tn->name);
	if (ret) {
		dprintk(err, "cannot init kobj\n");
		goto out_stats;
	}
	ret = sysfs_create_group(&tn->kobj, &ethblk_initiator_disk_tgt_group);
	if (ret) {
		dprintk(err, "disk %s ini %s can't create sysfs: %d\n", d->name,
			tn->name, ret);
		goto out_kobj;
	}

	ret = percpu_ref_init(&tn->ref, ethblk_initiator_tgt_free, 0,
			      GFP_KERNEL);
	if (ret) {
		dprintk(err, "cannot init percpu_ref\n");
		goto out_sysfs;
	}
	tn->relax_timeout_rearm = TAINT_RELAX;
	for (i = 0; i < num_hw_queues; i++) {
		tn->ctx[i].taint = 0;
		tn->ctx[i].relax_timeout = tn->relax_timeout_rearm;
	}

	spin_lock_irqsave(&d->target_lock, flags);
	rcu_read_lock();
	to = rcu_dereference(d->targets);
	t->nr = to->nr + 1;
	dprintk(debug, "disk %s %d old targets at %px, %d new at %px\n", d->name,
		to->nr, to, t->nr, t);
	for (i = 0; i < to->nr; i++) {
		dprintk(debug, "disk %s copying target[%d] %s\n", d->name, i,
			to->tgts[i]->name);
		t->tgts[i] = to->tgts[i];
	}
	t->tgts[i] = tn;
	dprintk(debug, "disk %s added new target[%d] %s\n", d->name, i,
		tn->name);
	rcu_assign_pointer(d->targets, t);
	kfree_rcu(to, rcu);
	rcu_read_unlock();
	spin_unlock_irqrestore(&d->target_lock, flags);

	tn->max_payload = ethblk_initiator_calc_max_payload(nd->mtu);

	return tn;
out_sysfs:
	sysfs_remove_group(&tn->kobj, &ethblk_initiator_disk_tgt_group);
out_kobj:
	kobject_del(&tn->kobj);
out_stats:
	ethblk_initiator_tgt_stat_free(tn);
out_t:
	kfree(t);
	dev_put(nd);
out_ctx:
	kfree(tn->ctx);
out_tn:
	kfree(tn);
out:
	return NULL;
}

static int ethblk_initiator_disk_remove_target(struct ethblk_initiator_tgt *t)
{
	struct ethblk_initiator_disk *d = t->d;
	struct ethblk_initiator_tgt_array *tn, *to;
	unsigned long flags;
	int i, j, ret;

	dprintk(info, "disk %s removing target %s\n", d->name, t->name);

	tn = kzalloc(sizeof(struct ethblk_initiator_tgt_array), GFP_ATOMIC);
	if (!tn) {
		dprintk(err, "can't allocate memory for new targets array\n");
		ret = -ENOMEM;
		goto out;
	}

	rcu_read_lock();
	spin_lock_irqsave(&d->target_lock, flags);
	to = rcu_dereference(d->targets);
	tn->nr = to->nr - 1;
	dprintk(debug, "disk %s %d old targets at %px, %d new at %px\n", d->name,
		to->nr, to, tn->nr, tn);
	for (i = j = 0; i < to->nr; i++) {
		if (to->tgts[i] != t) {
			dprintk(debug, "disk %s copying target[%d] %s\n",
				d->name, i, to->tgts[i]->name);
			tn->tgts[j++] = to->tgts[i];
		}
	}
	if (i == j) {
		spin_unlock_irqrestore(&d->target_lock, flags);
		rcu_read_unlock();
		dprintk(err,
			"disk %s target %s was not found. "
			"Keeping old targets array\n",
			d->name, t->name);
		kfree(tn);
		ret = -ENOENT;
		goto out;
	}
	rcu_assign_pointer(d->targets, tn);
	kfree_rcu(to, rcu);
	spin_unlock_irqrestore(&d->target_lock, flags);
	rcu_read_unlock();

	percpu_ref_kill(&t->ref);
	ret = 0;
out:
	return ret;
}

static void ethblk_initiator_cmd_drv_in_done(struct request *req,
					     blk_status_t error)
{
	blk_put_request(req);
}

static void ethblk_initiator_tgt_send_id(struct ethblk_initiator_tgt *t)
{
	struct request *req;
	struct ethblk_initiator_cmd *cmd;
	struct ethblk_initiator_disk *d = t->d;

	dprintk(info, "ID for disk %s tgt %s\n", d->name, t->name);
	req = blk_mq_alloc_request(d->queue, REQ_OP_DRV_IN, 0);
	if (!req) {
		dprintk(err, "can't alloc blk_mq request!\n");
		return;
	}

	cmd = blk_mq_rq_to_pdu(req);
	cmd->ethblk_hdr.op = ETHBLK_OP_ID;
	cmd->ethblk_hdr.lba = cpu_to_be64(t->id);

	blk_execute_rq_nowait(d->queue, NULL, req, 0,
			      ethblk_initiator_cmd_drv_in_done);
}

static void ethblk_initiator_tgt_checksum(struct ethblk_initiator_tgt *t,
					  u64 lba,
					  int sectors)
{
	struct request *req;
	struct ethblk_initiator_cmd *cmd;
	struct ethblk_initiator_disk *d = t->d;

	dprintk(info, "CHECKSUM for disk %s tgt %s lba %llu sectors %u\n",
		d->name, t->name, lba, sectors);
	req = blk_mq_alloc_request(d->queue, REQ_OP_DRV_IN, 0);
	if (!req) {
		dprintk(err, "can't alloc blk_mq request!\n");
		return;
	}

	cmd = blk_mq_rq_to_pdu(req);
	cmd->ethblk_hdr.op = ETHBLK_OP_CHECKSUM;
	cmd->ethblk_hdr.lba = cpu_to_be64(lba);
	cmd->ethblk_hdr.num_sectors = sectors;

	blk_execute_rq_nowait(d->queue, NULL, req, 0,
			      ethblk_initiator_cmd_drv_in_done);
}

void ethblk_initiator_discover_response(struct sk_buff *skb)
{
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_tgt *t;
	struct ethblk_hdr *rep_hdr = (struct ethblk_hdr *)skb_mac_header(skb);
	unsigned short drv_id;
	bool l3 = rep_hdr->tag; /* NOTE ugly hack */
	unsigned char *p = l3 ? (unsigned char *)&rep_hdr->tag : rep_hdr->src;

	drv_id = be16_to_cpu(rep_hdr->drv_id);
	if (l3)
		dprintk(info,
			"DISCOVER response for eda%d "
			"%s_%pI4\n",
			drv_id, skb->dev->name, p);
	else
		dprintk(info,
			"DISCOVER response for eda%d "
			"%s_%pM\n",
			drv_id, skb->dev->name, p);

	d = ethblk_initiator_find_disk(drv_id, true);
	if (!d) {
		dprintk(err, "can't allocate new device eda%d\n", drv_id);
		goto out;
	}

	t = ethblk_initiator_disk_find_target(d, p, skb->dev, l3);
	if (!t) {
		t = ethblk_initiator_disk_add_target(d, p, skb->dev, l3);
		if (!t)
			goto out;
	}

	ethblk_initiator_tgt_send_id(t);
out:
	consume_skb(skb);
	if (d)
		ethblk_initiator_put_disk(d);
}

static void
ethblk_initiator_cmd_id_complete(struct ethblk_initiator_cmd *cmd,
				 struct ethblk_hdr *rep_hdr)
{
	struct ethblk_initiator_disk *d = cmd->d;
	struct ethblk_initiator_tgt *t;
	struct ethblk_cfg_hdr *cfg = (struct ethblk_cfg_hdr *)(rep_hdr + 1);
	sector_t ssize = be64_to_cpu(cfg->num_sectors);
	int tgt_id = be64_to_cpu(rep_hdr->lba);

	if (d->ssize != ssize) {
		dprintk(info, "disk %s new size %llu sectors\n", d->name,
			(long long)ssize);
		d->ssize = ssize;
// FIXME set_capacity_revalidate_and_notify ?
		set_capacity(d->gd, ssize);
		schedule_work(&d->cap_work);
	}

	t = ethblk_initiator_disk_find_tgt_by_id(d, tgt_id);
	if (t) {
		int num_queues = max(1, (int)be16_to_cpu(cfg->num_queues));
		int q_depth = max(1, (int)be16_to_cpu(cfg->q_depth));

		dprintk(info, "disk %s tgt %s q_depth %d num_queues %d uuid %pU\n",
			d->name, t->name, q_depth, num_queues, cfg->uuid);
// FIXME if d->uuid mismatesh then kill the tgt
//	memcpy(d->uuid, cfg->uuid, sizeof(cfg->uuid));
		t->num_queues = num_queues;

// FIXME TEST		ethblk_initiator_tgt_checksum(t, 0, 128);

		ethblk_initiator_put_tgt(t);
	} else {
		dprintk(err, "disk %s can't find tgt id %d\n", d->name, tgt_id);
	}
}

static int ethblk_skb_copy_to_cmd(struct sk_buff *skb,
				  struct ethblk_initiator_cmd *cmd,
				  int req_offset)
{
	struct bio_vec bv;
	struct req_iterator iter;
	struct request *req = blk_mq_rq_from_pdu(cmd);
	int off = 0;
	char *to;

	rq_for_each_segment (bv, req, iter) {
		to = page_address(bv.bv_page) + bv.bv_offset;
		if (off >= req_offset) {
			skb_copy_bits(skb, off, to, bv.bv_len);
		}
		off += bv.bv_len;
	}
	return off;
}

static void ethblk_initiator_checksum_cmd_complete(struct ethblk_initiator_cmd *cmd,
						   struct ethblk_hdr *rep_hdr)
{
	__u32 *rep_sha_dg = (__u32 *)(rep_hdr + 1);
	__be32 sha_dg[SHA_DIGEST_WORDS];
	char s[SHA_DIGEST_WORDS * 4 * 2 + 1] = { 0 };
	int i;

	for (i = 0 ; i < SHA_DIGEST_WORDS; i++)
		sha_dg[i] = cpu_to_be32(rep_sha_dg[i]);

	bin2hex(s, (char *)sha_dg, SHA_DIGEST_WORDS * 4);
	DEBUG_INI_CMD(debug, cmd, "checksum %s", s);
}

static bool ethblk_initiator_cmd_complete(struct ethblk_initiator_cmd *cmd,
					  struct sk_buff *skb)
{
	struct ethblk_hdr *rep_hdr, *req_hdr;
	int n, skb_idx, offset;
	bool done = true;
	u32 tag;
	struct bio * bio;

	req_hdr = &cmd->ethblk_hdr;

	if (ethblk_network_skb_is_l3(skb))
		skb_pull(skb, ETHBLK_HDR_L3_SIZE);

	rep_hdr = (struct ethblk_hdr *)skb->data;
	skb_pull(skb, sizeof(struct ethblk_hdr));
	if (ETHBLK_HDR_GET_STATUS(rep_hdr)) {
		cmd->status = BLK_STS_IOERR;
		DEBUG_INI_CMD(err, cmd, "IO error %lu",
			      ETHBLK_HDR_GET_STATUS(rep_hdr));
		goto out;
	}

	n = req_hdr->num_sectors << SECTOR_SHIFT;

	tag = be32_to_cpu(rep_hdr->tag);
	skb_idx = (tag >> 24) & 63;
	if (skb_idx && (skb_idx >= cmd->skb_idx)) {
		dprintk_ratelimit(err,
				  "%s: tag skb_idx %d >= cmd->skb_idx %d\n",
				  cmd->d->name, skb_idx, cmd->skb_idx);
		cmd->status = BLK_STS_IOERR;
		goto out;
	}
	offset = cmd->offsets[skb_idx];
	bio = cmd->bios[skb_idx];

	switch (req_hdr->op) {
	case ETHBLK_OP_READ:
		cmd->nr_skbs--;
		if (cmd->nr_skbs)
			done = false;
		if (n > blk_rq_bytes(blk_mq_rq_from_pdu(cmd))) {
			dprintk_ratelimit(err,
				"%s: too large read data size %d"
				"(need %d)\n",
				cmd->d->name, n,
				blk_rq_bytes(blk_mq_rq_from_pdu(cmd)));
			cmd->status = BLK_STS_IOERR;
			break;
		}
		DEBUG_INI_CMD(debug, cmd, "skb_idx %d, offset %d, nr_skbs left %d", skb_idx, offset, cmd->nr_skbs);
		ethblk_skb_copy_to_cmd(skb, cmd, offset);
		if (bio) {
			bio_put(bio);
			cmd->bios[skb_idx] = NULL;
		}
		cmd->status = BLK_STS_OK;
		break;
	case ETHBLK_OP_WRITE:
		cmd->nr_skbs--;
		if (cmd->nr_skbs)
			done = false;
		DEBUG_INI_CMD(debug, cmd, "skb_idx %d, offset %d, nr_skbs left %d", skb_idx, offset, cmd->nr_skbs);
		if (bio) {
			bio_put(bio);
			cmd->bios[skb_idx] = NULL;
		}
		cmd->status = BLK_STS_OK;
		break;
	case ETHBLK_OP_ID:
		if (skb->len < sizeof(struct ethblk_cfg_hdr)) {
			dprintk(err, "%s: runt data size %d in ID reply (need %lu)\n",
				cmd->d->name, skb->len, sizeof(struct ethblk_cfg_hdr));
			break;
		}
		ethblk_initiator_cmd_id_complete(cmd, rep_hdr);
		break;
	case ETHBLK_OP_CHECKSUM:
		ethblk_initiator_checksum_cmd_complete(cmd, rep_hdr);
		break;
	default:
		dprintk(info, "%s: unknown op %d in reply\n",
			cmd->d->name, rep_hdr->op);
		break;
	}

out:
	return done;
}

void ethblk_initiator_cmd_response(struct sk_buff *skb, unsigned comp_cpu)
{
	struct ethblk_hdr *rep_hdr = ethblk_network_skb_get_hdr(skb);
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_cmd *cmd = NULL;
	struct ethblk_initiator_tgt *t = NULL;
	unsigned int tag;
	unsigned short drv_id;
	unsigned int cmd_nr, gen_id, cmd_gen_id;

	dprintk(debug, "skb = %px\n", skb);
	drv_id = be16_to_cpu(rep_hdr->drv_id);
	d = ethblk_initiator_find_disk(drv_id, false);
	if (!d) {
		dprintk(debug, "unknown drv_id %d\n", drv_id);
		goto out;
	}

	if (!d->online)
		goto out;

	t = ethblk_initiator_disk_find_target_by_skb(skb);

	if (!t) {
		dprintk(debug, "unknown target %pM for disk %s\n", rep_hdr->src, d->name);
		NET_STAT_INC(t, cnt.rx_err_count);
		goto out;
	}

	tag = be32_to_cpu(rep_hdr->tag);

	cmd_nr = tag & 0xffff;
	gen_id = (tag >> 16) & CMD_TAG_MASK;

	dprintk(debug, "target %s tag %d is cmd_nr %d gen_id %d\n", t->name,
		tag, cmd_nr, gen_id);

	if (cmd_nr >= t->d->max_cmd) {
		dprintk(err, "target %s bad tag %d (cmd_nr %d > max_cmd %d)\n",
			t->name, tag, cmd_nr, t->d->max_cmd);
		NET_STAT_INC(t, cnt.rx_err_count);
		goto out;
	}

	cmd = t->d->cmd[cmd_nr];

	spin_lock_bh(&cmd->lock);

	if (!blk_mq_request_started(blk_mq_rq_from_pdu(cmd))) {
		DEBUG_INI_CMD(debug, cmd,
			      "target %s request is not started"
			      "(was just finished?)",
			      t->name);
		NET_STAT_INC(cmd->t, cnt.rx_late_count);
		goto out_unlock;
	}

	cmd_gen_id = cmd->gen_id & CMD_TAG_MASK;
	if (cmd_gen_id != gen_id) {
		DEBUG_INI_CMD(debug, cmd,
			      "target %s bad tag %d"
			      "(got gen_id %d, expect %d"
			      "- was request reused?)",
			      t->name, tag, gen_id, cmd_gen_id);
		NET_STAT_INC(cmd->t, cnt.rx_late_count);
		goto out_unlock;
	}

	DEBUG_INI_CMD(debug, cmd, "found cmd %px L%d for tag %d", cmd,
		      cmd->l3 ? 3 : 2, tag);
	cmd->cpu_completed = comp_cpu;
	if (ethblk_initiator_cmd_complete(cmd, skb)) {
		dprintk(debug, "cmd[%d] complete request\n", cmd->id);
		ethblk_initiator_blk_complete_request_locked(blk_mq_rq_from_pdu(cmd));
	}
out_unlock:
	spin_unlock_bh(&cmd->lock);
out:
	if (t)
		ethblk_initiator_put_tgt(t);
	if (d)
		ethblk_initiator_put_disk(d);
	consume_skb(skb);
}

static void ethblk_initiator_cmd(struct ethblk_worker_cb *cb)
{
	struct sk_buff *skb = (struct sk_buff *)cb->data;
	bool in_headroom = cb->in_headroom;

	if (in_headroom)
		skb_pull(skb, sizeof(struct ethblk_worker_cb));

	switch (cb->type) {
	case ETHBLK_WORKER_CB_TYPE_INITIATOR_IO:
		ethblk_initiator_cmd_response(skb, cb->comp_cpu);
		break;
	case ETHBLK_WORKER_CB_TYPE_INITIATOR_DISCOVER:
		ethblk_initiator_discover_response(skb);
		break;
	default:
		dprintk(err, "unknown cb type: %d\n", cb->type);
		consume_skb(skb);
		break;
	}
	if (!in_headroom)
		kmem_cache_free(workers->cb_cache, cb);
}

static void ethblk_initiator_prepare_cfg_pkts(unsigned short drv_id,
					      struct sk_buff_head *queue)
{
	struct ethblk_hdr *req_hdr;
	struct sk_buff *skb;
	struct net_device *ifp;

	rcu_read_lock();
	for_each_netdev_rcu (&init_net, ifp) {
		dev_hold(ifp);
		skb = ethblk_network_new_skb(ETHBLK_CFG_REPLY_SIZE);
		if (skb == NULL) {
			dprintk(err, "skb alloc failure\n");
			goto cont;
		}
		skb_put(skb, ETHBLK_CFG_REPLY_SIZE);
		skb->dev = ifp;
		__skb_queue_tail(queue, skb);
		req_hdr = (struct ethblk_hdr *)skb_mac_header(skb);
		memset(req_hdr, 0, ETHBLK_CFG_REPLY_SIZE);

		eth_broadcast_addr(req_hdr->dst);
		ether_addr_copy(req_hdr->src, ifp->dev_addr);

		req_hdr->type = cpu_to_be16(eth_p_type);
		ETHBLK_HDR_SET_FLAGS(req_hdr, ETHBLK_PROTO_VERSION, 0, 0);
		req_hdr->drv_id = cpu_to_be16(drv_id);
		req_hdr->op = ETHBLK_OP_DISCOVER;
	cont:
		dev_put(ifp);
	}
	rcu_read_unlock();
}

static void ethblk_initiator_discover(void)
{
	struct sk_buff_head queue;
	struct sk_buff *skb;

	skb_queue_head_init(&queue);
	/* NOTE
	 * DISCOVER is L2 broadcast
	 * Target answers with IP hint (if configured).
	 * Initiator automatically picks tgt IP up.
	 */
	ethblk_initiator_prepare_cfg_pkts(0xffff, &queue);
	while ((skb = skb_dequeue(&queue))) {
		ethblk_network_xmit_skb(skb);
	}
}

void ethblk_initiator_handle_cfg_change(struct sk_buff *in_skb)
{
	struct ethblk_hdr *in_hdr = ethblk_network_skb_get_hdr(in_skb);
	struct ethblk_hdr *req_hdr;
	struct sk_buff *skb;

	rcu_read_lock();
	dev_hold(in_skb->dev);
	skb = ethblk_network_new_skb(ETHBLK_CFG_REPLY_SIZE);
	if (skb == NULL) {
		dprintk(err, "skb alloc failure\n");
		goto err;
	}
	skb_put(skb, ETHBLK_CFG_REPLY_SIZE);
	skb->dev = in_skb->dev;

	req_hdr = (struct ethblk_hdr *)skb_mac_header(skb);
	memset(req_hdr, 0, ETHBLK_CFG_REPLY_SIZE);

	ether_addr_copy(req_hdr->dst, in_hdr->src);
	ether_addr_copy(req_hdr->src, skb->dev->dev_addr);

	req_hdr->type = cpu_to_be16(eth_p_type);
	ETHBLK_HDR_SET_FLAGS(req_hdr, ETHBLK_PROTO_VERSION, 0, 0);
	req_hdr->drv_id = in_hdr->drv_id;
	req_hdr->op = ETHBLK_OP_DISCOVER;

	ethblk_network_xmit_skb(skb);
err:
	dev_put(in_skb->dev);
	rcu_read_unlock();
}

static void ethblk_initiator_tgt_free(struct percpu_ref *ref)
{
	struct ethblk_initiator_tgt *t =
		container_of(ref, struct ethblk_initiator_tgt, ref);

	dprintk(info, "disk %s %s %px schedule freeing\n", t->d->name, t->name, t);
	schedule_work(&t->free_work);
}

static void ethblk_initiator_tgt_free_deferred(struct work_struct *w)
{
	struct ethblk_initiator_tgt *t =
		container_of(w, struct ethblk_initiator_tgt, free_work);

	dprintk(info, "disk %s freeing target %s %px\n", t->d->name, t->name, t);
	sysfs_remove_group(&t->kobj, &ethblk_initiator_disk_tgt_group);
	kobject_del(&t->kobj);
	ethblk_initiator_tgt_stat_free(t);
	dev_put(t->nd);
	percpu_ref_exit(&t->ref);
	kzfree(t->ctx);
	kzfree(t);
}

static void
ethblk_initiator_disk_remove_all_targets(struct ethblk_initiator_disk *d)
{
	struct ethblk_initiator_tgt *t;
	struct ethblk_initiator_tgt_array *ta;

	dprintk(info, "%s removing targets\n", d->name);

	d->online = false;

	rcu_read_lock();
again:
	ta = rcu_dereference(d->targets);
	if (ta->nr) {
		t = ta->tgts[0];
		/* Make sure tgt won't be freed in the following
		 * disk_remove_target */
		ethblk_initiator_get_tgt(t);
		rcu_read_unlock();
		ethblk_initiator_disk_remove_target(t);
		ethblk_initiator_put_tgt(t);
		rcu_read_lock();
		goto again;
	}
	rcu_read_unlock();

	dprintk(info, "disk %s has no more targets\n", d->name);
}

static ssize_t discover_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	dprintk(info, "discovering targets and disks\n");
	ethblk_initiator_discover();
	return count;
}

static ssize_t disconnect_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	dprintk(info, "disconnecting everything\n");
	ethblk_initiator_destroy_all_disks();
	return count;
}

static ssize_t log_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buff)
{
	return 0;
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buff)
{
	return 0;
}

static ssize_t create_disk_store(struct kobject *kobj,
				 struct kobj_attribute *attr, const char *buf,
				 size_t count)
{
	unsigned short drv_id;
	int ret;
	static struct ethblk_initiator_disk *d;

	ret = sscanf(buf, "%hu", &drv_id);
	if (ret != 1) {
		dprintk(err, "can't parse (%d): %s\n", ret, buf);
		return -EINVAL;
	}
	d = ethblk_initiator_find_disk(drv_id, false);
	if (d) {
		dprintk(err, "can't create disk %s (already exists)\n",
			d->name);
		count = -EEXIST;
	} else {
		d = ethblk_initiator_find_disk(drv_id, true);
		if (!d) {
			dprintk(err, "can't create disk eda%d (see logs)\n",
				drv_id);
			count = -EINVAL;
		}
	}
	if (d)
		ethblk_initiator_put_disk(d);
	return count;
}

static struct kobj_attribute ethblk_initiator_create_disk_attr =
	__ATTR_WO(create_disk);
static struct kobj_attribute ethblk_initiator_discover_attr =
	__ATTR_WO(discover);
static struct kobj_attribute ethblk_initiator_disconnect_attr =
	__ATTR_WO(disconnect);
static struct kobj_attribute ethblk_initiator_log_attr = __ATTR_RO(log);
static struct kobj_attribute ethblk_initiator_stats_attr = __ATTR_RO(stats);

static struct attribute *ethblk_sysfs_initiator_default_attrs[] = {
	&ethblk_initiator_create_disk_attr.attr,
	&ethblk_initiator_discover_attr.attr,
	&ethblk_initiator_disconnect_attr.attr,
	&ethblk_initiator_log_attr.attr,
	&ethblk_initiator_stats_attr.attr,
	NULL
};

static struct kobj_type ethblk_sysfs_initiator_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = ethblk_sysfs_initiator_default_attrs,
};

static void ethblk_initiator_netdevice_unregister(struct net_device *nd)
{
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_tgt_array *ta;
	struct ethblk_initiator_tgt *t;
	int i;
	unsigned long drv_id;

	dprintk(info, "nd %px name %s\n", nd, nd->name);
	xa_for_each(&ethblk_initiator_disks, drv_id, d) {
	again:
		rcu_read_lock();
		spin_lock_bh(&d->target_lock);
		ta = rcu_dereference(d->targets);
		if (ta->nr) {
			for (i = 0; i < ta->nr; i++) {
				t = ta->tgts[i];
				if (nd == t->nd) {
					ethblk_initiator_get_tgt(t);
					spin_unlock_bh(&d->target_lock);
					rcu_read_unlock();
					ethblk_initiator_disk_remove_target(t);
					ethblk_initiator_put_tgt(t);
					goto again;
				}
			}
		}
		spin_unlock_bh(&d->target_lock);
		rcu_read_unlock();
	}
}

static void ethblk_initiator_netdevice_change_mtu(struct net_device *nd)
{
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_tgt_array *ta;
	struct ethblk_initiator_tgt *t;
	int i;
	unsigned long drv_id;

	dprintk(info, "nd %px name %s mtu %d\n", nd, nd->name, nd->mtu);
	xa_for_each(&ethblk_initiator_disks, drv_id, d) {
		rcu_read_lock();
		spin_lock_bh(&d->target_lock);
		ta = rcu_dereference(d->targets);
		if (ta->nr) {
			for (i = 0; i < ta->nr; i++) {
				t = ta->tgts[i];
				if (nd == t->nd) {
					t->max_payload = ethblk_initiator_calc_max_payload(nd->mtu);
					dprintk(info, "t %px new max_payload %d\n", t, t->max_payload);
				}
			}
		}
		spin_unlock_bh(&d->target_lock);
		rcu_read_unlock();
	}
}

static void ethblk_initiator_netdevice_up(struct net_device *nd)
{
	struct ethblk_initiator_disk *d;
	struct ethblk_initiator_tgt_array *ta;
	struct ethblk_initiator_tgt *t;
	int i;
	unsigned long drv_id;
	__be32 ip = ethblk_network_if_get_saddr_unlocked(nd);
	unsigned char *p = (unsigned char *)&ip;

	/* Reread IPv4 address */
	dprintk(info, "nd %px name %s addr %pI4\n",
		nd, nd->name, p);

	xa_for_each(&ethblk_initiator_disks, drv_id, d) {
		rcu_read_lock();
		spin_lock_bh(&d->target_lock);
		ta = rcu_dereference(d->targets);
		if (ta->nr) {
			for (i = 0; i < ta->nr; i++) {
				t = ta->tgts[i];
				if (nd == t->nd) {
					t->local_ip = ip;
					t->has_router_mac = false;

				}
			}
		}
		spin_unlock_bh(&d->target_lock);
		rcu_read_unlock();
	}
}

static int ethblk_initiator_netdevice_event(struct notifier_block *unused,
					    unsigned long event, void *ptr)
{
	struct net_device *nd = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_UNREGISTER:
		ethblk_initiator_netdevice_unregister(nd);
		break;
	case NETDEV_CHANGEMTU:
		ethblk_initiator_netdevice_change_mtu(nd);
		break;
	case NETDEV_UP:
		ethblk_initiator_netdevice_up(nd);
	default:
		break;
	}

	return NOTIFY_DONE;
}

void ethblk_initiator_cmd_deferred(struct sk_buff *skb,
				   int type)
{
	struct ethblk_worker_cb *cb = NULL;
	int headroom;

	if (!initiator_running)
		goto err;

	headroom = skb_headroom(skb);

	if (headroom >= sizeof(struct ethblk_worker_cb)) {
		cb = (struct ethblk_worker_cb *)skb_push(skb, sizeof(struct ethblk_worker_cb));
		cb->in_headroom = true;
	} else {
		cb = kmem_cache_zalloc(workers->cb_cache, GFP_ATOMIC);
		if (!cb) {
			dprintk_ratelimit(debug, "can't allocate cb\n");
			goto err;
		}
	}
	INIT_LIST_HEAD(&cb->list);
	cb->fn = ethblk_initiator_cmd;
	cb->data = skb;
	cb->type = type;
	cb->comp_cpu = smp_processor_id();
	if (!ethblk_worker_enqueue(workers, &cb->list)) {
		dprintk_ratelimit(err, "can't enqueue work\n");
		goto err;
	}
	goto out;
err:
	if (cb && !cb->in_headroom)
		kmem_cache_free(workers->cb_cache, cb);
	consume_skb(skb);
out:
	return;
}

static void ethblk_initiator_cmd_worker(struct kthread_work *work)
{
	struct ethblk_worker *w =
		container_of(work, struct ethblk_worker, work);
	struct list_head queue;
	struct ethblk_worker_cb *cb, *n;
	bool queue_empty;

	dprintk(debug, "worker[%d] on\n", w->idx);
	for (;;) {
		INIT_LIST_HEAD(&queue);
		spin_lock_bh(&w->lock);
		list_splice_tail_init(&w->queue, &queue);
		queue_empty = list_empty(&queue);
		if (queue_empty)
			w->active = false;
		spin_unlock_bh(&w->lock);

		if (queue_empty)
			break;

		list_for_each_entry_safe(cb, n, &queue, list) {
			cb->fn(cb);
		}
	}

	dprintk(debug, "worker[%d] off\n", w->idx);
}

static int ethblk_initiator_start_workers(void)
{
	int ret;

	ret = ethblk_worker_create_pool(&workers,
		"ethblk-ini", ethblk_initiator_cmd_worker, cpu_online_mask);
	return ret;
}

static void ethblk_initiator_stop_workers(void)
{
	if (workers)
		ethblk_worker_destroy_pool(workers);
}

static struct notifier_block ethblk_initiator_netdevice_notifier = {
	.notifier_call = ethblk_initiator_netdevice_event
};

int __init ethblk_initiator_start(struct kobject *parent)
{
	int ret;
	int tag_size = 1UL << (8 * (sizeof_field(struct ethblk_hdr, tag) / 2));

	ret = ethblk_initiator_start_workers();
	if (ret) {
		dprintk(err, "can't starts workers: %d\n", ret);
		goto out;
	}

	ret = register_netdevice_notifier(&ethblk_initiator_netdevice_notifier);
	if (ret) {
		dprintk(err, "can't register netdevice notifier: %d\n", ret);
		goto out;
	}

	ret = register_blkdev(disk_major, "ethblk");
	if (ret < 0) {
		dprintk(err, "can't register blkdev %d: %d\n", disk_major, ret);
		goto out;
	}
	ret = kobject_init_and_add(&ethblk_sysfs_initiator_kobj,
				   &ethblk_sysfs_initiator_ktype, parent, "%s",
				   "initiator");
	if (ret) {
		dprintk(err, "can't init root sysfs object: %d\n", ret);
		unregister_blkdev(disk_major, "ethblk");
		goto out;
	}
	if (!num_hw_queues)
		num_hw_queues = num_online_cpus();

	if ((num_hw_queues + 1) * queue_depth >= tag_size) {
		num_hw_queues = tag_size / queue_depth / 2;
	}
	dprintk(info,
		"using Ethernet packet type 0x%04x, disk major %d, "
		"hw queues %d\n",
		eth_p_type, disk_major, num_hw_queues);
	initiator_running = true;
	dprintk(info, "initiator started\n");
out:
	return ret;
}

int ethblk_initiator_stop(void)
{
	if (!initiator_running)
		return -EINVAL;
	unregister_netdevice_notifier(&ethblk_initiator_netdevice_notifier);
	ethblk_initiator_destroy_all_disks();
	kobject_del(&ethblk_sysfs_initiator_kobj);
	ethblk_initiator_stop_workers();
	unregister_blkdev(disk_major, "ethblk");
	initiator_running = false;
	ida_destroy(&ethblk_used_minors);
	dprintk(info, "initiator stopped\n");
	return 0;
}
