// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
*/

#include <linux/blk-mq.h>
#include <linux/module.h>
#include <linux/version.h>
#include "ethblk.h"
#include "network.h"
#include "target.h"
#include "worker.h"

int force_dma_alignment = 511;
module_param(force_dma_alignment, int, 0644);
MODULE_PARM_DESC(force_dma_alignment, "Force DMA alignment of backing store (511 by default)");

static bool target_running = false;

static struct ethblk_worker_pool *workers;

#define NET_STAT_ADD(i, var, val)                                              \
	do {                                                                   \
		if (i) {                                                       \
			if (i->d->net_stat_enabled) {                          \
				struct ethblk_target_disk_net_stat *dstat =    \
					this_cpu_ptr(i->d->stat);              \
				dstat->_##var += val;                          \
				if (i->net_stat_enabled) {                     \
					struct ethblk_target_disk_net_stat     \
						*is = this_cpu_ptr(i->stat);   \
					is->_##var += val;                     \
				}                                              \
			}                                                      \
		}                                                              \
	} while (0)

#define NET_STAT_INC(i, var) NET_STAT_ADD(i, var, 1)

#define NET_STAT_GET(struc, var)                                               \
	({                                                                     \
		int cpu;                                                       \
		unsigned long long acc = 0;                                    \
		for_each_possible_cpu (cpu) {                                  \
			acc += (per_cpu_ptr(struc, cpu))->_##var;              \
		}                                                              \
		acc;                                                           \
	})

static struct kmem_cache *ethblk_target_cmd_cache = NULL;

static DEFINE_MUTEX(ethblk_target_disks_lock);
static struct list_head ethblk_target_disks;

static void ethblk_target_initiator_free_deferred(struct work_struct *w);
static void
ethblk_target_disk_delete_initiator(struct ethblk_target_disk_ini *ini);
static void ethblk_target_disk_free_deferred(struct work_struct *w);
static void ethblk_target_ini_free(struct percpu_ref *ref);

static struct ethblk_target_disk *ethblk_target_find_disk(unsigned short drv_id);

static void ethblk_target_disk_free(struct percpu_ref *ref);

static inline void ethblk_target_get_disk(struct ethblk_target_disk *d)
{
	percpu_ref_get(&d->ref);
}

static inline void ethblk_target_put_disk(struct ethblk_target_disk *d)
{
	percpu_ref_put(&d->ref);
}

static inline void ethblk_target_get_ini(struct ethblk_target_disk_ini *ini)
{
	percpu_ref_get(&ini->ref);
}

static inline void ethblk_target_put_ini(struct ethblk_target_disk_ini *ini)
{
	percpu_ref_put(&ini->ref);
}

static int ethblk_target_disk_net_stat_init(
	struct ethblk_target_disk_net_stat __percpu **stat)
{
	struct ethblk_target_disk_net_stat *st;
	unsigned int i;

	*stat = alloc_percpu(struct ethblk_target_disk_net_stat);

	if (!*stat) {
		dprintk(err, "can't alloc disk stat\n");
		return -ENOMEM;
	}
	for_each_possible_cpu (i) {
		st = per_cpu_ptr(*stat, i);
		memset(st, 0, sizeof(struct ethblk_target_disk_net_stat));
	}
	return 0;
}

static void ethblk_target_unregister_netdevice(struct net_device *nd)
{
	struct ethblk_target_disk *d, *n;
	struct ethblk_target_disk_ini *ini;

	/* FIXME rtnl_lock held, we are in atomic context. Oh well... */
	dprintk(info, "nd %px name %s\n", nd, nd->name);
	rcu_read_lock();
	list_for_each_entry_safe (d, n, &ethblk_target_disks, list) {
		list_for_each_entry_rcu (ini, &d->initiators, list) {
			if (nd == ini->nd) {
				ethblk_target_disk_delete_initiator(ini);
			}
		}
	}
	rcu_read_unlock();
}

static struct ethblk_target_disk_ini *
ethblk_target_disk_initiator_find(struct ethblk_target_disk *d,
				  const char *mac, struct net_device *nd)
{
	struct ethblk_target_disk_ini *ini;

	rcu_read_lock();
	list_for_each_entry_rcu (ini, &d->initiators, list) {
		if ((nd == ini->nd) && ether_addr_equal(mac, ini->mac)) {
			ethblk_target_get_ini(ini);
			goto out;
		}
	}
	ini = NULL;
out:
	rcu_read_unlock();
	return ini;
}

static int ethblk_target_disk_access_check(struct ethblk_target_disk *d,
					   const unsigned char *mac,
					   struct net_device *nd)
{
	struct ethblk_target_disk_ini *ini;

	ini = ethblk_target_disk_initiator_find(d, mac, nd);

	if (ini)
		ethblk_target_put_ini(ini);

	return !!ini;
}

static struct kobject ethblk_sysfs_target_kobj;

static int ethblk_target_disk_net_stat_dump(
	char *buf, int len, struct ethblk_target_disk_net_stat __percpu *stat)
{
	return snprintf(buf, len,
			"rx-count %llu\ntx-count %llu\nrx-bytes %llu\n"
			"tx-bytes %llu\nrx-dropped %llu\ntx-dropped %llu\n"
			"err-count %llu\n",
			NET_STAT_GET(stat, cnt.rx_count),
			NET_STAT_GET(stat, cnt.tx_count),
			NET_STAT_GET(stat, cnt.rx_bytes),
			NET_STAT_GET(stat, cnt.tx_bytes),
			NET_STAT_GET(stat, cnt.rx_dropped),
			NET_STAT_GET(stat, cnt.tx_dropped),
			NET_STAT_GET(stat, cnt.err_count));
}

static ssize_t ethblk_target_disk_ini_stat_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct ethblk_target_disk_ini *ini =
		container_of(kobj, struct ethblk_target_disk_ini, kobj);
	ssize_t ret;

	ret = ethblk_target_disk_net_stat_dump(buf, PAGE_SIZE, ini->stat);

	return min_t(ssize_t, (ssize_t)PAGE_SIZE, ret);
}

static struct kobj_attribute ethblk_target_disk_ini_stat_attr =
	__ATTR(stat, 0440, ethblk_target_disk_ini_stat_show, NULL);

static struct attribute *ethblk_target_disk_ini_attrs[] = {
	&ethblk_target_disk_ini_stat_attr.attr, NULL
};

static struct attribute_group ethblk_target_disk_ini_group = {
	.attrs = ethblk_target_disk_ini_attrs,
};

static struct kobj_type ethblk_target_disk_ini_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};


static void ethblk_target_announce(struct ethblk_target_disk_ini *ini)
{
	struct ethblk_hdr *req_hdr;
	struct sk_buff *skb;
	int hdr_size = sizeof(struct ethblk_hdr);// + sizeof(struct ethblk_cfg_hdr);

	rcu_read_lock();
	dev_hold(ini->nd);
	skb = ethblk_network_new_skb(hdr_size);
	if (skb == NULL) {
		dprintk(err, "skb alloc failure\n");
		goto err;
	}
	skb_put(skb, hdr_size);
	skb->dev = ini->nd;

	req_hdr = (struct ethblk_hdr *)skb_mac_header(skb);
	memset(req_hdr, 0, hdr_size);

	eth_broadcast_addr(req_hdr->dst);
	ether_addr_copy(req_hdr->src, ini->nd->dev_addr);

	req_hdr->type = cpu_to_be16(eth_p_type);
	req_hdr->version = ETHBLK_PROTO_VERSION;
	req_hdr->response = 0;
	req_hdr->status = 0;
	req_hdr->drv_id = cpu_to_be16(ini->d->drv_id);
	req_hdr->op = ETHBLK_OP_CFG_CHANGE;

	ethblk_network_xmit_skb(skb);

	/* FIXME send IP address as well  */
err:
	dev_put(ini->nd);
	rcu_read_unlock();
}

static int ethblk_target_disk_add_initiator(struct ethblk_target_disk *d,
					    unsigned char *mac, char *iface)
{
	struct ethblk_target_disk_ini *ini;
	struct net_device *nd;
	int ret;

	nd = dev_get_by_name(&init_net, iface);
	if (!nd) {
		dprintk(err, "no network interface %s\n", iface);
		ret = -EINVAL;
		goto err;
	}

	if (ether_addr_equal(mac, nd->dev_addr)) {
		dprintk(err, "target can't be initiator to self\n");
		ret = -EINVAL;
		goto err_free_netdev;
	}

	ini = kzalloc(sizeof(struct ethblk_target_disk_ini), GFP_KERNEL);
	if (!ini) {
		dprintk(err, "can't allocate memory for new initiator\n");
		ret = -ENOMEM;
		goto err_free_netdev;
	}

	ret = ethblk_target_disk_net_stat_init(&ini->stat);
	if (ret != 0) {
		dprintk(err, "can't allocate stat memory for new initiator\n");
		goto err_free_ini;
	}
	snprintf(ini->name, sizeof(ini->name),
		 "%s_%02x:%02x:%02x:%02x:%02x:%02x", iface, mac[0], mac[1],
		 mac[2], mac[3], mac[4], mac[5]);
	dprintk(debug, "disk %s creating initiator %s %px\n", d->name, ini->name,
		ini);

	ini->d = d;
	ini->nd = nd;
	ini->net_stat_enabled = d->net_stat_enabled;

	ether_addr_copy(ini->mac, mac);
	ini->ip = ethblk_network_if_get_saddr(ini->nd);

	INIT_LIST_HEAD(&ini->list);
	INIT_WORK(&ini->free_work, ethblk_target_initiator_free_deferred);

	if (ethblk_target_disk_access_check(d, ini->mac, nd)) {
		dprintk(err, "disk %s initiator %s already exists\n", d->name,
			ini->name);
		ret = -EEXIST;
		goto err_free_ini;
	}

	ret = percpu_ref_init(&ini->ref, ethblk_target_ini_free, 0, GFP_KERNEL);
	if (ret) {
		dprintk(err, "cannot init percpu_ref\n");
		goto err_free_ini;
	}

	mutex_lock(&d->initiator_lock);
	ret = kobject_init_and_add(&ini->kobj,
				   &ethblk_target_disk_ini_kobj_type,
				   &d->inis_kobj, ini->name);
	if (ret) {
		mutex_unlock(&d->initiator_lock);
		dprintk(err, "disk %s ini %s can't add kobject: %d\n", d->name,
			ini->name, ret);
		goto err_free_ref;
	}
	ret = sysfs_create_group(&ini->kobj, &ethblk_target_disk_ini_group);
	if (ret) {
		mutex_unlock(&d->initiator_lock);
		dprintk(err, "disk %s ini %s can't create sysfs: %d\n", d->name,
			ini->name, ret);
		goto err_free_kobject;
	}

	ethblk_target_get_disk(ini->d);

	list_add_tail_rcu(&ini->list, &d->initiators);
	mutex_unlock(&d->initiator_lock);

	synchronize_rcu();

	dprintk(info, "disk %s added new initiator %s\n", d->name, ini->name);

	ethblk_target_announce(ini);

	return 0;

err_free_kobject:
	kobject_del(&ini->kobj);
err_free_ref:
	percpu_ref_exit(&ini->ref);
err_free_ini:
	if (ini->stat)
		free_percpu(ini->stat);
	kfree(ini);
err_free_netdev:
	dev_put(nd);
err:
	return ret;
}

static void ethblk_target_initiator_free_deferred(struct work_struct *w)
{
	struct ethblk_target_disk_ini *ini =
		container_of(w, struct ethblk_target_disk_ini, free_work);

	dprintk(info, "disk %s freeing ini %s %px\n", ini->d->name, ini->name, ini);

	dev_put(ini->nd);
	sysfs_remove_group(&ini->kobj, &ethblk_target_disk_ini_group);
	kobject_del(&ini->kobj);

	ethblk_target_put_disk(ini->d);

	free_percpu(ini->stat);
	percpu_ref_exit(&ini->ref);
	kfree_rcu(ini, rcu);
}

static void ethblk_target_ini_free(struct percpu_ref *ref)
{
	struct ethblk_target_disk_ini *ini =
		container_of(ref, struct ethblk_target_disk_ini, ref);

	dprintk(info, "disk %s ini %s %px schedule freeing\n", ini->d->name, ini->name, ini);

	schedule_work(&ini->free_work);
}

static void
ethblk_target_disk_delete_initiator(struct ethblk_target_disk_ini *ini)
{
	dprintk(info, "disk %s deleting initiator %s\n", ini->d->name,
		ini->name);

// NOTE	ini->d->initiator_lock) is already held
	list_del_rcu(&ini->list);

	percpu_ref_kill(&ini->ref);

	dprintk(info, "disk %s initiator %s deleted\n", ini->d->name,
		ini->name);
}

static int
ethblk_target_disk_find_and_delete_initiator(struct ethblk_target_disk *d,
					     unsigned char *mac, char *iface)
{
	struct ethblk_target_disk_ini *ini;
	struct net_device *nd;
	int ret;
	char s[ETH_ALEN * 3 + IFNAMSIZ];

	snprintf(s, sizeof(s), "%s_%02x:%02x:%02x:%02x:%02x:%02x", iface,
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	dprintk(debug, "disk %s deleting initiator %s\n", d->name, s);

	nd = dev_get_by_name(&init_net, iface);
	if (!nd) {
		dprintk(err, "no network interface %s\n", iface);
		ret = -ENOENT;
		goto err;
	}

	ini = ethblk_target_disk_initiator_find(d, mac, nd);

	if (!ini) {
		char s[ETH_ALEN * 3];
		ethblk_dump_mac(s, sizeof(s), mac);
		dprintk(info, "disk %s initiator %s_%s was not found\n",
			d->name, nd->name, s);
		ret = -ENOENT;
		goto err_nd;
	}

	mutex_lock(&d->initiator_lock);
	ethblk_target_disk_delete_initiator(ini);
	mutex_unlock(&d->initiator_lock);

	ethblk_target_put_ini(ini);
	ret = 0;
err_nd:
	dev_put(nd);
err:
	return ret;
}

static void ethblk_target_disk_inis_free(struct ethblk_target_disk *d)
{
	struct ethblk_target_disk_ini *ini;

	mutex_lock(&d->initiator_lock);
	dprintk(info, "disk %s deleting initiators\n", d->name);

	list_for_each_entry_rcu (ini, &d->initiators, list) {
		dprintk(info, "disk %s deleting initiator %s\n", d->name,
			ini->name);
		ethblk_target_disk_delete_initiator(ini);
	}
	mutex_unlock(&d->initiator_lock);
}

static ssize_t ethblk_target_disk_backend_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct ethblk_target_disk *d =
		container_of(kobj, struct ethblk_target_disk, kobj);
	return snprintf(buf, PAGE_SIZE, "%s\n", d->backend_path);
}

static void ethblk_target_destroy_disk_deferred(struct work_struct *w)
{
	struct ethblk_target_disk *d =
		container_of(w, struct ethblk_target_disk, destroy_work);

	dprintk(info, "disk %s\n", d->name);
	percpu_ref_kill(&d->ref);

	/* NOTE can't wait for completion - disk_free will be scheduled as */
	/* work, and it may get added to the same work queue we currently */
	/* run on */
}

static ssize_t ethblk_target_disk_destroy_store(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct ethblk_target_disk *d =
		container_of(kobj, struct ethblk_target_disk, kobj);

	dprintk(info, "destroying disk %s %px\n", d->name, d);
	schedule_work(&d->destroy_work);
	return count;
}

static ssize_t ethblk_target_disk_net_stat_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct ethblk_target_disk *d =
		container_of(kobj, struct ethblk_target_disk, kobj);
	ssize_t ret;

	ret = ethblk_target_disk_net_stat_dump(buf, PAGE_SIZE, d->stat);

	return min_t(ssize_t, PAGE_SIZE, ret);
}

static struct kobj_attribute ethblk_target_disk_backend_attr =
	__ATTR(backend, 0440, ethblk_target_disk_backend_show, NULL);

static struct kobj_attribute ethblk_target_disk_destroy_attr =
	__ATTR(destroy, 0220, NULL, ethblk_target_disk_destroy_store);

static struct kobj_attribute ethblk_target_disk_net_stat_attr =
	__ATTR(stat, 0440, ethblk_target_disk_net_stat_show, NULL);

static struct attribute *ethblk_target_disk_attrs[] = {
	&ethblk_target_disk_backend_attr.attr,
	&ethblk_target_disk_destroy_attr.attr,
	&ethblk_target_disk_net_stat_attr.attr, NULL
};

static struct attribute_group ethblk_target_disk_group = {
	.attrs = ethblk_target_disk_attrs,
};

static struct kobj_type ethblk_target_disk_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static ssize_t ethblk_target_disk_ini_add_store(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct ethblk_target_disk *d =
		container_of(kobj, struct ethblk_target_disk, inis_kobj);
	unsigned char mac[ETH_ALEN];
	char iface[IFNAMSIZ];
	char s[ETH_ALEN * 3 + 1];
	int ret;

	ret = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %s",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],
		     iface);
	if (ret != 7) {
		dprintk(err, "can't parse (%d): %s\n", ret, buf);
		return -EINVAL;
	}

	ret = ethblk_target_disk_add_initiator(d, mac, iface);
	if (ret) {
		ethblk_dump_mac(s, sizeof(s), mac);
		dprintk(debug, "disk %s can't add initiator %s/%s\n", d->name,
			s, iface);
		count = ret;
	}
	return count;
}

static ssize_t ethblk_target_disk_ini_delete_store(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   const char *buf,
						   size_t count)
{
	struct ethblk_target_disk *d =
		container_of(kobj, struct ethblk_target_disk, inis_kobj);
	unsigned char mac[ETH_ALEN];
	char iface[IFNAMSIZ];
	char s[ETH_ALEN * 3 + 1];
	int ret;

	ret = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx %s",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],
		     iface);
	if (ret != 7) {
		dprintk(err, "can't parse (%d): %s\n", ret, buf);
		return -EINVAL;
	}

	ret = ethblk_target_disk_find_and_delete_initiator(d, mac, iface);
	if (ret) {
		ethblk_dump_mac(s, sizeof(s), mac);
		dprintk(debug, "disk %s can't del initiator %s_%s\n", d->name,
			iface, s);
		count = ret;
	}
	return count;
}

static struct kobj_attribute ethblk_target_disk_ini_add_attr =
	__ATTR(add, 0220, NULL, ethblk_target_disk_ini_add_store);
static struct kobj_attribute ethblk_target_disk_ini_delete_attr =
	__ATTR(delete, 0220, NULL, ethblk_target_disk_ini_delete_store);

static struct attribute *ethblk_target_disk_inis_attrs[] = {
	&ethblk_target_disk_ini_add_attr.attr,
	&ethblk_target_disk_ini_delete_attr.attr, NULL
};

static struct attribute_group ethblk_target_disk_inis_group = {
	.attrs = ethblk_target_disk_inis_attrs,
};

static struct kobj_type ethblk_target_disk_inis_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static int ethblk_target_disk_create(unsigned short drv_id, char *path)
{
	int ret = -EINVAL;
	struct ethblk_target_disk *d;
	struct request_queue *q;

	dprintk(info, "creating disk drv_id:%d path:%s\n", drv_id, path);
	/* FIXME do mutex_lock only for list_add_rcu
    rest is under rcu_lock
    or add empty disk struct to the list and set the flag that it is initing */
	mutex_lock(&ethblk_target_disks_lock);
	d = ethblk_target_find_disk(drv_id);
	if (d) {
		dprintk(err, "disk %s already exists: %px\n", d->name, d);
		ethblk_target_put_disk(d);
		ret = -EEXIST;
		goto out;
	}
	d = kzalloc(sizeof(struct ethblk_target_disk), GFP_KERNEL);
	if (!d) {
		dprintk(err, "can't allocate memory for disk eda%d\n", drv_id);
		ret = -ENOMEM;
		goto out;
	}
	d->drv_id = drv_id;
	d->net_stat_enabled = net_stat;
	uuid_gen(&d->uuid);

	INIT_LIST_HEAD(&d->list);
	INIT_LIST_HEAD(&d->initiators);
	INIT_WORK(&d->destroy_work, ethblk_target_destroy_disk_deferred);
	INIT_WORK(&d->free_work, ethblk_target_disk_free_deferred);
	ret = percpu_ref_init(&d->ref, ethblk_target_disk_free, 0, GFP_KERNEL);
	if (ret) {
		dprintk(err, "can't init percpu_ref: %d\n", ret);
		goto out;
	}
	init_completion(&d->destroy_completion);
	mutex_init(&d->initiator_lock);

	if (ethblk_target_disk_net_stat_init(&d->stat) != 0) {
		kfree(d);
		d = NULL;
		goto out;
	}

	snprintf(d->name, sizeof(d->name), "eda%d", drv_id);

	d->bd = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(d->bd)) {
		dprintk(err, "disk %s can't open backing store %s: %ld\n",
			d->name, path, PTR_ERR(d->bd));
		d->bd = NULL;
		goto out_err;
	}
	q = d->bd->bd_queue;

	d->old_dma_alignment = q->dma_alignment;
	if (q->dma_alignment != force_dma_alignment) {
		blk_queue_dma_alignment(q, force_dma_alignment);
		dprintk(info, "disk %s backing store %s has new dma alignment %d\n", d->name, path, q->dma_alignment);
	}

	ret = kobject_init_and_add(&d->kobj, &ethblk_target_disk_kobj_type,
				   &ethblk_sysfs_target_kobj, d->name);
	if (ret) {
		dprintk(err, "disk %s can't add kobject: %d\n", d->name, ret);
		goto out_err;
	}
	ret = sysfs_create_group(&d->kobj, &ethblk_target_disk_group);
	if (ret) {
		dprintk(err, "disk %s can't create sysfs group: %d\n", d->name,
			ret);
		goto out_d_kobj;
	}

	ret = kobject_init_and_add(&d->inis_kobj,
				   &ethblk_target_disk_inis_kobj_type, &d->kobj,
				   "initiators");
	if (ret) {
		dprintk(err, "disk %s can't create sysfs group: %d\n", d->name,
			ret);
		goto out_sysfs;
	}
	ret = sysfs_create_group(&d->inis_kobj, &ethblk_target_disk_inis_group);
	if (ret) {
		dprintk(err, "disk %s can't create sysfs group for inis: %d\n",
			d->name, ret);
		goto out_d_inis_kobj;
	}

	d->backend_path = kstrdup(path, GFP_KERNEL);

	list_add_tail_rcu(&d->list, &ethblk_target_disks);
	dprintk(info, "disk %s created\n", d->name);
	ret = 0;
	goto out;

out_d_inis_kobj:
	kobject_del(&d->inis_kobj);
out_sysfs:
	sysfs_remove_group(&d->kobj, &ethblk_target_disk_group);
out_d_kobj:
	kobject_del(&d->kobj);
out_err:
	free_percpu(d->stat);
	if (d->bd)
		blkdev_put(d->bd, FMODE_READ | FMODE_WRITE);
	kfree(d);
	d = NULL;
out:
	mutex_unlock(&ethblk_target_disks_lock);
	synchronize_rcu();
	return ret;
};

static void ethblk_target_disk_free_deferred(struct work_struct *w)
{
	struct ethblk_target_disk *d =
		container_of(w, struct ethblk_target_disk, free_work);
	unsigned short drv_id = d->drv_id;

	dprintk(info, "freeing disk %s %px\n", d->name, d);

	mutex_lock(&ethblk_target_disks_lock);
	sysfs_remove_group(&d->inis_kobj, &ethblk_target_disk_inis_group);
	kobject_del(&d->inis_kobj);
	sysfs_remove_group(&d->kobj, &ethblk_target_disk_group);
	kobject_del(&d->kobj);
	list_del_rcu(&d->list);
	mutex_unlock(&ethblk_target_disks_lock);

	synchronize_rcu();

	blk_queue_dma_alignment(d->bd->bd_queue, d->old_dma_alignment);
	blkdev_put(d->bd, FMODE_READ | FMODE_WRITE);
	/* Initiators must be already freed by now as they hold
	   refcounts to the disk */
	free_percpu(d->stat);
	kfree(d->backend_path);
	complete(&d->destroy_completion);
	kfree_rcu(d, rcu);
	dprintk(info, "disk %px eda%d freed\n", d, drv_id);
}

static void ethblk_target_disk_free(struct percpu_ref *ref)
{
	struct ethblk_target_disk *d =
		container_of(ref, struct ethblk_target_disk, ref);
	schedule_work(&d->free_work);
}

static void ethblk_target_destroy_all_disks(void)
{
	struct ethblk_target_disk *d, *n;
	LIST_HEAD(tmp);

	mutex_lock(&ethblk_target_disks_lock);
	list_splice(&ethblk_target_disks, &tmp);
	mutex_unlock(&ethblk_target_disks_lock);

	list_for_each_entry_safe (d, n, &tmp, list) {
		dprintk(info, "destroying %s %px\n", d->name, d);
		percpu_ref_kill(&d->ref);

		ethblk_target_disk_inis_free(d);

		wait_for_completion(&d->destroy_completion);
	}
}

static ssize_t ethblk_target_disk_create_store(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       const char *buf, size_t count)
{
	unsigned short drv_id;
	char path[256];
	int ret;

	ret = sscanf(buf, "%hu %s", &drv_id, path);
	if (ret != 2) {
		dprintk(err, "can't parse (%d): %s\n", ret, buf);
		return -EINVAL;
	}
	ret = ethblk_target_disk_create(drv_id, path);
	if (ret) {
		dprintk(err, "can't create disk eda%d = %s: %d\n", drv_id,
			path, ret);
		count = ret;
	}
	return count;
}

static struct kobj_attribute ethblk_target_disk_create_attr =
	__ATTR(create_disk, 0220, NULL, ethblk_target_disk_create_store);

static struct attribute *ethblk_sysfs_target_default_attrs[] = {
	&ethblk_target_disk_create_attr.attr, NULL
};

static struct kobj_type ethblk_sysfs_target_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = ethblk_sysfs_target_default_attrs,
};

static void ethblk_target_cmd_rw_complete(struct bio *);
static void ethblk_target_send_reply(struct ethblk_target_cmd *cmd);

static void ethblk_target_cmd_free(struct ethblk_target_cmd *cmd)
{
	dprintk(debug, "cmd %px\n", cmd);
	if (!cmd)
		return;
	if (cmd->ini)
		ethblk_target_put_ini(cmd->ini);
	if (cmd->d)
		ethblk_target_put_disk(cmd->d);
	if (cmd->bio)
		bio_put(cmd->bio);
	if (cmd->req_skb)
		consume_skb(cmd->req_skb);
	if (cmd->rep_skb)
		consume_skb(cmd->rep_skb);
	kmem_cache_free(ethblk_target_cmd_cache, cmd);
}

static void
ethblk_target_cmd_reply_fill_skb_headers(struct ethblk_target_cmd *cmd)
{
	if (cmd->l3) {
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(cmd->rep_skb);
		struct iphdr *ip = (struct iphdr *)(eth + 1);
		struct udphdr *udp = (struct udphdr *)(ip + 1);
		struct ethhdr *s_eth =
			(struct ethhdr *)skb_mac_header(cmd->req_skb);
		struct iphdr *s_ip = (struct iphdr *)(s_eth + 1);
		struct udphdr *s_udp = (struct udphdr *)(s_ip + 1);

		/* make space for eth, ip and udp headers (ethblk hdr follows) */
		skb_put(cmd->rep_skb, sizeof(struct ethhdr) +
			sizeof(struct iphdr) +
			sizeof(struct udphdr));

		cmd->rep_skb->protocol = htons(ETH_P_IP);
		eth->h_proto = htons(ETH_P_IP);
		ip->version = 4;
		ip->ihl = 5;
		ip->ttl = 255;
		ip->saddr = s_ip->daddr;
		ip->daddr = s_ip->saddr;
		ip->protocol = IPPROTO_UDP;
		ip->frag_off = htons(IP_DF);
		ip->id = 0;
		udp->source = s_udp->dest;
		udp->dest = s_udp->source;
	} else {
		cmd->rep_skb->protocol = htons(eth_p_type);
	}
}

static void
ethblk_target_cmd_reply_finalize_skb_headers(struct ethblk_target_cmd *cmd)
{
	if (cmd->l3) {
		struct ethblk_hdr *rep_hdr = ethblk_network_skb_get_hdr(cmd->rep_skb);
		struct ethhdr *eth = (struct ethhdr *)skb_mac_header(cmd->rep_skb);
		struct iphdr *ip = (struct iphdr *)(eth + 1);
		struct udphdr *udp = (struct udphdr *)(ip + 1);

		ether_addr_copy(eth->h_dest, rep_hdr->dst);
		ether_addr_copy(eth->h_source, rep_hdr->src);
		ip->tot_len = htons(cmd->rep_skb->len - sizeof(struct ethhdr));
		udp->len = htons(ntohs(ip->tot_len) - sizeof(struct iphdr));
		udp->check = 0;
		ip_send_check(ip);
	}
}

static void ethblk_target_cmd_id(struct ethblk_target_cmd *cmd)
{
	struct sk_buff *req_skb = cmd->req_skb;
	struct ethblk_hdr *req_hdr = cmd->req_hdr;
	struct ethblk_hdr *rep_hdr;
	struct ethblk_cfg_hdr *rep_cfg_hdr;
	struct sk_buff *rep_skb;
	unsigned short drv_id;
	struct ethblk_target_disk_net_stat *stat;
	int len = ETH_ZLEN + 512;

	drv_id = be16_to_cpu(req_hdr->drv_id);
	cmd->d = ethblk_target_find_disk(drv_id);
	if (!cmd->d) {
		dprintk_ratelimit(err, "unknown drv_id %d\n", drv_id);
		return;
	}
	dprintk(debug, "%s disk ID\n", cmd->d->name);

	stat = per_cpu_ptr(cmd->d->stat, smp_processor_id());

	cmd->ini =
		ethblk_target_disk_initiator_find(cmd->d, req_hdr->src, req_skb->dev);

	if (!cmd->ini) {
		char s[ETH_ALEN * 3 + 1];
		ethblk_dump_mac(s, sizeof(s), req_hdr->src);
		dprintk_ratelimit(err,
				  "initiator %s_%s has no access to disk %s\n",
				  req_skb->dev->name, s, cmd->d->name);
		/* can't use NET_STAT_INC, it needs initiator */
		stat->_cnt.rx_dropped++;
		goto out;
	}

	if (cmd->l3)
		len += sizeof(struct iphdr) + sizeof(struct udphdr);

	rep_skb = ethblk_network_new_skb(len);
	if (!rep_skb) {
		dprintk(debug, "can't allocate reply skb len %d\n", len);
		NET_STAT_INC(cmd->ini, cnt.rx_dropped);
		goto out;
	}

	cmd->rep_skb = rep_skb; /* fill/finalize_skb_headers need it*/

	ethblk_target_cmd_reply_fill_skb_headers(cmd);
	rep_hdr = ethblk_network_skb_get_hdr(rep_skb);

	skb_put(rep_skb, sizeof(struct ethblk_hdr) + sizeof(struct ethblk_cfg_hdr));

	ether_addr_copy(rep_hdr->src, req_skb->dev->dev_addr);
	ether_addr_copy(rep_hdr->dst, req_hdr->src);

	rep_hdr->type = cpu_to_be16(eth_p_type);
	rep_hdr->version = ETHBLK_PROTO_VERSION;
	rep_hdr->response = 1;
	rep_hdr->status = 0;
	rep_hdr->drv_id = cpu_to_be16(cmd->d->drv_id);
	rep_hdr->tag = req_hdr->tag;
	rep_hdr->op = req_hdr->op;
	rep_hdr->lba = req_hdr->lba;
	rep_hdr->num_sectors = req_hdr->num_sectors;
	rep_skb->dev = req_skb->dev;

	rep_cfg_hdr = (struct ethblk_cfg_hdr *)(rep_hdr + 1);
	rep_cfg_hdr->q_depth = cpu_to_be16(blk_queue_depth(cmd->d->bd->bd_queue));
	rep_cfg_hdr->num_queues = cpu_to_be16(min(req_skb->dev->num_rx_queues, num_online_cpus()));
	rep_cfg_hdr->num_sectors = cpu_to_be64(i_size_read(cmd->d->bd->bd_inode) >> 9);  /* FIXME send disk size and uuid */
	uuid_copy((uuid_t *)rep_cfg_hdr->uuid, &cmd->d->uuid);

	NET_STAT_INC(cmd->ini, cnt.rx_count);

	ethblk_target_cmd_reply_finalize_skb_headers(cmd);

	cmd->rep_skb = NULL; /* to avoid skb_clone */
	if (ethblk_network_xmit_skb(rep_skb) == NET_XMIT_DROP)
		NET_STAT_INC(cmd->ini, cnt.tx_count);
	else
		NET_STAT_INC(cmd->ini, cnt.tx_dropped);
out:
	ethblk_target_cmd_free(cmd);
}

static void ethblk_target_cmd_rw(struct ethblk_target_cmd *cmd)
{
	ssize_t rep_skb_alloc_len;
	struct ethblk_hdr *req_hdr;
	struct ethblk_hdr *rep_hdr;
	struct sk_buff *rep_skb;
	struct ethblk_target_disk *d;
	unsigned long lba;
	int len;
	unsigned short drv_id;
	struct request_queue *q;
	struct bio *bio;
	bool write;
	struct scatterlist sgl[16];
	int sgn;
	struct sk_buff *req_skb = cmd->req_skb;
	struct ethblk_target_disk_net_stat *stat;
	struct sk_buff *bio_skb;
	int offset;

	req_hdr = cmd->req_hdr;
	drv_id = be16_to_cpu(req_hdr->drv_id);

	cmd->d = d = ethblk_target_find_disk(drv_id);
	if (!d) {
		dprintk_ratelimit(err, "unknown drv_id %d\n", drv_id);
		goto out;
	}

	stat = per_cpu_ptr(d->stat, smp_processor_id());

	cmd->ini = ethblk_target_disk_initiator_find(d, req_hdr->src, req_skb->dev);

	if (!cmd->ini) {
		char s[ETH_ALEN * 3 + 1];
		ethblk_dump_mac(s, sizeof(s), req_hdr->src);
		dprintk_ratelimit(err,
				  "initiator %s/%s has no access to disk %s\n",
				  s, req_skb->dev->name, d->name);
		goto out_drop;
	}

	q = bdev_get_queue(d->bd);
	if (IS_ERR(q)) {
		dprintk(err, "disk %s can't get queue: %ld\n", d->name,
			PTR_ERR(q));
		goto out_drop;
	}

	write = (req_hdr->op == ETHBLK_OP_WRITE);
	lba = be64_to_cpu(req_hdr->lba);
	len = req_hdr->num_sectors << 9;

	rep_skb_alloc_len = sizeof(struct ethblk_hdr);

	if (cmd->l3)
		rep_skb_alloc_len += sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr);

	rep_skb = ethblk_network_new_skb_with_payload(rep_skb_alloc_len,
						      (write ? 0 : len));
	if (!rep_skb) {
		dprintk(err, "can't allocate %ld bytes for rep_skb\n",
			rep_skb_alloc_len);
		goto out_drop;
	}

	cmd->rep_skb = rep_skb;

	ethblk_target_cmd_reply_fill_skb_headers(cmd);

	rep_hdr = ethblk_network_skb_get_hdr(rep_skb);

	skb_put(rep_skb, sizeof(struct ethblk_hdr));
	ether_addr_copy(rep_hdr->src, req_skb->dev->dev_addr);
	ether_addr_copy(rep_hdr->dst, req_hdr->src);

	rep_hdr->type = cpu_to_be16(eth_p_type);
	rep_hdr->version = ETHBLK_PROTO_VERSION;
	rep_hdr->response = 1;
	rep_hdr->status = 0;
	rep_hdr->drv_id = req_hdr->drv_id;
	rep_hdr->tag = req_hdr->tag;
	rep_hdr->op = req_hdr->op;
	rep_hdr->lba = req_hdr->lba;
	rep_hdr->num_sectors = req_hdr->num_sectors;

	rep_skb->dev = req_skb->dev;

	dprintk(debug, "req_skb %px rep_skb %px tag %u disk %s op %s lba %ld len %d\n",
		req_skb, rep_skb, be32_to_cpu(req_hdr->tag), d->name,
		req_hdr->op == ETHBLK_OP_READ ? "READ" : "WRITE", lba,
		len);

	NET_STAT_INC(cmd->ini, cnt.rx_count);
	NET_STAT_ADD(cmd->ini, cnt.rx_bytes, write ? len : 0);

	if (write) {
		bio_skb = req_skb;
	} else {
		bio_skb = rep_skb;
	}

	sg_init_table(sgl, ARRAY_SIZE(sgl));
	offset = (unsigned char *)ethblk_network_skb_get_payload(bio_skb) -
		skb_mac_header(bio_skb);
	sgn = skb_to_sgvec(bio_skb, sgl, offset, len);
	if (sgn < 0) {
		dprintk(err, "skb %px skb_to_sgvec failed: %d\n", bio_skb, sgn);
		goto out_err;
	}
	bio = bio_alloc(GFP_ATOMIC, sgn);
	if (bio) {
		int i, ret;
		struct scatterlist *sg;
		for_each_sg (sgl, sg, sgn, i) {
			ret = bio_add_page(bio, sg_page(sg), sg->length,
					   sg->offset);
			dprintk(debug,
				"skb %px bio %px bio_add_page[%d/%d] "
				"page %px length %d offset %d: %d\n",
				bio_skb, bio, i, sgn, sg_page(sg), sg->length,
				sg->offset, ret);
			if (ret != sg->length) {
				dprintk(err,
					"skb %px bio %px can't add "
					"page[%d/%d] %px length %d "
					"offset %d: %d\n",
					bio_skb, bio, i, sgn, sg_page(sg),
					sg->length, sg->offset, ret);
				bio_put(bio);
				bio = NULL;
				goto out_err;
			}
		}
	} else {
		dprintk_ratelimit(err, "disk %s can't alloc bio\n", d->name);
		goto out_err;
	}

	/* add payload for READ reply skb */
	if (!write) {
		rep_skb->data_len = len;
		rep_skb->len += len;
	}

	bio->bi_iter.bi_sector = lba;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	bio->bi_bdev = d->bd;
#else
	bio_set_dev(bio, d->bd);
#endif
	bio_set_op_attrs(bio, write ? REQ_OP_WRITE : REQ_OP_READ,
/* FIXME RHEL-8...
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
			 (queue_is_rq_based(q) ? REQ_NOWAIT : 0) |
#endif
*/
			 (write ? REQ_SYNC | REQ_IDLE : 0));
	bio->bi_end_io = ethblk_target_cmd_rw_complete;
	bio->bi_private = cmd;
	cmd->bio = bio;

	submit_bio(bio);
	return;
out_err:
	NET_STAT_INC(cmd->ini, cnt.err_count);
	rep_hdr->status = 1;
	ethblk_target_send_reply(cmd);
	return;

out_drop:
	NET_STAT_INC(cmd->ini, cnt.rx_dropped);
out:
	ethblk_target_cmd_free(cmd);
}

static void ethblk_target_send_reply(struct ethblk_target_cmd *cmd)
{
	struct bio *bio = cmd->bio;
	struct ethblk_hdr *rep_hdr = ethblk_network_skb_get_hdr(cmd->rep_skb);

	if (bio) {
		if (bio->bi_status == BLK_STS_AGAIN ||
		    bio->bi_status == BLK_STS_RESOURCE) {
			/* FIXME send pushback reply */
			goto out;
		}

		if (bio->bi_status)
			dprintk(err,
				"complete bio %px rep_skb %px req_skb %px "
				"rep_hdr->tag %u with status %d\n",
				bio, cmd->rep_skb, cmd->req_skb,
				be32_to_cpu(rep_hdr->tag),
				bio->bi_status);
		else
			dprintk(debug,
				"complete bio %px rep_skb %px req_skb %px "
				"rep_hdr->tag %u with status %d\n",
				bio, cmd->rep_skb, cmd->req_skb,
				be32_to_cpu(rep_hdr->tag),
				bio->bi_status);

		if (bio->bi_status != BLK_STS_OK) {
			/* FIXME drop payload, don't send it over network */
			rep_hdr->status = bio->bi_status;
		}
	}

	ethblk_target_cmd_reply_finalize_skb_headers(cmd);

	/* xmit_skb will consume skb, but we need it for the following NET_STAT */
	skb_get(cmd->rep_skb);
	if (ethblk_network_xmit_skb(cmd->rep_skb) == NET_XMIT_DROP) {
		NET_STAT_INC(cmd->ini, cnt.tx_dropped);
	} else {
		NET_STAT_INC(cmd->ini, cnt.tx_count);
		NET_STAT_ADD(cmd->ini, cnt.tx_bytes,
			     (rep_hdr->op == ETHBLK_OP_READ ?
			      rep_hdr->num_sectors << 9 :
			      0));
	}
	consume_skb(cmd->rep_skb);
	cmd->rep_skb = NULL;
out:
	ethblk_target_cmd_free(cmd);
}

static void ethblk_target_cmd_rw_complete(struct bio *bio)
{
	struct ethblk_target_cmd *cmd = bio->bi_private;
	cmd->work_type = ETHBLK_TARGET_CMD_WORK_TYPE_BIO;

	if (!ethblk_worker_enqueue(workers, &cmd->list)) {
		dprintk_ratelimit(debug, "can't enqueue bio work\n");
		ethblk_target_cmd_free(cmd);
	}
}

void ethblk_target_cmd(struct ethblk_target_cmd *cmd)
{
	switch (cmd->req_hdr->op) {
	case ETHBLK_OP_READ:
	case ETHBLK_OP_WRITE:
		ethblk_target_cmd_rw(cmd);
		break;
	case ETHBLK_OP_ID:
		ethblk_target_cmd_id(cmd);
		break;
	case ETHBLK_OP_DISCOVER:
		ethblk_target_handle_discover(cmd->req_skb);
		ethblk_target_cmd_free(cmd);
		break;
	default:
		/* FIXME rx_dropped++ */
		dprintk(err, "skb %px unknown cmdstat %d\n", cmd->req_skb,
			cmd->req_hdr->op);
		ethblk_target_cmd_free(cmd);
		break;
	}
}

void ethblk_target_cmd_deferred(struct sk_buff *skb)
{
	struct ethblk_target_cmd *cmd;

	if (!target_running) {
		consume_skb(skb);
		return;
	}
	cmd = kmem_cache_zalloc(ethblk_target_cmd_cache, GFP_ATOMIC);
	if (!cmd) {
		dprintk_ratelimit(debug, "can't allocate cmd\n");
		consume_skb(skb);
		return;
	}
	dprintk(debug, "alloc cmd %px\n", cmd);
	INIT_LIST_HEAD(&cmd->list);
	cmd->req_skb = skb;
	cmd->req_hdr = ethblk_network_skb_get_hdr(skb);
	cmd->l3 = ethblk_network_skb_is_l3(skb);
	cmd->work_type = ETHBLK_TARGET_CMD_WORK_TYPE_SKB;

	if (!ethblk_worker_enqueue(workers, &cmd->list)) {
		dprintk_ratelimit(debug, "can't enqueue work\n");
		goto err;
	}
	goto out;
err:
	kmem_cache_free(ethblk_target_cmd_cache, cmd);
	consume_skb(skb);
out:
	return;
}

static void ethblk_target_cmd_worker(struct kthread_work *work)
{
	struct ethblk_worker *w =
		container_of(work, struct ethblk_worker, work);
	struct list_head queue;
	struct ethblk_target_cmd *cmd, *n;
	bool queue_empty;
	struct blk_plug plug;
	unsigned long flags;

	dprintk(debug, "worker[%d] on\n", w->idx);
	for (;;) {
		INIT_LIST_HEAD(&queue);
		spin_lock_irqsave(&w->lock, flags);
		list_splice_tail_init(&w->queue, &queue);
		queue_empty = list_empty(&queue);
		if (queue_empty)
			w->active = false;
		spin_unlock_irqrestore(&w->lock, flags);

		if (queue_empty)
			break;

		blk_start_plug(&plug);
		list_for_each_entry_safe (cmd, n, &queue, list) {
			dprintk(debug, "cmd %px type %d\n", cmd, cmd->work_type);
			switch(cmd->work_type) {
			case ETHBLK_TARGET_CMD_WORK_TYPE_SKB:
				ethblk_target_cmd(cmd);
				break;
			case ETHBLK_TARGET_CMD_WORK_TYPE_BIO:
				ethblk_target_send_reply(cmd);
				break;
			default:
				dprintk(err, "unknown work type %d\n",
					cmd->work_type);
				break;
			}
		}
		blk_finish_plug(&plug);
	}

	dprintk(debug, "worker[%d] off\n", w->idx);
}

void ethblk_target_handle_discover(struct sk_buff *skb)
{
	struct ethblk_hdr *req_hdr = ethblk_network_skb_get_hdr(skb);
	struct ethblk_hdr *rep_hdr;
	struct sk_buff *rep_skb;
	struct ethblk_target_disk *d;
	struct ethblk_target_disk_ini *ini;
	char s[ETH_ALEN * 3 + 1];

	ethblk_dump_mac(s, sizeof(s), req_hdr->src);

	dprintk(info, "checking initiator %s_%s access to disks\n",
		skb->dev->name, s);

	rcu_read_lock();
	list_for_each_entry(d, &ethblk_target_disks, list) {
		ini = ethblk_target_disk_initiator_find(d, req_hdr->src, skb->dev);
		if (!ini)
			continue;
		dprintk(debug, "initiator %s_%s revealing disk %s\n",
			skb->dev->name, s, d->name);

		rep_skb = ethblk_network_new_skb(ETH_ZLEN);
		if (!rep_skb) {
			dprintk(err, "can't allocate %d bytes for discover rep_skb",
				ETH_ZLEN);
			ethblk_target_put_ini(ini);
			continue;
		}
		rep_hdr = (struct ethblk_hdr *)skb_mac_header(rep_skb);

		skb_put(rep_skb, sizeof(struct ethblk_hdr));

		ether_addr_copy(rep_hdr->src, skb->dev->dev_addr);
		ether_addr_copy(rep_hdr->dst, req_hdr->src);
		/* FIXME init hdr function? */
		rep_hdr->type = cpu_to_be16(eth_p_type);
		rep_hdr->version = ETHBLK_PROTO_VERSION;
		rep_hdr->response = 1;
		rep_hdr->status = 0;
		rep_hdr->drv_id = cpu_to_be16(d->drv_id);
		rep_hdr->tag = rep_hdr->tag;
		rep_hdr->op = req_hdr->op;
		rep_hdr->num_sectors = req_hdr->num_sectors;

		/* NOTE
		 * ugly hack... tag is IPv4 address of target
		 * comment out for disk to be discovered as L2
		 */
		rep_hdr->tag = ini->ip;

		rep_skb->dev = skb->dev;
		ethblk_network_xmit_skb(rep_skb);
		ethblk_target_put_ini(ini);
	}
	rcu_read_unlock();
}


static struct ethblk_target_disk *ethblk_target_find_disk(unsigned short drv_id)
{
	struct ethblk_target_disk *d;

	dprintk(debug, "drv_id %d\n", drv_id);
	rcu_read_lock();
	list_for_each_entry_rcu (d, &ethblk_target_disks, list) {
		if (d->drv_id == drv_id) {
			goto out;
		}
	}
	d = NULL;
out:
	if (d) {
		dprintk(debug, "found disk %px %s\n", d, d->name);
		ethblk_target_get_disk(d);
	}
	rcu_read_unlock();
	return d;
}

static int ethblk_target_start_workers(void)
{
	int ret;

	ret = ethblk_worker_create_pool(&workers,
		"ethblk-tgt", ethblk_target_cmd_worker, cpu_online_mask);
	return ret;
}

static void ethblk_target_stop_workers(void)
{
	if (workers)
		ethblk_worker_destroy_pool(workers);
}

static int ethblk_target_netdevice_event(struct notifier_block *unused,
					 unsigned long event, void *ptr)
{
	struct net_device *nd = netdev_notifier_info_to_dev(ptr);

	if (target_running && (event == NETDEV_UNREGISTER)) {
		ethblk_target_unregister_netdevice(nd);
	}

	return NOTIFY_DONE;
}

static struct notifier_block ethblk_target_netdevice_notifier = {
	.notifier_call = ethblk_target_netdevice_event
};

int __init ethblk_target_start(struct kobject *parent)
{
	int ret;

	ret = ethblk_target_start_workers();
	if (ret) {
		dprintk(err, "can't starts workers: %d\n", ret);
		goto out;
	}

	INIT_LIST_HEAD(&ethblk_target_disks);

	ret = register_netdevice_notifier(&ethblk_target_netdevice_notifier);
	if (ret) {
		dprintk(err, "can't register netdevice notifier: %d\n", ret);
		goto out;
	}

	ethblk_target_cmd_cache =
		kmem_cache_create("ethblk_tgt",
				  sizeof(struct ethblk_target_cmd), 0,
				  SLAB_HWCACHE_ALIGN, NULL);
	if (!ethblk_target_cmd_cache) {
		dprintk(err, "can't create kmem cache\n");
		ret = -ENOMEM;
		goto out;
	}
	dprintk(info, "ethblk_target_cmd_cache %px\n", ethblk_target_cmd_cache);
	ret = kobject_init_and_add(&ethblk_sysfs_target_kobj,
				   &ethblk_sysfs_target_ktype, parent, "%s",
				   "target");
	if (ret) {
		dprintk(err, "can't init root sysfs object: %d\n", ret);
		kmem_cache_destroy(ethblk_target_cmd_cache);
		ethblk_target_cmd_cache = NULL;
		goto out;
	}
	target_running = true;
	dprintk(info, "target started\n");
out:
	return ret;
}

int ethblk_target_stop(void)
{
	if (!target_running)
		return -EINVAL;
	ethblk_target_destroy_all_disks();
	kobject_del(&ethblk_sysfs_target_kobj);
	ethblk_target_stop_workers();
	if (ethblk_target_cmd_cache) {
		kmem_cache_destroy(ethblk_target_cmd_cache);
		ethblk_target_cmd_cache = NULL;
	}
	target_running = false;
	smp_wmb();
	unregister_netdevice_notifier(&ethblk_target_netdevice_notifier);
	dprintk(info, "target stopped\n");
	return 0;
}
