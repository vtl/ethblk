// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, 2020 Vitaly Mayatskikh <v.mayatskih@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/printk.h>
#include "ethblk.h"
#include "initiator.h"
#include "target.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaly Mayatskikh <v.mayatskih@gmail.com>");
MODULE_DESCRIPTION("High performance block-over-ethernet target and initiator");
MODULE_VERSION(VERSION);

int net_stat = 1;
module_param(net_stat, int, 0644);
MODULE_PARM_DESC(net_stat, "Enable network counters");

int ip_ports = 64;
module_param(ip_ports, int, 0644);
MODULE_PARM_DESC(ip_ports, "Use that many ports");

char *log_buf;

bool target_mode = false;
bool initiator_mode = false;

static struct kobject ethblk_sysfs_root_kobj;

static void ethblk_sysfs_root_release(struct kobject *kobj)
{
}

static struct kobj_type ethblk_sysfs_root_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = ethblk_sysfs_root_release,
};

static void ethblk_exit(void)
{
	int ret;

	ethblk_net_exit();
	if (target_mode)
		ret = ethblk_target_stop();
	if (initiator_mode)
		ret = ethblk_initiator_stop();
	kobject_put(&ethblk_sysfs_root_kobj);
	dprintk(info, "unloaded\n");
	if (log_buf)
		vfree(log_buf);
}

static int __init ethblk_init(void)
{
	int ret = 0;

	log_buf = vmalloc(LOG_ENTRY_SIZE * NR_CPUS);
	if (!log_buf) {
		printk(KERN_ERR "ethblk: can't allocate log buffer\n");
		goto out;
	}
	ret = kobject_init_and_add(&ethblk_sysfs_root_kobj,
				   &ethblk_sysfs_root_ktype, kernel_kobj, "%s",
				   "ethblk");
	if (ret) {
		dprintk(err, "can't init root sysfs object: %d\n", ret);
		goto out;
	}

	if (target_mode) {
		ret = ethblk_target_start(&ethblk_sysfs_root_kobj);
		if (ret) {
			dprintk(err, "Target failed to start: %d\n", ret);
			goto out;
		}
	}

	if (initiator_mode) {
		ret = ethblk_initiator_start(&ethblk_sysfs_root_kobj);
		if (ret) {
			dprintk(err, "Initiator failed to start: %d\n", ret);
			if (target_mode)
				ethblk_target_stop();
			goto out;
		}
	}

	ethblk_net_init();

	if (ret == 0)
		dprintk(info, "loaded\n");
	return ret;

out:
	if (log_buf) {
		vfree(log_buf);
		log_buf = NULL;
	}
	return ret;
}

module_init(ethblk_init);
module_exit(ethblk_exit);
module_param_named(target, target_mode, bool, 0);
MODULE_PARM_DESC(target, "Enable target mode");
module_param_named(initiator, initiator_mode, bool, 0);
MODULE_PARM_DESC(initiator, "Enable initiator mode");
