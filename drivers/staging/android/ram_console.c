/* drivers/android/ram_console.c
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/console.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/persistent_ram.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include "ram_console.h"

static struct persistent_ram_zone *ram_console_zone;
static const char *bootinfo;
static size_t bootinfo_size;

static void
ram_console_write(struct console *console, const char *s, unsigned int count)
{
	struct persistent_ram_zone *prz = console->data;
	persistent_ram_write(prz, s, count);
}

static struct console ram_console = {
	.name	= "ram",
	.write	= ram_console_write,
	.flags	= CON_PRINTBUFFER | CON_ENABLED | CON_ANYTIME,
	.index	= -1,
};

void ram_console_enable_console(int enabled)
{
	if (enabled)
		ram_console.flags |= CON_ENABLED;
	else
		ram_console.flags &= ~CON_ENABLED;
}

static int __devinit ram_console_probe(struct platform_device *pdev)
{
	struct ram_console_platform_data *pdata = pdev->dev.platform_data;
	struct persistent_ram_zone *prz;

	prz = persistent_ram_init_ringbuffer(&pdev->dev, true);
	if (IS_ERR(prz))
		return PTR_ERR(prz);


	if (pdata) {
		bootinfo = kstrdup(pdata->bootinfo, GFP_KERNEL);
		if (bootinfo)
			bootinfo_size = strlen(bootinfo);
	}

	ram_console_zone = prz;
	ram_console.data = prz;

	register_console(&ram_console);

	return 0;
}

#ifdef VENDOR_EDIT /*schedule ramconsole initailize on cpu 2 by huruihuan*/
struct ram_console_optimize_data{
	struct work_struct work;
	struct platform_device *pdev;
};
static struct ram_console_optimize_data optimize_data;

static void __devinit optimize_ramconsole_oneplus_func(struct work_struct *work)
{
	struct platform_device *ramconsole_dev = optimize_data.pdev;
	ram_console_probe(ramconsole_dev);
}

static int __devinit ram_console_probe_oneplus(struct platform_device *pdev)
{
	INIT_WORK(&(optimize_data.work), optimize_ramconsole_oneplus_func);
	optimize_data.pdev = pdev;
	schedule_work_on(cpu_is_offline(2)?0:2,&(optimize_data.work));
	return 0;
}
#endif


static struct platform_driver ram_console_driver = {
	.driver		= {
		.name	= "ram_console",
	},
#ifdef VENDOR_EDIT /*schedule ramconsole initailize on cpu 2 by huruihuan*/
	.probe = ram_console_probe_oneplus,
#else
	.probe = ram_console_probe,
#endif
};

#ifdef VENDOR_EDIT
//Zhilong.Zhang@OnlineRd.Driver, 2013/12/03, Add for ram_console device
static struct platform_device *ram_console_dev;
#endif

static int __init ram_console_module_init(void)
{

#ifndef VENDOR_EDIT
//Zhilong.Zhang@OnlineRd.Driver, 2013/12/03, Add for ram_console device
	return platform_driver_register(&ram_console_driver);
#else  /* VENDOR_EDIT */
	int ret;

	ram_console_dev = platform_device_alloc("ram_console", -1);
	if (!ram_console_dev)
		return -ENOMEM;

	ret = platform_device_add(ram_console_dev);
	if (ret != 0) {
		platform_device_put(ram_console_dev);
		return ret;
	}

	ret = platform_driver_register(&ram_console_driver);
	if (ret != 0)
		platform_device_unregister(ram_console_dev);

	return ret;
#endif  /* VENDOR_EDIT */
}

#ifndef CONFIG_PRINTK
#define dmesg_restrict	0
#endif

static ssize_t ram_console_read_old(struct file *file, char __user *buf,
				    size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;
	struct persistent_ram_zone *prz = ram_console_zone;
	size_t old_log_size = persistent_ram_old_size(prz);
	const char *old_log = persistent_ram_old(prz);
	char *str;
	int ret;

#ifndef VENDOR_EDIT
//Zhilong.Zhang@OnlineRd.Driver, 2014/01/16, Delete for solve the problem that can not read /proc/last_kmsg right.
	if (dmesg_restrict && !capable(CAP_SYSLOG))
		return -EPERM;
#endif  /* VENDOR_EDIT */

	/* Main last_kmsg log */
	if (pos < old_log_size) {
		count = min(len, (size_t)(old_log_size - pos));
		if (copy_to_user(buf, old_log + pos, count))
			return -EFAULT;
		goto out;
	}

	/* ECC correction notice */
	pos -= old_log_size;
	count = persistent_ram_ecc_string(prz, NULL, 0);
	if (pos < count) {
		str = kmalloc(count, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		persistent_ram_ecc_string(prz, str, count + 1);
		count = min(len, (size_t)(count - pos));
		ret = copy_to_user(buf, str + pos, count);
		kfree(str);
		if (ret)
			return -EFAULT;
		goto out;
	}

	/* Boot info passed through pdata */
	pos -= count;
	if (pos < bootinfo_size) {
		count = min(len, (size_t)(bootinfo_size - pos));
		if (copy_to_user(buf, bootinfo + pos, count))
			return -EFAULT;
		goto out;
	}

	/* EOF */
	return 0;

out:
	*offset += count;
	return count;
}

static const struct file_operations ram_console_file_ops = {
	.owner = THIS_MODULE,
	.read = ram_console_read_old,
};

static int __init ram_console_late_init(void)
{
	struct proc_dir_entry *entry;
	struct persistent_ram_zone *prz = ram_console_zone;

	if (!prz)
		return 0;

	if (persistent_ram_old_size(prz) == 0)
		return 0;

	entry = create_proc_entry("last_kmsg", S_IFREG | S_IRUGO, NULL);
	if (!entry) {
		printk(KERN_ERR "ram_console: failed to create proc entry\n");
		persistent_ram_free_old(prz);
		return 0;
	}

	entry->proc_fops = &ram_console_file_ops;
	entry->size = persistent_ram_old_size(prz) +
		persistent_ram_ecc_string(prz, NULL, 0) +
		bootinfo_size;

	return 0;
}

late_initcall(ram_console_late_init);
postcore_initcall(ram_console_module_init);
