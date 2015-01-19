/* drivers/misc/uid_stat.c
 *
 * Copyright (C) 2008 - 2009 Google, Inc.
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

#include <asm/atomic.h>

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/uid_stat.h>
#include <net/activity_stats.h>

#ifdef CONFIG_VENDOR_EDIT
/* wenxian.zhen@Onlinerd.Driver, 2014/05/06  Add for stactist the data both receive and send  of the progress  */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/splice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/uid_stat.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/netdma.h>
#include <net/sock.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>



#include <linux/fs.h>
static DEFINE_SPINLOCK(uid_lock);
static LIST_HEAD(uid_list);
static struct proc_dir_entry *parent;

struct uid_stat {
	struct list_head link;
	uid_t uid;
	atomic_t tcp_rcv;
	atomic_t tcp_snd;
};
static DEFINE_SPINLOCK(pid_lock);
static LIST_HEAD(pid_list);
static struct proc_dir_entry *pid_parent;

struct pid_stat {
	struct list_head link;
	pid_t pid;
	atomic_t tcp_rcv;
	atomic_t tcp_snd;
};
#endif /*CONFIG_VENDOR_EDIT*/
static struct uid_stat *find_uid_stat(uid_t uid) {
	unsigned long flags;
	struct uid_stat *entry;

	spin_lock_irqsave(&uid_lock, flags);
	list_for_each_entry(entry, &uid_list, link) {
		if (entry->uid == uid) {
			spin_unlock_irqrestore(&uid_lock, flags);
			return entry;
		}
	}
	spin_unlock_irqrestore(&uid_lock, flags);
	return NULL;
}

static int tcp_snd_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	int len;
	unsigned int bytes;
	char *p = page;
	struct uid_stat *uid_entry = (struct uid_stat *) data;
	if (!data)
		return 0;

	bytes = (unsigned int) (atomic_read(&uid_entry->tcp_snd) + INT_MIN);
	p += sprintf(p, "%u\n", bytes);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

static int tcp_rcv_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	int len;
	unsigned int bytes;
	char *p = page;
	struct uid_stat *uid_entry = (struct uid_stat *) data;
	if (!data)
		return 0;

	bytes = (unsigned int) (atomic_read(&uid_entry->tcp_rcv) + INT_MIN);
	p += sprintf(p, "%u\n", bytes);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

/* Create a new entry for tracking the specified uid. */
static struct uid_stat *create_stat(uid_t uid) {
	unsigned long flags;
	char uid_s[32];
	struct uid_stat *new_uid;
	struct proc_dir_entry *entry;

	/* Create the uid stat struct and append it to the list. */
	if ((new_uid = kmalloc(sizeof(struct uid_stat), GFP_KERNEL)) == NULL)
		return NULL;

	new_uid->uid = uid;
	/* Counters start at INT_MIN, so we can track 4GB of network traffic. */
	atomic_set(&new_uid->tcp_rcv, INT_MIN);
	atomic_set(&new_uid->tcp_snd, INT_MIN);

	spin_lock_irqsave(&uid_lock, flags);
	list_add_tail(&new_uid->link, &uid_list);
	spin_unlock_irqrestore(&uid_lock, flags);

	sprintf(uid_s, "%d", uid);
	entry = proc_mkdir(uid_s, parent);

	/* Keep reference to uid_stat so we know what uid to read stats from. */
	create_proc_read_entry("tcp_snd", S_IRUGO, entry , tcp_snd_read_proc,
		(void *) new_uid);

	create_proc_read_entry("tcp_rcv", S_IRUGO, entry, tcp_rcv_read_proc,
		(void *) new_uid);

	return new_uid;
}

int uid_stat_tcp_snd(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = find_uid_stat(uid)) == NULL &&
		((entry = create_stat(uid)) == NULL)) {
			return -1;
	}
	atomic_add(size, &entry->tcp_snd);
	return 0;
}

int uid_stat_tcp_rcv(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = find_uid_stat(uid)) == NULL &&
		((entry = create_stat(uid)) == NULL)) {
			return -1;
	}
	atomic_add(size, &entry->tcp_rcv);
	return 0;
}

static int __init uid_stat_init(void)
{
	parent = proc_mkdir("uid_stat", NULL);
	if (!parent) {
		pr_err("uid_stat: failed to create proc entry\n");
		return -1;
	}
	return 0;
}
#ifdef CONFIG_VENDOR_EDIT
/* wenxian.zhen@Onlinerd.Driver, 2014/05/06  Add for stactist the data both receive and send  of the progress  */
static struct pid_stat *find_pid_stat(pid_t pid) {
	unsigned long flags;
	struct pid_stat *entry;

	spin_lock_irqsave(&pid_lock, flags);
	list_for_each_entry(entry, &pid_list, link) {
		if (entry->pid == pid) {
			spin_unlock_irqrestore(&pid_lock, flags);
			return entry;
		}
	}
	spin_unlock_irqrestore(&pid_lock, flags);
	return NULL;
}

static int tcp_snd_read_proc_pid(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	int len;
	unsigned int bytes;
	char *p = page;
	struct uid_stat *pid_entry = (struct uid_stat *) data;
	if (!data)
		return 0;

	bytes = (unsigned int) (atomic_read(&pid_entry->tcp_snd) + INT_MIN);
	p += sprintf(p, "%u\n", bytes);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

static int tcp_rcv_read_proc_pid(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	int len;
	unsigned int bytes;
	char *p = page;
	struct pid_stat *pid_entry = (struct pid_stat *) data;
	if (!data)
		return 0;

	bytes = (unsigned int) (atomic_read(&pid_entry->tcp_rcv) + INT_MIN);
	p += sprintf(p, "%u\n", bytes);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

/* Create a new entry for tracking the specified uid. */
static struct pid_stat *create_stat_pid(uid_t pid) {
	unsigned long flags;
	//zwxchar pid_s[32];
	char pid_s[500];
	char buf[500];
		loff_t pos;
	mm_segment_t fs;
	struct pid_stat *new_pid;
	struct proc_dir_entry *entry;
	
	struct file *fp;


	/* Create the uid stat struct and append it to the list. */
	if ((new_pid = kmalloc(sizeof(struct pid_stat), GFP_KERNEL)) == NULL)
		return NULL;

	new_pid->pid = pid;
	/* Counters start at INT_MIN, so we can track 4GB of network traffic. */
	atomic_set(&new_pid->tcp_rcv, INT_MIN);
	atomic_set(&new_pid->tcp_snd, INT_MIN);

	spin_lock_irqsave(&pid_lock, flags);
	list_add_tail(&new_pid->link, &pid_list);
	spin_unlock_irqrestore(&pid_lock, flags);

	sprintf(pid_s, "%d", pid);
	entry = proc_mkdir(pid_s, pid_parent);

	/* Keep reference to uid_stat so we know what uid to read stats from. */
	create_proc_read_entry("tcp_snd", S_IRUGO, entry , tcp_snd_read_proc_pid,
		(void *) new_pid);

	create_proc_read_entry("tcp_rcv", S_IRUGO, entry, tcp_rcv_read_proc_pid,
		(void *) new_pid);
	

	sprintf(pid_s, "/proc/%d/cmdline", pid);
 	//printk("zwx-----%s\n",pid_s);
	fp =filp_open(pid_s,O_RDONLY,0644);
	if (IS_ERR(fp)){ 
      printk("open file error---/n");
       return NULL;
    } 
	pos =0;
	fs=get_fs();	
	set_fs(KERNEL_DS);	
    vfs_read(fp,buf, sizeof(buf), &pos);
    printk("read: %s/n",buf);
	set_fs(fs);	
    filp_close(fp,NULL);
		create_proc_read_entry(buf, S_IRUGO, entry, NULL,
			(void *) new_pid);

	return new_pid;
}

int pid_stat_tcp_snd(pid_t pid, int size) {
	struct pid_stat *entry;
	activity_stats_update();
	if ((entry = find_pid_stat(pid)) == NULL &&
		((entry = create_stat_pid(pid)) == NULL)) {
			return -1;
	}
	atomic_add(size, &entry->tcp_snd);
	return 0;
}

int pid_stat_tcp_rcv(pid_t pid, int size) {
	struct pid_stat *entry;
	activity_stats_update();
	if ((entry = find_pid_stat(pid)) == NULL &&
		((entry = create_stat_pid(pid)) == NULL)) {
			return -1;
	}
	atomic_add(size, &entry->tcp_rcv);
	return 0;
}

static int __init pid_stat_init(void)
{
	pid_parent = proc_mkdir("pid_stat", NULL);
	if (!pid_parent) {
		pr_err("pid_stat: failed to create proc entry\n");
		return -1;
	}
	return 0;
}

__initcall(pid_stat_init);

#endif /*CONFIG_VENDOR_EDIT*/
__initcall(uid_stat_init);
