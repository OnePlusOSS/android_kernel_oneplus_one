/* include/linux/uid_stat.h
 *
 * Copyright (C) 2008-2009 Google, Inc.
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

#ifndef __uid_stat_h
#define __uid_stat_h

/* Contains definitions for resource tracking per uid. */

#ifdef CONFIG_UID_STAT
int uid_stat_tcp_snd(uid_t uid, int size);
int uid_stat_tcp_rcv(uid_t uid, int size);
#ifdef CONFIG_VENDOR_EDIT
/* wenxian.zhen@Onlinerd.Driver, 2014/05/06  Add for stactist the data both receive and send  of the progress  */
int pid_stat_tcp_snd(pid_t pid, int size);
int pid_stat_tcp_rcv(pid_t pid, int size);
#endif /*CONFIG_VENDOR_EDIT*/
#else
#define uid_stat_tcp_snd(uid, size) do {} while (0);
#define uid_stat_tcp_rcv(uid, size) do {} while (0);
#ifdef CONFIG_VENDOR_EDIT
/* wenxian.zhen@Onlinerd.Driver, 2014/05/06  Add for stactist the data both receive and send  of the progress  */
#define pid_stat_tcp_snd(pid_t pid, int size) do {} while (0);
#define pid_stat_tcp_rcv(pid_t pid, int size) do {} while (0);
#endif /*CONFIG_VENDOR_EDIT*/
#endif

#endif /* _LINUX_UID_STAT_H */
