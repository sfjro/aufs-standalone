/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2022 Junjiro R. Okajima
 */

/*
 * sub-routines for VFS
 */

#ifndef __AUFS_VFSUB_H__
#define __AUFS_VFSUB_H__

#ifdef __KERNEL__

#include <linux/fs.h>
#include "debug.h"

/* to debug easier, do not make them inlined functions */
#define MtxMustLock(mtx)	AuDebugOn(!mutex_is_locked(mtx))
#define IMustLock(i)		AuDebugOn(!inode_is_locked(i))

int vfsub_kern_path(const char *name, unsigned int flags, struct path *path);

/* ---------------------------------------------------------------------- */

ssize_t vfsub_read_u(struct file *file, char __user *ubuf, size_t count,
		     loff_t *ppos);
ssize_t vfsub_read_k(struct file *file, void *kbuf, size_t count,
			loff_t *ppos);
ssize_t vfsub_write_u(struct file *file, const char __user *ubuf, size_t count,
		      loff_t *ppos);
ssize_t vfsub_write_k(struct file *file, void *kbuf, size_t count,
		      loff_t *ppos);

#endif /* __KERNEL__ */
#endif /* __AUFS_VFSUB_H__ */
