/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2022 Junjiro R. Okajima
 */

/*
 * file operations
 */

#ifndef __AUFS_FILE_H__
#define __AUFS_FILE_H__

#ifdef __KERNEL__

#include <linux/file.h>
#include <linux/fs.h>
#include "rwsem.h"

struct au_branch;
struct au_hfile {
	struct file		*hf_file;
	struct au_branch	*hf_br;
};

struct au_vdir;
struct au_fidir {
	aufs_bindex_t		fd_bbot;
	aufs_bindex_t		fd_nent;
	struct au_vdir		*fd_vdir_cache;
	struct au_hfile		fd_hfile[];
};

static inline int au_fidir_sz(int nent)
{
	AuDebugOn(nent < 0);
	return sizeof(struct au_fidir) + sizeof(struct au_hfile) * nent;
}

struct au_finfo {
	atomic_t		fi_generation;

	struct au_rwsem		fi_rwsem;
	aufs_bindex_t		fi_btop;

	/* do not union them */
	struct au_hfile		fi_htop;	/* for non-dir */
	struct au_fidir		*fi_hdir;	/* for dir only */
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;

/* ---------------------------------------------------------------------- */

/* file.c */
extern const struct address_space_operations aufs_aop;
unsigned int au_file_roflags(unsigned int flags);
struct file *au_h_open(struct dentry *dentry, aufs_bindex_t bindex, int flags,
		       struct file *file);

/* finfo.c */
void au_hfput(struct au_hfile *hf, int execed);
void au_set_h_fptr(struct file *file, aufs_bindex_t bindex,
		   struct file *h_file);

void au_update_figen(struct file *file);
struct au_fidir *au_fidir_alloc(struct super_block *sb);
int au_fidir_realloc(struct au_finfo *finfo, int nbr, int may_shrink);

void au_fi_init_once(void *_fi);
void au_finfo_fin(struct file *file);
int au_finfo_init(struct file *file, struct au_fidir *fidir);

/* ---------------------------------------------------------------------- */

static inline struct au_finfo *au_fi(struct file *file)
{
	return file->private_data;
}

/* ---------------------------------------------------------------------- */

#define fi_read_lock(f)	au_rw_read_lock(&au_fi(f)->fi_rwsem)
#define fi_write_lock(f)	au_rw_write_lock(&au_fi(f)->fi_rwsem)
#define fi_read_trylock(f)	au_rw_read_trylock(&au_fi(f)->fi_rwsem)
#define fi_write_trylock(f)	au_rw_write_trylock(&au_fi(f)->fi_rwsem)
/*
#define fi_read_trylock_nested(f) \
	au_rw_read_trylock_nested(&au_fi(f)->fi_rwsem)
#define fi_write_trylock_nested(f) \
	au_rw_write_trylock_nested(&au_fi(f)->fi_rwsem)
*/

#define fi_read_unlock(f)	au_rw_read_unlock(&au_fi(f)->fi_rwsem)
#define fi_write_unlock(f)	au_rw_write_unlock(&au_fi(f)->fi_rwsem)
#define fi_downgrade_lock(f)	au_rw_dgrade_lock(&au_fi(f)->fi_rwsem)

#define FiMustNoWaiters(f)	AuRwMustNoWaiters(&au_fi(f)->fi_rwsem)
#define FiMustAnyLock(f)	AuRwMustAnyLock(&au_fi(f)->fi_rwsem)
#define FiMustWriteLock(f)	AuRwMustWriteLock(&au_fi(f)->fi_rwsem)

/* ---------------------------------------------------------------------- */

/* todo: hard/soft set? */
static inline aufs_bindex_t au_fbtop(struct file *file)
{
	FiMustAnyLock(file);
	return au_fi(file)->fi_btop;
}

static inline aufs_bindex_t au_fbbot_dir(struct file *file)
{
	FiMustAnyLock(file);
	AuDebugOn(!au_fi(file)->fi_hdir);
	return au_fi(file)->fi_hdir->fd_bbot;
}

static inline struct au_vdir *au_fvdir_cache(struct file *file)
{
	FiMustAnyLock(file);
	AuDebugOn(!au_fi(file)->fi_hdir);
	return au_fi(file)->fi_hdir->fd_vdir_cache;
}

static inline void au_set_fbtop(struct file *file, aufs_bindex_t bindex)
{
	FiMustWriteLock(file);
	au_fi(file)->fi_btop = bindex;
}

static inline void au_set_fbbot_dir(struct file *file, aufs_bindex_t bindex)
{
	FiMustWriteLock(file);
	AuDebugOn(!au_fi(file)->fi_hdir);
	au_fi(file)->fi_hdir->fd_bbot = bindex;
}

static inline void au_set_fvdir_cache(struct file *file,
				      struct au_vdir *vdir_cache)
{
	FiMustWriteLock(file);
	AuDebugOn(!au_fi(file)->fi_hdir);
	au_fi(file)->fi_hdir->fd_vdir_cache = vdir_cache;
}

static inline struct file *au_hf_top(struct file *file)
{
	FiMustAnyLock(file);
	AuDebugOn(au_fi(file)->fi_hdir);
	return au_fi(file)->fi_htop.hf_file;
}

static inline struct file *au_hf_dir(struct file *file, aufs_bindex_t bindex)
{
	FiMustAnyLock(file);
	AuDebugOn(!au_fi(file)->fi_hdir);
	return au_fi(file)->fi_hdir->fd_hfile[0 + bindex].hf_file;
}

/* todo: memory barrier? */
static inline unsigned int au_figen(struct file *f)
{
	return atomic_read(&au_fi(f)->fi_generation);
}

#endif /* __KERNEL__ */
#endif /* __AUFS_FILE_H__ */
