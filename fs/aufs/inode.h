/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2022 Junjiro R. Okajima
 */

/*
 * inode operations
 */

#ifndef __AUFS_INODE_H__
#define __AUFS_INODE_H__

#ifdef __KERNEL__

#include <linux/fsnotify.h>
#include "rwsem.h"

struct vfsmount;

struct au_hnotify {
#ifdef CONFIG_AUFS_HNOTIFY
#ifdef CONFIG_AUFS_HFSNOTIFY
	/* never use fsnotify_add_vfsmount_mark() */
	struct fsnotify_mark		hn_mark;
#endif
	struct inode		*hn_aufs_inode;	/* no get/put */
	struct rcu_head		rcu;
#endif
} ____cacheline_aligned_in_smp;

struct au_hinode {
	struct inode		*hi_inode;
	aufs_bindex_t		hi_id;
#ifdef CONFIG_AUFS_HNOTIFY
	struct au_hnotify	*hi_notify;
#endif

	/* reference to the copied-up whiteout with get/put */
	struct dentry		*hi_whdentry;
};

/* ig_flags */
#define AuIG_HALF_REFRESHED		1
#define au_ig_ftest(flags, name)	((flags) & AuIG_##name)
#define au_ig_fset(flags, name) \
	do { (flags) |= AuIG_##name; } while (0)
#define au_ig_fclr(flags, name) \
	do { (flags) &= ~AuIG_##name; } while (0)

struct au_iigen {
	spinlock_t	ig_spin;
	__u32		ig_generation, ig_flags;
};

struct au_vdir;
struct au_iinfo {
	struct au_iigen		ii_generation;
	struct super_block	*ii_hsb1;	/* no get/put */

	struct au_rwsem		ii_rwsem;
	aufs_bindex_t		ii_btop, ii_bbot;
	__u32			ii_higen;
	struct au_hinode	*ii_hinode;
	struct au_vdir		*ii_vdir;
};

struct au_icntnr {
	struct au_iinfo		iinfo;
	struct inode		vfs_inode;
	struct hlist_bl_node	plink;
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;

/* au_pin flags */
#define AuPin_DI_LOCKED		1
#define AuPin_MNT_WRITE		(1 << 1)
#define au_ftest_pin(flags, name)	((flags) & AuPin_##name)
#define au_fset_pin(flags, name) \
	do { (flags) |= AuPin_##name; } while (0)
#define au_fclr_pin(flags, name) \
	do { (flags) &= ~AuPin_##name; } while (0)

struct au_pin {
	/* input */
	struct dentry *dentry;
	unsigned int udba;
	unsigned char lsc_di, lsc_hi, flags;
	aufs_bindex_t bindex;

	/* output */
	struct dentry *parent;
	struct au_hinode *hdir;
	struct vfsmount *h_mnt;

	/* temporary unlock/relock for copyup */
	struct dentry *h_dentry, *h_parent;
	struct au_branch *br;
	struct task_struct *task;
};

void au_pin_hdir_unlock(struct au_pin *p);
int au_pin_hdir_lock(struct au_pin *p);
int au_pin_hdir_relock(struct au_pin *p);
void au_pin_hdir_acquire_nest(struct au_pin *p);
void au_pin_hdir_release(struct au_pin *p);

/* ---------------------------------------------------------------------- */

static inline struct au_iinfo *au_ii(struct inode *inode)
{
	BUG_ON(is_bad_inode(inode));
	return &(container_of(inode, struct au_icntnr, vfs_inode)->iinfo);
}

/* ---------------------------------------------------------------------- */

/* inode.c */
struct inode *au_igrab(struct inode *inode);
int au_refresh_hinode_self(struct inode *inode);
int au_refresh_hinode(struct inode *inode, struct dentry *dentry);
int au_ino(struct super_block *sb, aufs_bindex_t bindex, ino_t h_ino,
	   unsigned int d_type, ino_t *ino);
struct inode *au_new_inode(struct dentry *dentry, int must_new);
int au_test_ro(struct super_block *sb, aufs_bindex_t bindex,
	       struct inode *inode);
int au_test_h_perm(struct user_namespace *h_userns, struct inode *h_inode,
		   int mask);
int au_test_h_perm_sio(struct user_namespace *h_userns, struct inode *h_inode,
		       int mask);

/* i_op.c */
enum {
	AuIop_SYMLINK,
	AuIop_DIR,
	AuIop_OTHER,
	AuIop_Last
};
extern struct inode_operations aufs_iop[AuIop_Last]; /* not const */

struct dentry *au_pinned_h_parent(struct au_pin *pin);
void au_pin_init(struct au_pin *pin, struct dentry *dentry,
		 aufs_bindex_t bindex, int lsc_di, int lsc_hi,
		 unsigned int udba, unsigned char flags);
int au_pin(struct au_pin *pin, struct dentry *dentry, aufs_bindex_t bindex,
	   unsigned int udba, unsigned char flags) __must_check;
int au_do_pin(struct au_pin *pin) __must_check;
void au_unpin(struct au_pin *pin);

/* iinfo.c */
struct inode *au_h_iptr(struct inode *inode, aufs_bindex_t bindex);
void au_hiput(struct au_hinode *hinode);
void au_set_hi_wh(struct inode *inode, aufs_bindex_t bindex,
		  struct dentry *h_wh);
unsigned int au_hi_flags(struct inode *inode, int isdir);

/* hinode flags */
#define AuHi_XINO	1
#define AuHi_HNOTIFY	(1 << 1)
#define au_ftest_hi(flags, name)	((flags) & AuHi_##name)
#define au_fset_hi(flags, name) \
	do { (flags) |= AuHi_##name; } while (0)
#define au_fclr_hi(flags, name) \
	do { (flags) &= ~AuHi_##name; } while (0)

#ifndef CONFIG_AUFS_HNOTIFY
#undef AuHi_HNOTIFY
#define AuHi_HNOTIFY	0
#endif

void au_set_h_iptr(struct inode *inode, aufs_bindex_t bindex,
		   struct inode *h_inode, unsigned int flags);

void au_update_iigen(struct inode *inode, int half);
void au_update_ibrange(struct inode *inode, int do_put_zero);

void au_icntnr_init_once(void *_c);
void au_hinode_init(struct au_hinode *hinode);
int au_iinfo_init(struct inode *inode);
void au_iinfo_fin(struct inode *inode);
int au_hinode_realloc(struct au_iinfo *iinfo, int nbr, int may_shrink);

#ifdef CONFIG_PROC_FS
/* plink.c */
int au_plink_maint(struct super_block *sb, int flags);
struct au_sbinfo;
void au_plink_maint_leave(struct au_sbinfo *sbinfo);
int au_plink_maint_enter(struct super_block *sb);
#ifdef CONFIG_AUFS_DEBUG
void au_plink_list(struct super_block *sb);
#else
AuStubVoid(au_plink_list, struct super_block *sb)
#endif
int au_plink_test(struct inode *inode);
struct dentry *au_plink_lkup(struct inode *inode, aufs_bindex_t bindex);
void au_plink_append(struct inode *inode, aufs_bindex_t bindex,
		     struct dentry *h_dentry);
void au_plink_put(struct super_block *sb, int verbose);
void au_plink_clean(struct super_block *sb, int verbose);
#else
AuStubInt0(au_plink_maint, struct super_block *sb, int flags);
AuStubVoid(au_plink_maint_leave, struct au_sbinfo *sbinfo);
AuStubInt0(au_plink_maint_enter, struct super_block *sb);
AuStubVoid(au_plink_list, struct super_block *sb);
AuStubInt0(au_plink_test, struct inode *inode);
AuStub(struct dentry *, au_plink_lkup, return NULL,
       struct inode *inode, aufs_bindex_t bindex);
AuStubVoid(au_plink_append, struct inode *inode, aufs_bindex_t bindex,
	   struct dentry *h_dentry);
AuStubVoid(au_plink_put, struct super_block *sb, int verbose);
AuStubVoid(au_plink_clean, struct super_block *sb, int verbose);
#endif /* CONFIG_PROC_FS */

/* ---------------------------------------------------------------------- */

/* lock subclass for iinfo */
enum {
	AuLsc_II_CHILD,		/* child first */
	AuLsc_II_CHILD2,	/* rename(2), link(2), and cpup at hnotify */
	AuLsc_II_CHILD3,	/* copyup dirs */
	AuLsc_II_PARENT,	/* see AuLsc_I_PARENT in vfsub.h */
	AuLsc_II_PARENT2,
	AuLsc_II_PARENT3,	/* copyup dirs */
	AuLsc_II_NEW_CHILD
};

/*
 * ii_read_lock_child, ii_write_lock_child,
 * ii_read_lock_child2, ii_write_lock_child2,
 * ii_read_lock_child3, ii_write_lock_child3,
 * ii_read_lock_parent, ii_write_lock_parent,
 * ii_read_lock_parent2, ii_write_lock_parent2,
 * ii_read_lock_parent3, ii_write_lock_parent3,
 * ii_read_lock_new_child, ii_write_lock_new_child,
 */
#define AuReadLockFunc(name, lsc) \
static inline void ii_read_lock_##name(struct inode *i) \
{ \
	au_rw_read_lock_nested(&au_ii(i)->ii_rwsem, AuLsc_II_##lsc); \
}

#define AuWriteLockFunc(name, lsc) \
static inline void ii_write_lock_##name(struct inode *i) \
{ \
	au_rw_write_lock_nested(&au_ii(i)->ii_rwsem, AuLsc_II_##lsc); \
}

#define AuRWLockFuncs(name, lsc) \
	AuReadLockFunc(name, lsc) \
	AuWriteLockFunc(name, lsc)

AuRWLockFuncs(child, CHILD);
AuRWLockFuncs(child2, CHILD2);
AuRWLockFuncs(child3, CHILD3);
AuRWLockFuncs(parent, PARENT);
AuRWLockFuncs(parent2, PARENT2);
AuRWLockFuncs(parent3, PARENT3);
AuRWLockFuncs(new_child, NEW_CHILD);

#undef AuReadLockFunc
#undef AuWriteLockFunc
#undef AuRWLockFuncs

#define ii_read_unlock(i)	au_rw_read_unlock(&au_ii(i)->ii_rwsem)
#define ii_write_unlock(i)	au_rw_write_unlock(&au_ii(i)->ii_rwsem)
#define ii_downgrade_lock(i)	au_rw_dgrade_lock(&au_ii(i)->ii_rwsem)

#define IiMustNoWaiters(i)	AuRwMustNoWaiters(&au_ii(i)->ii_rwsem)
#define IiMustAnyLock(i)	AuRwMustAnyLock(&au_ii(i)->ii_rwsem)
#define IiMustWriteLock(i)	AuRwMustWriteLock(&au_ii(i)->ii_rwsem)

/* ---------------------------------------------------------------------- */

static inline void au_icntnr_init(struct au_icntnr *c)
{
#ifdef CONFIG_AUFS_DEBUG
	c->vfs_inode.i_mode = 0;
#endif
}

static inline unsigned int au_iigen(struct inode *inode, unsigned int *igflags)
{
	unsigned int gen;
	struct au_iinfo *iinfo;
	struct au_iigen *iigen;

	iinfo = au_ii(inode);
	iigen = &iinfo->ii_generation;
	spin_lock(&iigen->ig_spin);
	if (igflags)
		*igflags = iigen->ig_flags;
	gen = iigen->ig_generation;
	spin_unlock(&iigen->ig_spin);

	return gen;
}

/* tiny test for inode number */
/* tmpfs generation is too rough */
static inline int au_test_higen(struct inode *inode, struct inode *h_inode)
{
	struct au_iinfo *iinfo;

	iinfo = au_ii(inode);
	AuRwMustAnyLock(&iinfo->ii_rwsem);
	return !(iinfo->ii_hsb1 == h_inode->i_sb
		 && iinfo->ii_higen == h_inode->i_generation);
}

static inline void au_iigen_dec(struct inode *inode)
{
	struct au_iinfo *iinfo;
	struct au_iigen *iigen;

	iinfo = au_ii(inode);
	iigen = &iinfo->ii_generation;
	spin_lock(&iigen->ig_spin);
	iigen->ig_generation--;
	spin_unlock(&iigen->ig_spin);
}

static inline int au_iigen_test(struct inode *inode, unsigned int sigen)
{
	int err;

	err = 0;
	if (unlikely(inode && au_iigen(inode, NULL) != sigen))
		err = -EIO;

	return err;
}

/* ---------------------------------------------------------------------- */

static inline struct au_hinode *au_hinode(struct au_iinfo *iinfo,
					  aufs_bindex_t bindex)
{
	return iinfo->ii_hinode + bindex;
}

static inline int au_is_bad_inode(struct inode *inode)
{
	return !!(is_bad_inode(inode) || !au_hinode(au_ii(inode), 0));
}

static inline aufs_bindex_t au_ii_br_id(struct inode *inode,
					aufs_bindex_t bindex)
{
	IiMustAnyLock(inode);
	return au_hinode(au_ii(inode), bindex)->hi_id;
}

static inline aufs_bindex_t au_ibtop(struct inode *inode)
{
	IiMustAnyLock(inode);
	return au_ii(inode)->ii_btop;
}

static inline aufs_bindex_t au_ibbot(struct inode *inode)
{
	IiMustAnyLock(inode);
	return au_ii(inode)->ii_bbot;
}

static inline struct au_vdir *au_ivdir(struct inode *inode)
{
	IiMustAnyLock(inode);
	return au_ii(inode)->ii_vdir;
}

static inline struct dentry *au_hi_wh(struct inode *inode, aufs_bindex_t bindex)
{
	IiMustAnyLock(inode);
	return au_hinode(au_ii(inode), bindex)->hi_whdentry;
}

static inline void au_set_ibtop(struct inode *inode, aufs_bindex_t bindex)
{
	IiMustWriteLock(inode);
	au_ii(inode)->ii_btop = bindex;
}

static inline void au_set_ibbot(struct inode *inode, aufs_bindex_t bindex)
{
	IiMustWriteLock(inode);
	au_ii(inode)->ii_bbot = bindex;
}

static inline void au_set_ivdir(struct inode *inode, struct au_vdir *vdir)
{
	IiMustWriteLock(inode);
	au_ii(inode)->ii_vdir = vdir;
}

static inline struct au_hinode *au_hi(struct inode *inode, aufs_bindex_t bindex)
{
	IiMustAnyLock(inode);
	return au_hinode(au_ii(inode), bindex);
}

/* ---------------------------------------------------------------------- */

static inline struct dentry *au_pinned_parent(struct au_pin *pin)
{
	if (pin)
		return pin->parent;
	return NULL;
}

static inline struct inode *au_pinned_h_dir(struct au_pin *pin)
{
	if (pin && pin->hdir)
		return pin->hdir->hi_inode;
	return NULL;
}

static inline struct au_hinode *au_pinned_hdir(struct au_pin *pin)
{
	if (pin)
		return pin->hdir;
	return NULL;
}

static inline void au_pin_set_dentry(struct au_pin *pin, struct dentry *dentry)
{
	if (pin)
		pin->dentry = dentry;
}

static inline void au_pin_set_parent_lflag(struct au_pin *pin,
					   unsigned char lflag)
{
	if (pin) {
		if (lflag)
			au_fset_pin(pin->flags, DI_LOCKED);
		else
			au_fclr_pin(pin->flags, DI_LOCKED);
	}
}

#if 0 /* reserved */
static inline void au_pin_set_parent(struct au_pin *pin, struct dentry *parent)
{
	if (pin) {
		dput(pin->parent);
		pin->parent = dget(parent);
	}
}
#endif

/* ---------------------------------------------------------------------- */

struct au_branch;
#ifdef CONFIG_AUFS_HNOTIFY
struct au_hnotify_op {
	void (*ctl)(struct au_hinode *hinode, int do_set);
	int (*alloc)(struct au_hinode *hinode);

	/*
	 * if it returns true, the caller should free hinode->hi_notify,
	 * otherwise ->free() frees it.
	 */
	int (*free)(struct au_hinode *hinode,
		    struct au_hnotify *hn) __must_check;

	void (*fin)(void);
	int (*init)(void);

	int (*reset_br)(unsigned int udba, struct au_branch *br, int perm);
	void (*fin_br)(struct au_branch *br);
	int (*init_br)(struct au_branch *br, int perm);
};

/* hnotify.c */
int au_hn_alloc(struct au_hinode *hinode, struct inode *inode);
void au_hn_free(struct au_hinode *hinode);
void au_hn_ctl(struct au_hinode *hinode, int do_set);
void au_hn_reset(struct inode *inode, unsigned int flags);
int au_hnotify(struct inode *h_dir, struct au_hnotify *hnotify, u32 mask,
	       const struct qstr *h_child_qstr, struct inode *h_child_inode);
int au_hnotify_reset_br(unsigned int udba, struct au_branch *br, int perm);
int au_hnotify_init_br(struct au_branch *br, int perm);
void au_hnotify_fin_br(struct au_branch *br);
int __init au_hnotify_init(void);
void au_hnotify_fin(void);

/* hfsnotify.c */
extern const struct au_hnotify_op au_hnotify_op;

static inline
void au_hn_init(struct au_hinode *hinode)
{
	hinode->hi_notify = NULL;
}

static inline struct au_hnotify *au_hn(struct au_hinode *hinode)
{
	return hinode->hi_notify;
}

#else
AuStub(int, au_hn_alloc, return -EOPNOTSUPP,
       struct au_hinode *hinode __maybe_unused,
       struct inode *inode __maybe_unused)
AuStub(struct au_hnotify *, au_hn, return NULL, struct au_hinode *hinode)
AuStubVoid(au_hn_free, struct au_hinode *hinode __maybe_unused)
AuStubVoid(au_hn_ctl, struct au_hinode *hinode __maybe_unused,
	   int do_set __maybe_unused)
AuStubVoid(au_hn_reset, struct inode *inode __maybe_unused,
	   unsigned int flags __maybe_unused)
AuStubInt0(au_hnotify_reset_br, unsigned int udba __maybe_unused,
	   struct au_branch *br __maybe_unused,
	   int perm __maybe_unused)
AuStubInt0(au_hnotify_init_br, struct au_branch *br __maybe_unused,
	   int perm __maybe_unused)
AuStubVoid(au_hnotify_fin_br, struct au_branch *br __maybe_unused)
AuStubInt0(__init au_hnotify_init, void)
AuStubVoid(au_hnotify_fin, void)
AuStubVoid(au_hn_init, struct au_hinode *hinode __maybe_unused)
#endif /* CONFIG_AUFS_HNOTIFY */

static inline void au_hn_suspend(struct au_hinode *hdir)
{
	au_hn_ctl(hdir, /*do_set*/0);
}

static inline void au_hn_resume(struct au_hinode *hdir)
{
	au_hn_ctl(hdir, /*do_set*/1);
}

static inline void au_hn_inode_lock(struct au_hinode *hdir)
{
	inode_lock(hdir->hi_inode);
	au_hn_suspend(hdir);
}

static inline void au_hn_inode_lock_nested(struct au_hinode *hdir,
					  unsigned int sc __maybe_unused)
{
	inode_lock_nested(hdir->hi_inode, sc);
	au_hn_suspend(hdir);
}

#if 0 /* unused */
#include "vfsub.h"
static inline void au_hn_inode_lock_shared_nested(struct au_hinode *hdir,
						  unsigned int sc)
{
	inode_lock_shared_nested(hdir->hi_inode, sc);
	au_hn_suspend(hdir);
}
#endif

static inline void au_hn_inode_unlock(struct au_hinode *hdir)
{
	au_hn_resume(hdir);
	inode_unlock(hdir->hi_inode);
}

#endif /* __KERNEL__ */
#endif /* __AUFS_INODE_H__ */
