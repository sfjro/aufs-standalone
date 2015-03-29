// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * handling file/dir, and address_space operation
 */

#ifdef CONFIG_AUFS_DEBUG
#include <linux/migrate.h>
#endif
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include "aufs.h"

/* drop flags for writing */
unsigned int au_file_roflags(unsigned int flags)
{
	flags &= ~(O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC);
	flags |= O_RDONLY | O_NOATIME;
	return flags;
}

/* common functions to regular file and dir */
struct file *au_h_open(struct dentry *dentry, aufs_bindex_t bindex, int flags,
		       struct file *file)
{
	struct file *h_file;
	struct dentry *h_dentry;
	struct inode *h_inode;
	struct super_block *sb;
	struct au_branch *br;
	struct path h_path;
	int err;

	/* a race condition can happen between open and unlink/rmdir */
	h_file = ERR_PTR(-ENOENT);
	h_dentry = au_h_dptr(dentry, bindex);
	if (au_test_nfsd() && (!h_dentry || d_is_negative(h_dentry)))
		goto out;
	h_inode = d_inode(h_dentry);
	spin_lock(&h_dentry->d_lock);
	err = (!d_unhashed(dentry) && d_unlinked(h_dentry))
		/* || !d_inode(dentry)->i_nlink */
		;
	spin_unlock(&h_dentry->d_lock);
	if (unlikely(err))
		goto out;

	sb = dentry->d_sb;
	br = au_sbr(sb, bindex);
	err = au_br_test_oflag(flags, br);
	h_file = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	/* drop flags for writing */
	if (au_test_ro(sb, bindex, d_inode(dentry)))
		flags = au_file_roflags(flags);
	flags &= ~O_CREAT;
	au_lcnt_inc(&br->br_nfiles);
	h_path.dentry = h_dentry;
	h_path.mnt = au_br_mnt(br);
	h_file = vfsub_dentry_open(&h_path, flags);
	if (IS_ERR(h_file))
		goto out_br;

	if (flags & __FMODE_EXEC) {
		err = deny_write_access(h_file);
		if (unlikely(err)) {
			fput(h_file);
			h_file = ERR_PTR(err);
			goto out_br;
		}
	}
	fsnotify_open(h_file);
	goto out; /* success */

out_br:
	au_lcnt_dec(&br->br_nfiles);
out:
	return h_file;
}

/* ---------------------------------------------------------------------- */

/* cf. aufs_nopage() */
/* for madvise(2) */
static int aufs_readpage(struct file *file __maybe_unused, struct page *page)
{
	unlock_page(page);
	return 0;
}

/* it will never be called, but necessary to support O_DIRECT */
static ssize_t aufs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{ BUG(); return 0; }

/* they will never be called. */
#ifdef CONFIG_AUFS_DEBUG
static int aufs_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{ AuUnsupport(); return 0; }
static int aufs_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{ AuUnsupport(); return 0; }
static int aufs_writepage(struct page *page, struct writeback_control *wbc)
{ AuUnsupport(); return 0; }

static int aufs_set_page_dirty(struct page *page)
{ AuUnsupport(); return 0; }
static void aufs_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{ AuUnsupport(); }
static int aufs_releasepage(struct page *page, gfp_t gfp)
{ AuUnsupport(); return 0; }
#if 0 /* called by memory compaction regardless file */
static int aufs_migratepage(struct address_space *mapping, struct page *newpage,
			    struct page *page, enum migrate_mode mode)
{ AuUnsupport(); return 0; }
#endif
static bool aufs_isolate_page(struct page *page, isolate_mode_t mode)
{ AuUnsupport(); return true; }
static void aufs_putback_page(struct page *page)
{ AuUnsupport(); }
static int aufs_launder_page(struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_is_partially_uptodate(struct page *page,
				      unsigned long from,
				      unsigned long count)
{ AuUnsupport(); return 0; }
static void aufs_is_dirty_writeback(struct page *page, bool *dirty,
				    bool *writeback)
{ AuUnsupport(); }
static int aufs_error_remove_page(struct address_space *mapping,
				  struct page *page)
{ AuUnsupport(); return 0; }
static int aufs_swap_activate(struct swap_info_struct *sis, struct file *file,
			      sector_t *span)
{ AuUnsupport(); return 0; }
static void aufs_swap_deactivate(struct file *file)
{ AuUnsupport(); }
#endif /* CONFIG_AUFS_DEBUG */

const struct address_space_operations aufs_aop = {
	.readpage		= aufs_readpage,
	.direct_IO		= aufs_direct_IO,
#ifdef CONFIG_AUFS_DEBUG
	.writepage		= aufs_writepage,
	/* no writepages, because of writepage */
	.set_page_dirty		= aufs_set_page_dirty,
	/* no readpages, because of readpage */
	.write_begin		= aufs_write_begin,
	.write_end		= aufs_write_end,
	/* no bmap, no block device */
	.invalidatepage		= aufs_invalidatepage,
	.releasepage		= aufs_releasepage,
	/* is fallback_migrate_page ok? */
	/* .migratepage		= aufs_migratepage, */
	.isolate_page		= aufs_isolate_page,
	.putback_page		= aufs_putback_page,
	.launder_page		= aufs_launder_page,
	.is_partially_uptodate	= aufs_is_partially_uptodate,
	.is_dirty_writeback	= aufs_is_dirty_writeback,
	.error_remove_page	= aufs_error_remove_page,
	.swap_activate		= aufs_swap_activate,
	.swap_deactivate	= aufs_swap_deactivate
#endif /* CONFIG_AUFS_DEBUG */
};
