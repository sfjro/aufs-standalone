// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * mount options/flags
 */

#include <linux/file.h>
#include <linux/namei.h>
#include <linux/types.h> /* a distribution requires */
#include <linux/parser.h>
#include "aufs.h"

/* ---------------------------------------------------------------------- */

enum {
	Opt_br,
	Opt_add,
	Opt_xino, Opt_noxino,
	Opt_trunc_xino, Opt_trunc_xino_v, Opt_notrunc_xino,
	Opt_trunc_xino_path, Opt_itrunc_xino,
	Opt_trunc_xib, Opt_notrunc_xib,
	Opt_plink, Opt_noplink, Opt_list_plink,
	Opt_tail, Opt_ignore, Opt_ignore_silent, Opt_err
};

static match_table_t options = {
	{Opt_br, "br=%s"},
	{Opt_br, "br:%s"},

	{Opt_xino, "xino=%s"},
	{Opt_noxino, "noxino"},
	{Opt_trunc_xino, "trunc_xino"},
	{Opt_trunc_xino_v, "trunc_xino_v=%d:%d"},
	{Opt_notrunc_xino, "notrunc_xino"},
	{Opt_trunc_xino_path, "trunc_xino=%s"},
	{Opt_itrunc_xino, "itrunc_xino=%d"},
	/* {Opt_zxino, "zxino=%s"}, */
	{Opt_trunc_xib, "trunc_xib"},
	{Opt_notrunc_xib, "notrunc_xib"},

#ifdef CONFIG_PROC_FS
	{Opt_plink, "plink"},
#else
	{Opt_ignore_silent, "plink"},
#endif

	{Opt_noplink, "noplink"},

#ifdef CONFIG_AUFS_DEBUG
	{Opt_list_plink, "list_plink"},
#endif

	/* internal use for the scripts */
	{Opt_ignore_silent, "si=%s"},

	/* temporary workaround, due to old mount(8)? */
	{Opt_ignore_silent, "relatime"},

	{Opt_err, NULL}
};

/* ---------------------------------------------------------------------- */

static const char *au_optstr(int *val, match_table_t tbl)
{
	struct match_token *p;
	int v;

	v = *val;
	if (!v)
		goto out;
	p = tbl;
	while (p->pattern) {
		if (p->token
		    && (v & p->token) == p->token) {
			*val &= ~p->token;
			return p->pattern;
		}
		p++;
	}

out:
	return NULL;
}

/* ---------------------------------------------------------------------- */

static match_table_t brperm = {
	{AuBrPerm_RO, AUFS_BRPERM_RO},
	/* add more later */
	{0, NULL}
};

static match_table_t brattr = {
	/* ro/rr branch */
	{AuBrRAttr_WH, AUFS_BRRATTR_WH},
	/* add more later */
	{0, NULL}
};

static int br_attr_val(char *str, match_table_t table, substring_t args[])
{
	int attr, v;
	char *p;

	attr = 0;
	do {
		p = strchr(str, '+');
		if (p)
			*p = 0;
		v = match_token(str, table, args);
		if (v)
			attr |= v;
		else {
			if (p)
				*p = '+';
			pr_warn("ignored branch attribute %s\n", str);
			break;
		}
		if (p)
			str = p + 1;
	} while (p);

	return attr;
}

static int au_do_optstr_br_attr(au_br_perm_str_t *str, int perm)
{
	int sz;
	const char *p;
	char *q;

	q = str->a;
	*q = 0;
	p = au_optstr(&perm, brattr);
	if (p) {
		sz = strlen(p);
		memcpy(q, p, sz + 1);
		q += sz;
	} else
		goto out;

	do {
		p = au_optstr(&perm, brattr);
		if (p) {
			*q++ = '+';
			sz = strlen(p);
			memcpy(q, p, sz + 1);
			q += sz;
		}
	} while (p);

out:
	return q - str->a;
}

static int noinline_for_stack br_perm_val(char *perm)
{
	int val;
	char *p;
	substring_t args[MAX_OPT_ARGS];

	p = strchr(perm, '+');
	if (p)
		*p = 0;
	val = match_token(perm, brperm, args);
	if (!val) {
		if (p)
			*p = '+';
		pr_warn("ignored branch permission %s\n", perm);
		val = AuBrPerm_RO;
		goto out;
	}
	if (!p)
		goto out;

	val |= br_attr_val(p + 1, brattr, args);

out:
	return val;
}

void au_optstr_br_perm(au_br_perm_str_t *str, int perm)
{
	au_br_perm_str_t attr;
	const char *p;
	char *q;
	int sz;

	q = str->a;
	p = au_optstr(&perm, brperm);
	AuDebugOn(!p || !*p);
	sz = strlen(p);
	memcpy(q, p, sz + 1);
	q += sz;

	sz = au_do_optstr_br_attr(&attr, perm);
	if (sz) {
		*q++ = '+';
		memcpy(q, attr.a, sz + 1);
	}

	AuDebugOn(strlen(str->a) >= sizeof(str->a));
}

/* ---------------------------------------------------------------------- */

static const int lkup_dirflags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

static void dump_opts(struct au_opts *opts)
{
#ifdef CONFIG_AUFS_DEBUG
	/* reduce stack space */
	union {
		struct au_opt_add *add;
		struct au_opt_xino *xino;
		struct au_opt_xino_itrunc *xino_itrunc;
	} u;
	struct au_opt *opt;

	opt = opts->opt;
	while (opt->type != Opt_tail) {
		switch (opt->type) {
		case Opt_add:
			u.add = &opt->add;
			AuDbg("add {b%d, %s, 0x%x, %p}\n",
				  u.add->bindex, u.add->pathname, u.add->perm,
				  u.add->path.dentry);
			break;
		case Opt_xino:
			u.xino = &opt->xino;
			AuDbg("xino {%s %pD}\n", u.xino->path, u.xino->file);
			break;
		case Opt_trunc_xino:
			AuLabel(trunc_xino);
			break;
		case Opt_notrunc_xino:
			AuLabel(notrunc_xino);
			break;
		case Opt_trunc_xino_path:
		case Opt_itrunc_xino:
			u.xino_itrunc = &opt->xino_itrunc;
			AuDbg("trunc_xino %d\n", u.xino_itrunc->bindex);
			break;
		case Opt_noxino:
			AuLabel(noxino);
			break;
		case Opt_trunc_xib:
			AuLabel(trunc_xib);
			break;
		case Opt_notrunc_xib:
			AuLabel(notrunc_xib);
			break;
		case Opt_plink:
			AuLabel(plink);
			break;
		case Opt_noplink:
			AuLabel(noplink);
			break;
		case Opt_list_plink:
			AuLabel(list_plink);
			break;
		default:
			BUG();
		}
		opt++;
	}
#endif
}

void au_opts_free(struct au_opts *opts)
{
	struct au_opt *opt;

	opt = opts->opt;
	while (opt->type != Opt_tail) {
		switch (opt->type) {
		case Opt_add:
			path_put(&opt->add.path);
			break;
		case Opt_xino:
			fput(opt->xino.file);
			break;
		}
		opt++;
	}
}

static int opt_add(struct au_opt *opt, char *opt_str, unsigned long sb_flags,
		   aufs_bindex_t bindex)
{
	int err;
	struct au_opt_add *add = &opt->add;
	char *p;

	add->bindex = bindex;
	add->perm = AuBrPerm_RO;
	add->pathname = opt_str;
	p = strchr(opt_str, '=');
	if (p) {
		*p++ = 0;
		if (*p)
			add->perm = br_perm_val(p);
	}

	err = vfsub_kern_path(add->pathname, lkup_dirflags, &add->path);
	if (!err) {
		if (!p)
			add->perm = AuBrPerm_RO;
			/* re-commit later */
		opt->type = Opt_add;
		goto out;
	}
	pr_err("lookup failed %s (%d)\n", add->pathname, err);
	err = -EINVAL;

out:
	return err;
}

static int au_opts_parse_xino(struct super_block *sb, struct au_opt_xino *xino,
			      substring_t args[])
{
	int err;
	struct file *file;

	file = au_xino_create(sb, args[0].from, /*silent*/0);
	err = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;

	err = -EINVAL;
	if (unlikely(file->f_path.dentry->d_sb == sb)) {
		fput(file);
		pr_err("%s must be outside\n", args[0].from);
		goto out;
	}

	err = 0;
	xino->file = file;
	xino->path = args[0].from;

out:
	return err;
}

static int noinline_for_stack
au_opts_parse_xino_itrunc_path(struct super_block *sb,
			       struct au_opt_xino_itrunc *xino_itrunc,
			       substring_t args[])
{
	int err;
	aufs_bindex_t bbot, bindex;
	struct path path;
	struct dentry *root;

	err = vfsub_kern_path(args[0].from, lkup_dirflags, &path);
	if (unlikely(err)) {
		pr_err("lookup failed %s (%d)\n", args[0].from, err);
		goto out;
	}

	xino_itrunc->bindex = -1;
	root = sb->s_root;
	si_read_lock(sb, AuLock_FLUSH);
	di_read_lock_child(root, /*flags*/0);
	bbot = au_sbbot(sb);
	for (bindex = 0; bindex <= bbot; bindex++) {
		if (au_h_dptr(root, bindex) == path.dentry) {
			xino_itrunc->bindex = bindex;
			break;
		}
	}
	di_read_unlock(root, /*flags*/0);
	si_read_unlock(sb);
	path_put(&path);

	if (unlikely(xino_itrunc->bindex < 0)) {
		pr_err("no such branch %s\n", args[0].from);
		err = -EINVAL;
	}

out:
	return err;
}

/* called without aufs lock */
int au_opts_parse(struct super_block *sb, char *str, struct au_opts *opts)
{
	int err, n, token;
	aufs_bindex_t bindex;
	unsigned char skipped;
	struct dentry *root;
	struct au_opt *opt, *opt_tail;
	char *opt_str;
	/* reduce the stack space */
	union {
		struct au_opt_xino_itrunc *xino_itrunc;
		struct au_opt_wbr_create *create;
	} u;
	struct {
		substring_t args[MAX_OPT_ARGS];
	} *a;

	err = -ENOMEM;
	a = kmalloc(sizeof(*a), GFP_NOFS);
	if (unlikely(!a))
		goto out;

	root = sb->s_root;
	err = 0;
	bindex = 0;
	opt = opts->opt;
	opt_tail = opt + opts->max_opt - 1;
	opt->type = Opt_tail;
	while (!err && (opt_str = strsep(&str, ",")) && *opt_str) {
		err = -EINVAL;
		skipped = 0;
		token = match_token(opt_str, options, a->args);
		switch (token) {
		case Opt_br:
			err = 0;
			while (!err && (opt_str = strsep(&a->args[0].from, ":"))
			       && *opt_str) {
				err = opt_add(opt, opt_str, opts->sb_flags,
					      bindex++);
				if (unlikely(!err && ++opt > opt_tail)) {
					err = -E2BIG;
					break;
				}
				opt->type = Opt_tail;
				skipped = 1;
			}
			break;
		case Opt_add:
			if (unlikely(match_int(&a->args[0], &n))) {
				pr_err("bad integer in %s\n", opt_str);
				break;
			}
			bindex = n;
			err = opt_add(opt, a->args[1].from, opts->sb_flags,
				      bindex);
			if (!err)
				opt->type = token;
			break;

		case Opt_xino:
			err = au_opts_parse_xino(sb, &opt->xino, a->args);
			if (!err)
				opt->type = token;
			break;

		case Opt_trunc_xino_path:
			err = au_opts_parse_xino_itrunc_path
				(sb, &opt->xino_itrunc, a->args);
			if (!err)
				opt->type = token;
			break;

		case Opt_itrunc_xino:
			u.xino_itrunc = &opt->xino_itrunc;
			if (unlikely(match_int(&a->args[0], &n))) {
				pr_err("bad integer in %s\n", opt_str);
				break;
			}
			u.xino_itrunc->bindex = n;
			si_read_lock(sb, AuLock_FLUSH);
			di_read_lock_child(root, !AuLock_IR);
			if (n < 0 || au_sbbot(sb) < n) {
				pr_err("out of bounds, %d\n", n);
				di_read_unlock(root, !AuLock_IR);
				si_read_unlock(sb);
				break;
			}
			di_read_unlock(root, !AuLock_IR);
			si_read_unlock(sb);
			err = 0;
			opt->type = token;
			break;

		case Opt_trunc_xino:
		case Opt_notrunc_xino:
		case Opt_noxino:
		case Opt_trunc_xib:
		case Opt_notrunc_xib:
		case Opt_plink:
		case Opt_noplink:
		case Opt_list_plink:
			err = 0;
			opt->type = token;
			break;

		case Opt_ignore:
			pr_warn("ignored %s\n", opt_str);
			/*FALLTHROUGH*/
		case Opt_ignore_silent:
			skipped = 1;
			err = 0;
			break;
		case Opt_err:
			pr_err("unknown option %s\n", opt_str);
			break;
		}

		if (!err && !skipped) {
			if (unlikely(++opt > opt_tail)) {
				err = -E2BIG;
				opt--;
				opt->type = Opt_tail;
				break;
			}
			opt->type = Opt_tail;
		}
	}

	au_kfree_rcu(a);
	dump_opts(opts);
	if (unlikely(err))
		au_opts_free(opts);

out:
	return err;
}

/*
 * returns,
 * plus: processed without an error
 * zero: unprocessed
 */
static int au_opt_simple(struct super_block *sb, struct au_opt *opt,
			 struct au_opts *opts)
{
	int err;
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	err = 1; /* handled */
	sbinfo = au_sbi(sb);
	switch (opt->type) {
	case Opt_plink:
		au_opt_set(sbinfo->si_mntflags, PLINK);
		break;
	case Opt_noplink:
		if (au_opt_test(sbinfo->si_mntflags, PLINK))
			au_plink_put(sb, /*verbose*/1);
		au_opt_clr(sbinfo->si_mntflags, PLINK);
		break;
	case Opt_list_plink:
		if (au_opt_test(sbinfo->si_mntflags, PLINK))
			au_plink_list(sb);
		break;

	case Opt_trunc_xino:
		au_opt_set(sbinfo->si_mntflags, TRUNC_XINO);
		break;
	case Opt_notrunc_xino:
		au_opt_clr(sbinfo->si_mntflags, TRUNC_XINO);
		break;

	case Opt_trunc_xino_path:
	case Opt_itrunc_xino:
		err = au_xino_trunc(sb, opt->xino_itrunc.bindex,
				    /*idx_begin*/0);
		if (!err)
			err = 1;
		break;

	case Opt_trunc_xib:
		au_fset_opts(opts->flags, TRUNC_XIB);
		break;
	case Opt_notrunc_xib:
		au_fclr_opts(opts->flags, TRUNC_XIB);
		break;

	default:
		err = 0;
		break;
	}

	return err;
}

/*
 * returns tri-state.
 * plus: processed without an error
 * zero: unprocessed
 * minus: error
 */
static int au_opt_br(struct super_block *sb, struct au_opt *opt,
		     struct au_opts *opts)
{
	int err;

	err = 0;
	switch (opt->type) {
	case Opt_add:
		err = au_br_add(sb, &opt->add);
		if (!err) {
			err = 1;
			/* au_fset_opts(opts->flags, REFRESH); re-commit later */
		}
		break;
	}
	return err;
}

static int au_opt_xino(struct super_block *sb, struct au_opt *opt,
		       struct au_opt_xino **opt_xino,
		       struct au_opts *opts)
{
	int err;

	err = 0;
	switch (opt->type) {
	case Opt_xino:
		err = au_xino_set(sb, &opt->xino);
		if (unlikely(err))
			break;

		*opt_xino = &opt->xino;
		break;

	case Opt_noxino:
		au_xino_clr(sb);
		*opt_xino = (void *)-1;
		break;
	}

	return err;
}

int au_opts_mount(struct super_block *sb, struct au_opts *opts)
{
	int err;
	unsigned int tmp;
	aufs_bindex_t bbot;
	struct au_opt *opt;
	struct au_opt_xino *opt_xino, xino;
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	err = 0;
	opt_xino = NULL;
	opt = opts->opt;
	while (err >= 0 && opt->type != Opt_tail)
		err = au_opt_simple(sb, opt++, opts);
	if (err > 0)
		err = 0;
	else if (unlikely(err < 0))
		goto out;

	/* disable xino temporary */
	sbinfo = au_sbi(sb);
	tmp = sbinfo->si_mntflags;
	au_opt_clr(sbinfo->si_mntflags, XINO);

	opt = opts->opt;
	while (err >= 0 && opt->type != Opt_tail)
		err = au_opt_br(sb, opt++, opts);
	if (err > 0)
		err = 0;
	else if (unlikely(err < 0))
		goto out;

	bbot = au_sbbot(sb);
	if (unlikely(bbot < 0)) {
		err = -EINVAL;
		pr_err("no branches\n");
		goto out;
	}

	if (au_opt_test(tmp, XINO))
		au_opt_set(sbinfo->si_mntflags, XINO);
	opt = opts->opt;
	while (!err && opt->type != Opt_tail)
		err = au_opt_xino(sb, opt++, &opt_xino, opts);
	if (unlikely(err))
		goto out;

	/* restore xino */
	if (au_opt_test(tmp, XINO) && !opt_xino) {
		xino.file = au_xino_def(sb);
		err = PTR_ERR(xino.file);
		if (IS_ERR(xino.file))
			goto out;

		err = au_xino_set(sb, &xino);
		fput(xino.file);
		if (unlikely(err))
			goto out;
	}

	bbot = au_sbbot(sb);

out:
	return err;
}
