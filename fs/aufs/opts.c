// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2019 Junjiro R. Okajima
 */

/*
 * mount options/flags
 */

#include <linux/namei.h>
#include <linux/types.h> /* a distribution requires */
#include <linux/parser.h>
#include "aufs.h"

/* ---------------------------------------------------------------------- */

enum {
	Opt_br,
	Opt_add,
	Opt_tail, Opt_ignore, Opt_ignore_silent, Opt_err
};

static match_table_t options = {
	{Opt_br, "br=%s"},
	{Opt_br, "br:%s"},

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

int au_opts_mount(struct super_block *sb, struct au_opts *opts)
{
	int err;
	unsigned int tmp;
	aufs_bindex_t bbot;
	struct au_opt *opt;
	struct au_sbinfo *sbinfo;

	SiMustWriteLock(sb);

	err = 0;
	opt = opts->opt;
	while (err >= 0 && opt->type != Opt_tail)
		/* re-commit later */
		/* err = au_opt_simple(sb, opt++, opts); */
		err = 0;
	if (err > 0)
		err = 0;
	else if (unlikely(err < 0))
		goto out;

	sbinfo = au_sbi(sb);
	tmp = sbinfo->si_mntflags;
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

out:
	return err;
}
