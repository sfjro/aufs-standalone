// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Junjiro R. Okajima
 */

/*
 * fs context, aka new mount api
 */

#include <linux/fs_context.h>
#include "aufs.h"

struct au_fsctx_opts {
	aufs_bindex_t bindex;
	unsigned char skipped;
	struct au_opt *opt, *opt_tail;
	struct super_block *sb;
	struct au_sbinfo *sbinfo;
	struct au_opts opts;
};

static void au_fsctx_dump(struct au_opts *opts)
{
#ifdef CONFIG_AUFS_DEBUG
	/* reduce stack space */
	union {
		struct au_opt_add *add;
		struct au_opt_del *del;
		struct au_opt_mod *mod;
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
		case Opt_del:
			fallthrough;
		case Opt_idel:
			u.del = &opt->del;
			AuDbg("del {%s, %p}\n",
			      u.del->pathname, u.del->h_path.dentry);
			break;
		case Opt_mod:
			fallthrough;
		case Opt_imod:
			u.mod = &opt->mod;
			AuDbg("mod {%s, 0x%x, %p}\n",
				  u.mod->path, u.mod->perm, u.mod->h_root);
			break;
		case Opt_append:
			u.add = &opt->add;
			AuDbg("append {b%d, %s, 0x%x, %p}\n",
				  u.add->bindex, u.add->pathname, u.add->perm,
				  u.add->path.dentry);
			break;
		case Opt_prepend:
			u.add = &opt->add;
			AuDbg("prepend {b%d, %s, 0x%x, %p}\n",
				  u.add->bindex, u.add->pathname, u.add->perm,
				  u.add->path.dentry);
			break;

		case Opt_xino:
			u.xino = &opt->xino;
			AuDbg("xino {%s %pD}\n", u.xino->path, u.xino->file);
			break;

#define au_fsctx_TF(name)					  \
			case Opt_##name:			  \
				if (opt->tf)			  \
					AuLabel(name);		  \
				else				  \
					AuLabel(no##name);	  \
				break;

		/* simple true/false flag */
		au_fsctx_TF(trunc_xino);
		au_fsctx_TF(trunc_xib);
#undef au_fsctx_TF

		case Opt_trunc_xino_path:
			fallthrough;
		case Opt_itrunc_xino:
			u.xino_itrunc = &opt->xino_itrunc;
			AuDbg("trunc_xino %d\n", u.xino_itrunc->bindex);
			break;
		case Opt_noxino:
			AuLabel(noxino);
			break;
		/* re-commit later */

		default:
			AuDbg("type %d\n", opt->type);
			BUG();
		}
		opt++;
	}
#endif
}

/* ---------------------------------------------------------------------- */

/*
 * For conditionally compiled mount options.
 * Instead of fsparam_flag_no(), use this macro to distinguish ignore_silent.
 */
#define au_ignore_flag(name, action)		\
	fsparam_flag(name, action),		\
	fsparam_flag("no" name, Opt_ignore_silent)

const struct fs_parameter_spec aufs_fsctx_paramspec[] = {
	fsparam_string("br", Opt_br),

	/* "add=%d:%s" or "ins=%d:%s" */
	fsparam_string("add", Opt_add),
	fsparam_string("ins", Opt_add),
	fsparam_path("append", Opt_append),
	fsparam_path("prepend", Opt_prepend),

	fsparam_path("del", Opt_del),
	/* fsparam_s32("idel", Opt_idel), */
	fsparam_path("mod", Opt_mod),
	/* fsparam_string("imod", Opt_imod), */

	fsparam_path("xino", Opt_xino),
	fsparam_flag("noxino", Opt_noxino),
	fsparam_flag_no("trunc_xino", Opt_trunc_xino),
	/* "trunc_xino_v=%d:%d" */
	/* fsparam_string("trunc_xino_v", Opt_trunc_xino_v), */
	fsparam_path("trunc_xino", Opt_trunc_xino_path),
	fsparam_s32("itrunc_xino", Opt_itrunc_xino),
	/* fsparam_path("zxino", Opt_zxino), */
	fsparam_flag_no("trunc_xib", Opt_trunc_xib),

	/* re-commit later */
	{}
};

static int au_fsctx_parse_do_add(struct fs_context *fc, struct au_opt *opt,
				 char *brspec, size_t speclen,
				 aufs_bindex_t bindex)
{
	int err;
	char *p;

	AuDbg("brspec %s\n", brspec);

	err = -ENOMEM;
	if (!speclen)
		speclen = strlen(brspec);
	/* will be freed by au_fsctx_free() */
	p = kmemdup_nul(brspec, speclen, GFP_NOFS);
	if (unlikely(!p)) {
		errorfc(fc, "failed in %s", brspec);
		goto out;
	}
	err = au_opt_add(opt, p, fc->sb_flags, bindex);

out:
	AuTraceErr(err);
	return err;
}

static int au_fsctx_parse_br(struct fs_context *fc, char *brspec)
{
	int err;
	char *p;
	struct au_fsctx_opts *a = fc->fs_private;
	struct au_opt *opt = a->opt;
	aufs_bindex_t bindex = a->bindex;

	AuDbg("brspec %s\n", brspec);

	err = -EINVAL;
	while ((p = strsep(&brspec, ":")) && *p) {
		err = au_fsctx_parse_do_add(fc, opt, p, /*len*/0, bindex);
		AuTraceErr(err);
		if (unlikely(err))
			break;
		bindex++;
		opt++;
		if (unlikely(opt > a->opt_tail)) {
			err = -E2BIG;
			bindex--;
			opt--;
			break;
		}
		opt->type = Opt_tail;
		a->skipped = 1;
	}
	a->bindex = bindex;
	a->opt = opt;

	AuTraceErr(err);
	return err;
}

static int au_fsctx_parse_add(struct fs_context *fc, char *addspec)
{
	int err, n;
	char *p;
	struct au_fsctx_opts *a = fc->fs_private;
	struct au_opt *opt = a->opt;

	err = -EINVAL;
	p = strchr(addspec, ':');
	if (unlikely(!p)) {
		errorfc(fc, "bad arg in %s", addspec);
		goto out;
	}
	*p++ = '\0';
	err = kstrtoint(addspec, 0, &n);
	if (unlikely(err)) {
		errorfc(fc, "bad integer in %s", addspec);
		goto out;
	}
	AuDbg("n %d\n", n);
	err = au_fsctx_parse_do_add(fc, opt, p, /*len*/0, n);

out:
	AuTraceErr(err);
	return err;
}

static int au_fsctx_parse_del(struct fs_context *fc, struct au_opt_del *del,
			      struct fs_parameter *param)
{
	int err;

	err = -ENOMEM;
	/* will be freed by au_fsctx_free() */
	del->pathname = kmemdup_nul(param->string, param->size, GFP_NOFS);
	if (unlikely(!del->pathname))
		goto out;
	AuDbg("del %s\n", del->pathname);
	err = vfsub_kern_path(del->pathname, AuOpt_LkupDirFlags, &del->h_path);
	if (unlikely(err))
		errorfc(fc, "lookup failed %s (%d)", del->pathname, err);

out:
	AuTraceErr(err);
	return err;
}

#if 0 /* reserved for future use */
static int au_fsctx_parse_idel(struct fs_context *fc, struct au_opt_del *del,
			       aufs_bindex_t bindex)
{
	int err;
	struct super_block *sb;
	struct dentry *root;
	struct au_fsctx_opts *a = fc->fs_private;

	sb = a->sb;
	AuDebugOn(!sb);

	err = -EINVAL;
	root = sb->s_root;
	aufs_read_lock(root, AuLock_FLUSH);
	if (bindex < 0 || au_sbbot(sb) < bindex) {
		errorfc(fc, "out of bounds, %d", bindex);
		goto out;
	}

	err = 0;
	del->h_path.dentry = dget(au_h_dptr(root, bindex));
	del->h_path.mnt = mntget(au_sbr_mnt(sb, bindex));

out:
	aufs_read_unlock(root, !AuLock_IR);
	AuTraceErr(err);
	return err;
}
#endif

static int au_fsctx_parse_mod(struct fs_context *fc, struct au_opt_mod *mod,
			      struct fs_parameter *param)
{
	int err;
	struct path path;
	char *p;

	err = -ENOMEM;
	/* will be freed by au_fsctx_free() */
	mod->path = kmemdup_nul(param->string, param->size, GFP_NOFS);
	if (unlikely(!mod->path))
		goto out;

	err = -EINVAL;
	p = strchr(mod->path, '=');
	if (unlikely(!p)) {
		errorfc(fc, "no permission %s", mod->path);
		goto out;
	}

	*p++ = 0;
	err = vfsub_kern_path(mod->path, AuOpt_LkupDirFlags, &path);
	if (unlikely(err)) {
		errorfc(fc, "lookup failed %s (%d)", mod->path, err);
		goto out;
	}

	mod->perm = au_br_perm_val(p);
	AuDbg("mod path %s, perm 0x%x, %s", mod->path, mod->perm, p);
	mod->h_root = dget(path.dentry);
	path_put(&path);

out:
	AuTraceErr(err);
	return err;
}

#if 0 /* reserved for future use */
static int au_fsctx_parse_imod(struct fs_context *fc, struct au_opt_mod *mod,
			       char *ibrspec)
{
	int err, n;
	char *p;
	struct super_block *sb;
	struct dentry *root;
	struct au_fsctx_opts *a = fc->fs_private;

	sb = a->sb;
	AuDebugOn(!sb);

	err = -EINVAL;
	p = strchr(ibrspec, ':');
	if (unlikely(!p)) {
		errorfc(fc, "no index, %s", ibrspec);
		goto out;
	}
	*p++ = '\0';
	err = kstrtoint(ibrspec, 0, &n);
	if (unlikely(err)) {
		errorfc(fc, "bad integer in %s", ibrspec);
		goto out;
	}
	AuDbg("n %d\n", n);

	root = sb->s_root;
	aufs_read_lock(root, AuLock_FLUSH);
	if (n < 0 || au_sbbot(sb) < n) {
		errorfc(fc, "out of bounds, %d", bindex);
		goto out_root;
	}

	err = 0;
	mod->perm = au_br_perm_val(p);
	AuDbg("mod path %s, perm 0x%x, %s\n",
	      mod->path, mod->perm, p);
	mod->h_root = dget(au_h_dptr(root, bindex));

out_root:
	aufs_read_unlock(root, !AuLock_IR);
out:
	AuTraceErr(err);
	return err;
}
#endif

static int au_fsctx_parse_xino(struct fs_context *fc,
			       struct au_opt_xino *xino,
			       struct fs_parameter *param)
{
	int err;
	struct au_fsctx_opts *a = fc->fs_private;

	err = -ENOMEM;
	/* will be freed by au_opts_free() */
	xino->path = kmemdup_nul(param->string, param->size, GFP_NOFS);
	if (unlikely(!xino->path))
		goto out;
	AuDbg("path %s\n", xino->path);

	xino->file = au_xino_create(a->sb, xino->path, /*silent*/0,
				    /*wbrtop*/0);
	err = PTR_ERR(xino->file);
	if (IS_ERR(xino->file)) {
		xino->file = NULL;
		goto out;
	}

	err = 0;
	if (unlikely(a->sb && xino->file->f_path.dentry->d_sb == a->sb)) {
		err = -EINVAL;
		errorfc(fc, "%s must be outside", xino->path);
	}

out:
	AuTraceErr(err);
	return err;
}

static
int au_fsctx_parse_xino_itrunc_path(struct fs_context *fc,
				    struct au_opt_xino_itrunc *xino_itrunc,
				    char *pathname)
{
	int err;
	aufs_bindex_t bbot, bindex;
	struct path path;
	struct dentry *root;
	struct au_fsctx_opts *a = fc->fs_private;

	AuDebugOn(!a->sb);

	err = vfsub_kern_path(pathname, AuOpt_LkupDirFlags, &path);
	if (unlikely(err)) {
		errorfc(fc, "lookup failed %s (%d)", pathname, err);
		goto out;
	}

	xino_itrunc->bindex = -1;
	root = a->sb->s_root;
	aufs_read_lock(root, AuLock_FLUSH);
	bbot = au_sbbot(a->sb);
	for (bindex = 0; bindex <= bbot; bindex++) {
		if (au_h_dptr(root, bindex) == path.dentry) {
			xino_itrunc->bindex = bindex;
			break;
		}
	}
	aufs_read_unlock(root, !AuLock_IR);
	path_put(&path);

	if (unlikely(xino_itrunc->bindex < 0)) {
		err = -EINVAL;
		errorfc(fc, "no such branch %s", pathname);
	}

out:
	AuTraceErr(err);
	return err;
}

static int au_fsctx_parse_xino_itrunc(struct fs_context *fc,
				      struct au_opt_xino_itrunc *xino_itrunc,
				      unsigned int bindex)
{
	int err;
	aufs_bindex_t bbot;
	struct super_block *sb;
	struct au_fsctx_opts *a = fc->fs_private;

	sb = a->sb;
	AuDebugOn(!sb);

	err = 0;
	si_noflush_read_lock(sb);
	bbot = au_sbbot(sb);
	si_read_unlock(sb);
	if (bindex <= bbot)
		xino_itrunc->bindex = bindex;
	else {
		err = -EINVAL;
		errorfc(fc, "out of bounds, %u", bindex);
	}

	AuTraceErr(err);
	return err;
}

static int au_fsctx_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	int err, token;
	struct fs_parse_result result;
	struct au_fsctx_opts *a = fc->fs_private;
	struct au_opt *opt = a->opt;

	AuDbg("fc %p, param {key %s, string %s}\n",
	      fc, param->key, param->string);
	err = fs_parse(fc, aufs_fsctx_paramspec, param, &result);
	if (unlikely(err < 0))
		goto out;
	token = err;
	AuDbg("token %d, res{negated %d, uint64 %llu}\n",
	      token, result.negated, result.uint_64);

	err = -EINVAL;
	a->skipped = 0;
	switch (token) {
	case Opt_br:
		err = au_fsctx_parse_br(fc, param->string);
		break;
	case Opt_add:
		err = au_fsctx_parse_add(fc, param->string);
		break;
	case Opt_append:
		err = au_fsctx_parse_do_add(fc, opt, param->string, param->size,
					    /*dummy bindex*/1);
		break;
	case Opt_prepend:
		err = au_fsctx_parse_do_add(fc, opt, param->string, param->size,
					    /*bindex*/0);
		break;

	case Opt_del:
		err = au_fsctx_parse_del(fc, &opt->del, param);
		break;
#if 0 /* reserved for future use */
	case Opt_idel:
		if (!a->sb) {
			err = 0;
			a->skipped = 1;
			break;
		}
		del->pathname = "(indexed)";
		err = au_opts_parse_idel(fc, &opt->del, result.uint_32);
		break;
#endif

	case Opt_mod:
		err = au_fsctx_parse_mod(fc, &opt->mod, param);
		break;
#ifdef IMOD /* reserved for future use */
	case Opt_imod:
		if (!a->sb) {
			err = 0;
			a->skipped = 1;
			break;
		}
		u.mod->path = "(indexed)";
		err = au_opts_parse_imod(fc, &opt->mod, param->string);
		break;
#endif

	case Opt_xino:
		err = au_fsctx_parse_xino(fc, &opt->xino, param);
		break;
	case Opt_trunc_xino_path:
		if (!a->sb) {
			errorfc(fc, "no such branch %s", param->string);
			break;
		}
		err = au_fsctx_parse_xino_itrunc_path(fc, &opt->xino_itrunc,
						      param->string);
		break;
#if 0
	case Opt_trunc_xino_v:
		if (!a->sb) {
			err = 0;
			a->skipped = 1;
			break;
		}
		err = au_fsctx_parse_xino_itrunc_path(fc, &opt->xino_itrunc,
						      param->string);
		break;
#endif
	case Opt_itrunc_xino:
		if (!a->sb) {
			errorfc(fc, "out of bounds %s", param->string);
			break;
		}
		err = au_fsctx_parse_xino_itrunc(fc, &opt->xino_itrunc,
						 result.int_32);
		break;

	/* simple true/false flag */
#define au_fsctx_TF(name)				\
		case Opt_##name:			\
			err = 0;			\
			opt->tf = !result.negated;	\
			break;
	au_fsctx_TF(trunc_xino);
	au_fsctx_TF(trunc_xib);
#undef au_fsctx_TF

	case Opt_noxino:
		err = 0;
		break;

	/* re-commit later */

	default:
		a->skipped = 1;
		err = -ENOPARAM;
		break;
	}
	if (unlikely(err))
		goto out;
	if (a->skipped)
		goto out;

	switch (token) {
	case Opt_br:
		break;
	default:
		opt->type = token;
		break;
	}
	opt++;
	if (unlikely(opt > a->opt_tail)) {
		err = -E2BIG;
		opt--;
	}
	opt->type = Opt_tail;
	a->opt = opt;

out:
	return err;
}

/*
 * these options accept both 'name=val' and 'name:val' form.
 * some accept optional '=' in its value.
 * eg. br:/br1=rw:/br2=ro and br=/br1=rw:/br2=ro
 */
static inline unsigned int is_colonopt(char *str)
{
#define do_test(name)					\
	if (!strncmp(str, name ":", sizeof(name)))	\
		return sizeof(name) - 1;
	do_test("br");
	do_test("add");
	do_test("ins");
	do_test("append");
	do_test("prepend");
	do_test("del");
	/* do_test("idel"); */
	do_test("mod");
	/* do_test("imod"); */
#undef do_test

	return 0;
}

static int au_fsctx_parse_monolithic(struct fs_context *fc, void *data)
{
	int err;
	unsigned int u;
	char *str;
	struct au_fsctx_opts *a = fc->fs_private;

	str = data;
	AuDbg("str %s\n", str);
	while (1) {
		u = is_colonopt(str);
		if (u)
			str[u] = '=';
		str = strchr(str, ',');
		if (!str)
			break;
		str++;
	}
	str = data;
	AuDbg("str %s\n", str);

	err = generic_parse_monolithic(fc, str);
	AuTraceErr(err);
	au_fsctx_dump(&a->opts);

	return err;
}

/* ---------------------------------------------------------------------- */

static void au_fsctx_opts_free(struct au_opts *opts)
{
	struct au_opt *opt;

	opt = opts->opt;
	while (opt->type != Opt_tail) {
		switch (opt->type) {
		case Opt_add:
			fallthrough;
		case Opt_append:
			fallthrough;
		case Opt_prepend:
			kfree(opt->add.pathname);
			path_put(&opt->add.path);
			break;
		case Opt_del:
			kfree(opt->del.pathname);
			fallthrough;
		case Opt_idel:
			path_put(&opt->del.h_path);
			break;
		case Opt_mod:
			kfree(opt->mod.path);
			fallthrough;
		case Opt_imod:
			dput(opt->mod.h_root);
			break;
		case Opt_xino:
			kfree(opt->xino.path);
			fput(opt->xino.file);
			break;
		}
		opt++;
	}
}

static void au_fsctx_free(struct fs_context *fc)
{
	struct au_fsctx_opts *a = fc->fs_private;

	/* fs_type=%p, root=%pD */
	AuDbg("fc %p{sb_flags 0x%x, sb_flags_mask 0x%x, purpose %u\n",
	      fc, fc->sb_flags, fc->sb_flags_mask, fc->purpose);

	kobject_put(&a->sbinfo->si_kobj);
	au_fsctx_opts_free(&a->opts);
	free_page((unsigned long)a->opts.opt);
	au_kfree_rcu(a);
}

static const struct fs_context_operations au_fsctx_ops = {
	.free			= au_fsctx_free,
	.parse_param		= au_fsctx_parse_param,
	.parse_monolithic	= au_fsctx_parse_monolithic
	/* re-commit later */
};

int aufs_fsctx_init(struct fs_context *fc)
{
	int err;
	struct au_fsctx_opts *a;

	/* fs_type=%p, root=%pD */
	AuDbg("fc %p{sb_flags 0x%x, sb_flags_mask 0x%x, purpose %u\n",
	      fc, fc->sb_flags, fc->sb_flags_mask, fc->purpose);

	/* they will be freed by au_fsctx_free() */
	err = -ENOMEM;
	a = kzalloc(sizeof(*a), GFP_NOFS);
	if (unlikely(!a))
		goto out;
	a->bindex = 0;
	a->opts.opt = (void *)__get_free_page(GFP_NOFS);
	if (unlikely(!a->opts.opt))
		goto out_a;
	a->opt = a->opts.opt;
	a->opt->type = Opt_tail;
	a->opts.max_opt = PAGE_SIZE / sizeof(*a->opts.opt);
	a->opt_tail = a->opt + a->opts.max_opt - 1;
	a->opts.sb_flags = fc->sb_flags;

	a->sb = NULL;
	if (fc->root) {
		AuDebugOn(fc->purpose != FS_CONTEXT_FOR_RECONFIGURE);
		a->opts.flags = AuOpts_REMOUNT;
		a->sb = fc->root->d_sb;
		a->sbinfo = au_sbi(a->sb);
		kobject_get(&a->sbinfo->si_kobj);
	} else {
		a->sbinfo = au_si_alloc(a->sb);
		AuDebugOn(!a->sbinfo);
		err = PTR_ERR(a->sbinfo);
		if (IS_ERR(a->sbinfo))
			goto out_opt;
		au_rw_write_unlock(&a->sbinfo->si_rwsem);
	}

	err = 0;
	fc->fs_private = a;
	fc->ops = &au_fsctx_ops;
	goto out; /* success */

out_opt:
	free_page((unsigned long)a->opts.opt);
out_a:
	au_kfree_rcu(a);
out:
	AuTraceErr(err);
	return err;
}
