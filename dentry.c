/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "u2fs.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
static int u2fs_d_revalidate(struct dentry *dentry, struct nameidata *nd){
	return 1;
}

static void u2fs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */
	u2fs_put_reset_lower_path(dentry);
	free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations u2fs_dops = {
	.d_revalidate	= u2fs_d_revalidate,
	.d_release	= u2fs_d_release,
};
