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

#ifndef _U2FS_H_
#define _U2FS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>


#include "sioq.h"

/* the file system name */
#define U2FS_NAME "u2fs"

/* u2fs root inode number */
#define U2FS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* operations vectors defined in specific files */
extern const struct file_operations u2fs_main_fops;
extern const struct file_operations u2fs_dir_fops;
extern const struct inode_operations u2fs_main_iops;
extern const struct inode_operations u2fs_dir_iops;
extern const struct inode_operations u2fs_symlink_iops;
extern const struct super_operations u2fs_sops;
extern const struct dentry_operations u2fs_dops;
extern const struct address_space_operations u2fs_aops, u2fs_dummy_aops;
extern const struct vm_operations_struct u2fs_vm_ops;

extern int u2fs_init_inode_cache(void);
extern void u2fs_destroy_inode_cache(void);
extern int u2fs_init_dentry_cache(void);
extern void u2fs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *u2fs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd);
extern struct inode *u2fs_iget_root(struct super_block *sb,
		unsigned long ino);
extern struct inode *u2fs_iget(struct super_block *sb,
		struct inode *lower_inode);

extern int u2fs_interpose(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path);
extern int u2fs_interpose_new(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path_left, struct path *lower_path_right);


extern int u2fs_get_nlinks(const struct inode *inode);
extern void u2fs_copy_attr_times(struct inode *upper);
extern void u2fs_copy_attr_all(struct inode *dest, const struct inode *src);

/* file private data */
struct u2fs_file_info {
	struct file *lower_file;
	struct file *lower_file_left;
	struct file *lower_file_right;
	const struct vm_operations_struct *lower_vm_ops;
};

/* u2fs inode data in memory */
struct u2fs_inode_info {
	struct inode *lower_inode;
	struct inode *lower_inode_left;
	struct inode *lower_inode_right;
	struct inode vfs_inode;
};

/* u2fs dentry data in memory */
struct u2fs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	// need to remove
	struct path lower_path;
	struct path lower_path_left;
	struct path lower_path_right;
};

/* u2fs super-block data in memory */
struct u2fs_sb_info {
	char *dev_name;
	// need to remove
	struct super_block *lower_sb;
	struct super_block *lower_sb_left;
	struct super_block *lower_sb_right;
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * u2fs_inode_info structure, U2FS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct u2fs_inode_info *U2FS_I(const struct inode *inode)
{
	return container_of(inode, struct u2fs_inode_info, vfs_inode);
}

/* dentry to private data */
#define U2FS_D(dent) ((struct u2fs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define U2FS_SB(super) ((struct u2fs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define U2FS_F(file) ((struct u2fs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *u2fs_lower_file(const struct file *f)
{
	return U2FS_F(f)->lower_file;
}
/* file to lower left file */
static inline struct file *u2fs_lower_file_left(const struct file *f)
{
	return U2FS_F(f)->lower_file_left;
}
/* file to lower right file */
static inline struct file *u2fs_lower_file_right(const struct file *f)
{
	return U2FS_F(f)->lower_file_right;
}


// for setting lower files in u2fs_file_info
static inline void u2fs_set_lower_file(struct file *f, struct file *val)
{
	U2FS_F(f)->lower_file = val;
}

static inline void u2fs_set_lower_file_left(struct file *f, struct file *val)
{
	U2FS_F(f)->lower_file_left = val;
}

static inline void u2fs_set_lower_file_right(struct file *f, struct file *val)
{
	U2FS_F(f)->lower_file_right = val;
}

/* inode to lower inode. */
static inline struct inode *u2fs_lower_inode(const struct inode *i)
{
	return U2FS_I(i)->lower_inode;
}
static inline struct inode *u2fs_lower_inode_left(const struct inode *i)
{
	return U2FS_I(i)->lower_inode_left;
}
static inline struct inode *u2fs_lower_inode_right(const struct inode *i)
{
	return U2FS_I(i)->lower_inode_right;
}

static inline void u2fs_set_lower_inode(struct inode *i, struct inode *val)
{
	U2FS_I(i)->lower_inode = val;
}
static inline void u2fs_set_lower_inode_left(struct inode *i, struct inode *val)
{
	U2FS_I(i)->lower_inode_left = val;
}
static inline void u2fs_set_lower_inode_right(struct inode *i, struct inode *val)
{
	U2FS_I(i)->lower_inode_right = val;
}

/* superblock to lower superblock */
static inline struct super_block *u2fs_lower_super(
		const struct super_block *sb)
{
	return U2FS_SB(sb)->lower_sb;
}
static inline struct super_block *u2fs_lower_super_left(
		const struct super_block *sb)
{
	return U2FS_SB(sb)->lower_sb_left;
}

static inline struct super_block *u2fs_lower_super_right(
		const struct super_block *sb)
{
	return U2FS_SB(sb)->lower_sb_right;
}



static inline void u2fs_set_lower_super(struct super_block *sb,
		struct super_block *val)
{
	U2FS_SB(sb)->lower_sb = val;
}

static inline void u2fs_set_lower_super_left(struct super_block *sb,
		struct super_block *val){
	U2FS_SB(sb)->lower_sb_left = val;
}
static inline void u2fs_set_lower_super_right(struct super_block *sb,
		struct super_block *val)
{
	U2FS_SB(sb)->lower_sb_right = val;
}


/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void u2fs_get_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(lower_path, &U2FS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_get_lower_path_left(const struct dentry *dent,
		struct path *lower_path_left)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(lower_path_left, &U2FS_D(dent)->lower_path_left);
	path_get(lower_path_left);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_get_lower_path_right(const struct dentry *dent,
		struct path *lower_path_right)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(lower_path_right, &U2FS_D(dent)->lower_path_right);
	path_get(lower_path_right);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_put_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	path_put(lower_path);
	return;
}

static inline void u2fs_set_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->lower_path, lower_path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_set_lower_path_left(const struct dentry *dent,
		struct path *lower_path_left)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->lower_path_left, lower_path_left);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_set_lower_path_right(const struct dentry *dent,
		struct path *lower_path_right)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->lower_path_right, lower_path_right);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_set_both_lower_path(const struct dentry *dent,
		struct path *lower_path, struct path *lower_path_left, struct path *lower_path_right)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->lower_path, lower_path);
	pathcpy(&U2FS_D(dent)->lower_path_left, lower_path_left);
	pathcpy(&U2FS_D(dent)->lower_path_right, lower_path_right);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&U2FS_D(dent)->lock);
	U2FS_D(dent)->lower_path.dentry = NULL;
	U2FS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}

static inline void u2fs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&lower_path, &U2FS_D(dent)->lower_path);
	U2FS_D(dent)->lower_path.dentry = NULL;
	U2FS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

static inline void u2fs_put_reset_lower_path_left(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&lower_path, &U2FS_D(dent)->lower_path_left);
	U2FS_D(dent)->lower_path_left.dentry = NULL;
	U2FS_D(dent)->lower_path_left.mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

static inline void u2fs_put_reset_lower_path_right(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&lower_path, &U2FS_D(dent)->lower_path_right);
	U2FS_D(dent)->lower_path_right.dentry = NULL;
	U2FS_D(dent)->lower_path_right.mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

static inline void u2fs_put_reset_lower_paths(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&lower_path, &U2FS_D(dent)->lower_path);
	U2FS_D(dent)->lower_path.dentry = NULL;
	U2FS_D(dent)->lower_path.mnt = NULL;

	pathcpy(&lower_path, &U2FS_D(dent)->lower_path_left);
	U2FS_D(dent)->lower_path_left.dentry = NULL;
	U2FS_D(dent)->lower_path_left.mnt = NULL;

	pathcpy(&lower_path, &U2FS_D(dent)->lower_path_right);
	U2FS_D(dent)->lower_path_right.dentry = NULL;
	U2FS_D(dent)->lower_path_right.mnt = NULL;

	spin_unlock(&U2FS_D(dent)->lock);

	path_put(&lower_path);
	return;
}

static inline void verify_locked(struct dentry *d)
{
	//BUG_ON(!d);
	//BUG_ON(!mutex_is_locked(&U2FS_D(d)->lock));
}


/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
#endif	/* not _U2FS_H_ */
