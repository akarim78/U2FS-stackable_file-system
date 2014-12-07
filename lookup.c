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
#define DEBUG 0
/* The dentry cache is just so we have properly sized dentries */
static struct kmem_cache *u2fs_dentry_cachep;

static void u2fs_fill_inode(struct dentry *dentry,
		struct inode *inode)
{
	struct inode *lower_inode = NULL;
	struct inode *lower_inode_left;
	struct inode *lower_inode_right;
	struct dentry *lower_dentry;
	BUG_ON(!dentry);
	BUG_ON(!inode);

	lower_dentry = U2FS_D(dentry)->lower_path_left.dentry;
	if(lower_dentry)
	{
		lower_inode_left = igrab(lower_dentry->d_inode);
		if(lower_inode_left){
			u2fs_set_lower_inode_left(inode, lower_inode_left);
		}
	}

	lower_dentry = U2FS_D(dentry)->lower_path_right.dentry;
	if(lower_dentry){
		lower_inode_right = igrab(lower_dentry->d_inode);
		if(lower_inode_right){
			u2fs_set_lower_inode_right(inode, lower_inode_right);
		}
	}

	lower_inode_left = u2fs_lower_inode_left(inode);
	lower_inode_right = u2fs_lower_inode_right(inode);

	/* Use different set of inode ops for symlinks & directories */
	if(lower_inode_left){
		lower_inode = lower_inode_left;
	}
	else if(lower_inode_right){
		lower_inode = lower_inode_right;
	}

	if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &u2fs_symlink_iops;

	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &u2fs_dir_iops;

	/* Use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode)){
		inode->i_fop = &u2fs_dir_fops;
	}
	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
			S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode)){
		init_special_inode(inode, lower_inode->i_mode,
				lower_inode->i_rdev);
	}

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
}


int u2fs_init_dentry_cache(void)
{
	u2fs_dentry_cachep =
		kmem_cache_create("u2fs_dentry",
				sizeof(struct u2fs_dentry_info),
				0, SLAB_RECLAIM_ACCOUNT, NULL);

	return u2fs_dentry_cachep ? 0 : -ENOMEM;
}

void u2fs_destroy_dentry_cache(void)
{
	if (u2fs_dentry_cachep)
		kmem_cache_destroy(u2fs_dentry_cachep);
}

void free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(u2fs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry)
{

	// this extracts the u2fs_dentry_info from dentry
	struct u2fs_dentry_info *info = U2FS_D(dentry);
	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(u2fs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}

static int u2fs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = u2fs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int u2fs_inode_set(struct inode *inode, void *lower_inode)
{
	/* we do actual inode initialization in u2fs_iget */
	return 0;
}


struct inode *u2fs_iget_root(struct super_block *sb, unsigned long ino)
{
	struct u2fs_inode_info *info;
	struct inode *inode; /* the new inode to return */
	int size;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	info = U2FS_I(inode);
	memset(info, 0, offsetof(struct u2fs_inode_info, vfs_inode));

	size = sizeof(struct inode *);
	info->lower_inode_left = kzalloc(size, GFP_KERNEL);
	if (unlikely(!info->lower_inode_left)) {
		printk(KERN_CRIT "u2fs: no kernel memory when allocating lower-pointer array!\n");
		iget_failed(inode);
		return ERR_PTR(-ENOMEM);
	}

	info->lower_inode_right = kzalloc(size, GFP_KERNEL);
	if (unlikely(!info->lower_inode_right)){
		printk(KERN_CRIT "u2fs: no kernel memory when allocating lower-pointer array!\n");
		iget_failed(inode);
		return ERR_PTR(-ENOMEM);
	}

	info->lower_inode = kzalloc(size, GFP_KERNEL);
	if (unlikely(!info->lower_inode)){
		printk(KERN_CRIT "u2fs: no kernel memory when allocating lower-pointer array!\n");
		iget_failed(inode);
		return ERR_PTR(-ENOMEM);
	}
	inode->i_version++;
	inode->i_op = &u2fs_main_iops;
	inode->i_fop = &u2fs_main_fops;

	inode->i_mapping->a_ops = &u2fs_aops;
	inode->i_atime.tv_sec = inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = inode->i_ctime.tv_nsec = 0;
	unlock_new_inode(inode);
	return inode;

}

struct inode *u2fs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct u2fs_inode_info *info;
	struct inode *inode; /* the new inode to return */
	int err;

	inode = iget5_locked(sb, /* our superblock */
			/*
			 * hashval: we use inode number, but we can
			 * also use "(unsigned long)lower_inode"
			 * instead.
			 */
			lower_inode->i_ino, /* hashval */
			u2fs_inode_test,	/* inode comparison function */
			u2fs_inode_set, /* inode init function */
			lower_inode); /* data passed to test+set fxns */
	if (!inode) {
		err = -EACCES;
		iput(lower_inode);
		return ERR_PTR(err);
	}
	/* if found a cached inode, then just return it */
	if (!(inode->i_state & I_NEW))
		return inode;

	/* initialize new inode */
	info = U2FS_I(inode);

	inode->i_ino = lower_inode->i_ino;
	if (!igrab(lower_inode)) {
		err = -ESTALE;
		return ERR_PTR(err);
	}
	u2fs_set_lower_inode(inode, lower_inode);

	inode->i_version++;

	/* use different set of inode ops for symlinks & directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &u2fs_dir_iops;
	else if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &u2fs_symlink_iops;
	else
		inode->i_op = &u2fs_main_iops;

	/* use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &u2fs_dir_fops;
	else
		inode->i_fop = &u2fs_main_fops;

	inode->i_mapping->a_ops = &u2fs_aops;

	inode->i_atime.tv_sec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = 0;
	inode->i_ctime.tv_nsec = 0;

	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
			S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
				lower_inode->i_rdev);

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	unlock_new_inode(inode);
	return inode;
}


/*
 * Connect a u2fs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: u2fs's dentry which interposes on lower one
 * @sb: u2fs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int u2fs_interpose(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path)
{
	int err = 0;
	struct inode *inode;
	struct inode *lower_inode;
	struct super_block *lower_sb;

	lower_inode = lower_path->dentry->d_inode;
	lower_sb = u2fs_lower_super(sb);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		err = -EXDEV;
		goto out;
	}

	/*
	 * We allocate our new inode below by calling u2fs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* inherit lower inode number for u2fs's inode */
	inode = u2fs_iget(sb, lower_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_add(dentry, inode);

out:
	return err;
}

/*
 * Connect a u2fs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: u2fs's dentry which interposes on lower one
 * @sb: u2fs's super_block
 * @lower_path_left: the lower path left (caller does path_get/put)
 * @lower_path_right: the lower path right (caller does path_get/put)
 */
int u2fs_interpose_new(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path_left, struct path *lower_path_right)
{
	int err = 0;
	struct inode *inode;
	struct inode *lower_inode_left;
	struct inode *lower_inode_right;
	struct super_block *lower_sb_left;
	struct super_block *lower_sb_right;

	struct u2fs_inode_info *info;
	int size;

	if(lower_path_left){
		lower_inode_left = lower_path_left->dentry->d_inode;
		lower_sb_left = u2fs_lower_super_left(sb);
		/* check that the lower file system didn't cross a mount point */
		if (lower_inode_left->i_sb != lower_sb_left) {
			err = -EXDEV;
		}
	}

	if(lower_path_right){
		lower_inode_right = lower_path_right->dentry->d_inode;
		lower_sb_right = u2fs_lower_super_right(sb);
		/* check that the lower file system didn't cross a mount point */
		if (lower_inode_right->i_sb != lower_sb_right) {
			err = -EXDEV;
		}
	}

	/*
	 * We allocate our new inode below by calling u2fs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* creating upper inode */
	inode = iget_locked(sb, iunique(sb, U2FS_ROOT_INO));
	if (!inode)
		return -ENOMEM;
	if ((inode->i_state & I_NEW)){
		info = U2FS_I(inode);
		memset(info, 0, offsetof(struct u2fs_inode_info, vfs_inode));
		size = sizeof(struct inode *);

		if(lower_path_left){
			info->lower_inode_left = kzalloc(size, GFP_KERNEL);
			if (unlikely(!info->lower_inode_left)) {
				printk(KERN_CRIT "u2fs: no kernel memory when allocating lower left\n");
				iget_failed(inode);
				return -ENOMEM;
			}
		}

		if(lower_path_right){
			info->lower_inode_right = kzalloc(size, GFP_KERNEL);
			if (unlikely(!info->lower_inode_right)){
				printk(KERN_CRIT "u2fs: no kernel memory when allocating lower right\n");
				iget_failed(inode);
				return -ENOMEM;
			}
		}

		inode->i_version++;
		inode->i_op = &u2fs_main_iops;
		inode->i_fop = &u2fs_main_fops;

		inode->i_mapping->a_ops = &u2fs_aops;
		inode->i_atime.tv_sec = inode->i_atime.tv_nsec = 0;
		inode->i_mtime.tv_sec = inode->i_mtime.tv_nsec = 0;
		inode->i_ctime.tv_sec = inode->i_ctime.tv_nsec = 0;

		unlock_new_inode(inode);
	}
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	if (atomic_read(&inode->i_count) <= 1 && !IS_ERR(inode))
		u2fs_fill_inode(dentry, inode);

	d_add(dentry, inode);

out:
	return err;
}


/*
 * Main driver function for u2fs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
static struct dentry *__u2fs_lookup(struct dentry *dentry, int flags,
		struct path *lower_parent_path_left, struct path *lower_parent_path_right)
{
	int err = 0;
	int err1 = 0;
	int err2 = 0;
	int br_left = 0;
	int br_right = 0;

	struct vfsmount *lower_dir_mnt_left;
	struct vfsmount *lower_dir_mnt_right;

	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dir_dentry_left = NULL;
	struct dentry *lower_dir_dentry_right = NULL;
	struct dentry *lower_dentry = NULL;

	const char *name;
	struct path lower_path_left;
	struct path lower_path_right;
	struct qstr this;

	/* must initialize dentry operations */
	d_set_d_op(dentry, &u2fs_dops);

	if (IS_ROOT(dentry))
		goto out;

	name = dentry->d_name.name;
  if(DEBUG)
	   printk(KERN_INFO "u2fs: __u2fs_lookup: dentry info: name: %s\n", name);

	/* now start the actual lookup procedure */
	// first lookup under parent's left path
	if(lower_parent_path_left){
		lower_dir_dentry_left = lower_parent_path_left->dentry;
		lower_dir_dentry = lower_dir_dentry_left;
		lower_dir_mnt_left = lower_parent_path_left->mnt;

		/* Use vfs_path_lookup to check if the dentry exists or not in left path of parent dentry*/
		if(lower_dir_dentry_left){
			err1 = vfs_path_lookup(lower_dir_dentry_left, lower_dir_mnt_left, name, 0,
					&lower_path_left);

			if(!err1){
				u2fs_set_lower_path_left(dentry, &lower_path_left);
			}
		}else{
			err1 =-2;
		}
	}

	if(lower_parent_path_right){
		lower_dir_dentry_right = lower_parent_path_right->dentry;
		lower_dir_dentry = lower_dir_dentry_right;
		lower_dir_mnt_right = lower_parent_path_right->mnt;

		/* Use vfs_path_lookup to check if the dentry exists or not in right path of parent dentry*/
		if(lower_dir_dentry_right){
			err2 = vfs_path_lookup(lower_dir_dentry_right, lower_dir_mnt_right, name, 0,
					&lower_path_right);
			if(!err2){
				u2fs_set_lower_path_right(dentry, &lower_path_right);
			}
		}else{
			err2 = -2;
		}
	}

	if(!err1 && !err2){
		err = u2fs_interpose_new(dentry, dentry->d_sb, &lower_path_left, &lower_path_right);
		if(err){
			u2fs_put_reset_lower_path_left(dentry);
			u2fs_put_reset_lower_path_right(dentry);
		}
		goto out;
	}else if(!err1){
		err = u2fs_interpose_new(dentry, dentry->d_sb, &lower_path_left, NULL);
		if(err){
			u2fs_put_reset_lower_path_left(dentry);
		}
		goto out;
	}else if(!err2){
		err = u2fs_interpose_new(dentry, dentry->d_sb, NULL, &lower_path_right);
		if(err){
			u2fs_put_reset_lower_path_right(dentry);
		}
		goto out;
	}


	if (err && err != -ENOENT)
		goto out;

	/* instatiate a new negative dentry */

  if(DEBUG)
    printk(KERN_INFO "u2fs: __u2fs_lookup: creating a negative dentry %s\n", name);
	this.name = name;
	this.len = strlen(name);
	this.hash = full_name_hash(this.name, this.len);

	if(lower_dir_dentry_left){
		lower_dentry = d_lookup(lower_dir_dentry_left, &this);
		br_left = 1;
	} else if(lower_dir_dentry_right){
		lower_dentry = d_lookup(lower_dir_dentry_right, &this);
		br_right = 1;
	}

	if (lower_dentry){
		goto setup_lower;
	}

	if(lower_dir_dentry_left){
		lower_dentry = d_alloc(lower_dir_dentry_left, &this);
		br_left = 1;
	} else if(lower_dir_dentry_right){
		lower_dentry = d_alloc(lower_dir_dentry_right, &this);
		br_right = 1;
	}
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}

	d_add(lower_dentry, NULL); /* instantiate and hash */

setup_lower:
	if(br_left){
		lower_path_left.dentry = lower_dentry;
		lower_path_left.mnt = mntget(lower_dir_mnt_left);
		u2fs_set_lower_path_left(dentry, &lower_path_left);
	}else if(br_right){
		lower_path_right.dentry = lower_dentry;
		lower_path_right.mnt = mntget(lower_dir_mnt_right);
		u2fs_set_lower_path_right(dentry, &lower_path_right);
	}

	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;

out:
	return ERR_PTR(err);

}

struct dentry *u2fs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd)
{
	struct dentry *ret, *parent;

	struct path lower_parent_path_left;
	struct path lower_parent_path_right;
	int err = 0;

	BUG_ON(!nd);
	parent = dget_parent(dentry);

	u2fs_get_lower_path_left(parent, &lower_parent_path_left);
	u2fs_get_lower_path_right(parent, &lower_parent_path_right);

	/* allocate dentry private data.  We free it in ->d_release */
	err = new_dentry_private_data(dentry);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}

	ret = __u2fs_lookup(dentry, nd->flags, &lower_parent_path_left, &lower_parent_path_right);

	if (IS_ERR(ret)){
		goto out;
	}
	if (ret){
		dentry = ret;
	}

	if(U2FS_D(dentry)->lower_path_left.dentry){
		if (dentry->d_inode){
			fsstack_copy_attr_times(dentry->d_inode,
					u2fs_lower_inode_left(dentry->d_inode));
		}

		/* update parent directory's atime */
		fsstack_copy_attr_atime(parent->d_inode,
				u2fs_lower_inode_left(parent->d_inode));
	}

	if(U2FS_D(dentry)->lower_path_right.dentry){
		if (dentry->d_inode){
			fsstack_copy_attr_times(dentry->d_inode,
					u2fs_lower_inode_right(dentry->d_inode));
		}

		/* update parent directory's atime */
		fsstack_copy_attr_atime(parent->d_inode,
				u2fs_lower_inode_right(parent->d_inode));
	}

out:
	if(lower_parent_path_left.dentry){
		u2fs_put_lower_path(parent, &lower_parent_path_left);
	}
	if(lower_parent_path_right.dentry){
		u2fs_put_lower_path(parent, &lower_parent_path_right);
	}

	dput(parent);
	return ret;
}
