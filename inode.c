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
#define U2FS_WHPFX ".wh."
#define U2FS_WHLEN 4
#define DEBUG 0

/* construct whiteout filename (from unionfs) */
char *alloc_whname(const char *name, int len)
{
	char *buf;
	buf = kmalloc(len + U2FS_WHLEN + 1, GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);
	strcpy(buf, U2FS_WHPFX);
	strlcat(buf, name, len + U2FS_WHLEN + 1);
	return buf;
}

/* cleanup after creating whiteout file */
static void __cleanup_dentry(struct dentry *dentry)
{
	struct vfsmount *mnt;
	if(!U2FS_D(dentry)->lower_path_right.dentry->d_inode){
		dput(U2FS_D(dentry)->lower_path_right.dentry);
		mnt = U2FS_D(dentry)->lower_path_right.mnt;
		if(mnt)
			mntput(mnt);
		U2FS_D(dentry)->lower_path_right.mnt = NULL;
	}
}

/* set lower inode ptr and update left */
static void __set_inode(struct dentry *upper, struct dentry *lower)
{
	u2fs_set_lower_inode_left(upper->d_inode,  igrab(lower->d_inode));
}

/* set lower dentry ptr and update left */
static void __set_dentry(struct dentry *upper, struct dentry *lower)
{
	U2FS_D(upper)->lower_path_left.dentry = lower;
}

/*
 * Determine the mode based on the copyup flags, and the existing dentry.
 *
 * Handle file systems which may not support certain options.  For example
 * jffs2 doesn't allow one to chmod a symlink.  So we ignore such harmless
 * errors, rather than propagating them up, which results in copyup errors
 * and errors returned back to users.
 * from unionfs
 *
 */
static int copyup_permissions(struct super_block *sb,
		struct dentry *old_lower_dentry,
		struct dentry *new_lower_dentry)
{
	struct inode *i = old_lower_dentry->d_inode;
	struct iattr newattrs;
	int err;

	newattrs.ia_atime = i->i_atime;
	newattrs.ia_mtime = i->i_mtime;
	newattrs.ia_ctime = i->i_ctime;
	newattrs.ia_gid = i->i_gid;
	newattrs.ia_uid = i->i_uid;
	newattrs.ia_valid = ATTR_CTIME | ATTR_ATIME | ATTR_MTIME |
		ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_FORCE |
		ATTR_GID | ATTR_UID;
	mutex_lock(&new_lower_dentry->d_inode->i_mutex);
	err = notify_change(new_lower_dentry, &newattrs);
	if (err)
		goto out;

	/* now try to change the mode and ignore EOPNOTSUPP on symlinks */
	newattrs.ia_mode = i->i_mode;
	newattrs.ia_valid = ATTR_MODE | ATTR_FORCE;
	err = notify_change(new_lower_dentry, &newattrs);
	if (err == -EOPNOTSUPP &&
			S_ISLNK(new_lower_dentry->d_inode->i_mode)) {
		printk(KERN_WARNING
				"unionfs: changing \"%s\" symlink mode unsupported\n",
				new_lower_dentry->d_name.name);
		err = 0;
	}

out:
	mutex_unlock(&new_lower_dentry->d_inode->i_mutex);
	return err;
}

/*
 * This function replicates the directory structure up-to given dentry
 * in the left branch. Taken from unionfs except the concept of opaque
 * directory
 */
struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
		const char *name)
{
	int err;
	struct dentry *child_dentry;
	struct dentry *parent_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *lower_dentry = NULL;
	const char *childname;
	unsigned int childnamelen;
	int nr_dentry;
	int count = 0;
	struct dentry **path = NULL;
	struct super_block *sb;
	struct path lower_path;

	verify_locked(dentry);

	// I know which is the write branch
	lower_dentry = ERR_PTR(-ENOMEM);
	/* There is no sense allocating any less than the minimum. */
	nr_dentry = 1;
	path = kmalloc(nr_dentry * sizeof(struct dentry *), GFP_KERNEL);
	if (unlikely(!path))
		goto out;

	/* assume the negative dentry of unionfs as the parent dentry */
	parent_dentry = dentry;

	/*
	 * This loop finds the first parent that exists in the given branch.
	 * We start building the directory structure from there.  At the end
	 * of the loop, the following should hold:
	 *  - child_dentry is the first nonexistent child
	 *  - parent_dentry is the first existent parent
	 *  - path[0] is the = deepest child
	 *  - path[count] is the first child to create
	 */
	do {
		child_dentry = parent_dentry;
		/* find the parent directory dentry in u2fs */
		parent_dentry = dget_parent(child_dentry);

		/* find out the lower_parent_dentry in the given branch */
		u2fs_get_lower_path_left(parent_dentry, &lower_path);
		if(lower_path.dentry)
			lower_parent_dentry = lower_path.dentry;

		/* grow path table */
		if (count == nr_dentry) {
			void *p;
			nr_dentry *= 2;
			p = krealloc(path, nr_dentry * sizeof(struct dentry *),
					GFP_KERNEL);
			if (unlikely(!p)) {
				lower_dentry = ERR_PTR(-ENOMEM);
				goto out;
			}
			path = p;
		}
		/* store the child dentry */
		path[count++] = child_dentry;
	} while (!lower_parent_dentry);

	count--;
	sb = dentry->d_sb;

	/*
	 * This code goes between the begin/end labels and basically
	 * emulates a while(child_dentry != dentry), only cleaner and
	 * shorter than what would be a much longer while loop.
	 */
begin:
	/* get lower parent dir in the current branch */
	u2fs_get_lower_path_left(parent_dentry, &lower_path);
	lower_parent_dentry = lower_path.dentry;
	dput(parent_dentry);

	/* init the values to lookup */
	childname = child_dentry->d_name.name;
	childnamelen = child_dentry->d_name.len;

	if (child_dentry != dentry) {
		/* lookup child in the underlying file system */
		lower_dentry = lookup_one_len(childname, lower_parent_dentry,
				childnamelen);
    if(DEBUG)
		  printk(KERN_INFO "u2fs: create_parents: childname: %s\n", childname);
		if (IS_ERR(lower_dentry)){
			goto out;
		}
	}
	else {
		/*
		 * Is the name a whiteout of the child name ?  lookup the
		 * whiteout child in the underlying file system
		 */
		lower_dentry = lookup_one_len(name, lower_parent_dentry,
				strlen(name));
    if(DEBUG)
		  printk(KERN_INFO "u2fs: create_parents: name: %s\n", name);
		if (IS_ERR(lower_dentry)){
			goto out;
		}
		/* Replace the current dentry (if any) with the new one */
		dput(lower_parent_dentry);
		U2FS_D(dentry)->lower_path_left.dentry = lower_dentry;

		__cleanup_dentry(dentry);
		goto out;
	}

	if (lower_dentry->d_inode) {
		/*
		 * since this already exists we dput to avoid
		 * multiple references on the same dentry
		 */

		dput(lower_dentry);
	} else {
		// struct sioq_args args;
		/* it's a negative dentry, create a new dir */
		lower_parent_dentry = lock_parent(lower_dentry);

		/*
		   args.mkdir.parent = lower_parent_dentry->d_inode;
		   args.mkdir.dentry = lower_dentry;
		   args.mkdir.mode = child_dentry->d_inode->i_mode;

		   run_sioq(__u2fs_mkdir, &args);*/

		err = vfs_mkdir(lower_parent_dentry->d_inode,lower_dentry, child_dentry->d_inode->i_mode);

		if (!err){
			err = copyup_permissions(dir->i_sb, child_dentry,
					lower_dentry);
		}

		unlock_dir(lower_parent_dentry);
		if (err) {
			dput(lower_dentry);
			lower_dentry = ERR_PTR(err);
			goto out;
		}

	}
	__set_inode(child_dentry, lower_dentry);
	__set_dentry(child_dentry, lower_dentry);

	/*
	 * update times of this dentry, but also the parent, because if
	 * we changed, the parent may have changed too.
	 */
	fsstack_copy_attr_times(parent_dentry->d_inode,
			lower_parent_dentry->d_inode);
	fsstack_copy_attr_times(child_dentry->d_inode, lower_parent_dentry->d_inode);

	parent_dentry = child_dentry;
	child_dentry = path[--count];
	goto begin;
out:
	/* cleanup any leftover locks from the do/while loop above */
	if (IS_ERR(lower_dentry))
		while (count)
			dput(path[count--]);
	kfree(path);
	return lower_dentry;

}

/*
 * This is called for only unlink of a file in right branch
 */
int create_whiteout(struct dentry *dentry){
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct dentry *lower_wh_dentry;
	char *name = NULL;
	int err = -EINVAL;
	verify_locked(dentry);

	/* create dentry's whiteout equivalent */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	printk(KERN_INFO "u2fs: create_whiteout: %s\n", name);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	/*
	 * calling this function only for lower right dentry
	 */
	lower_dentry = create_parents(dentry->d_inode, dentry, dentry->d_name.name);
	if (!lower_dentry || IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		printk(KERN_ERR "u2fs: create_parents for  whiteout failed\n");
		goto out;
	}

	lower_wh_dentry = lookup_one_len(name, lower_dentry->d_parent, dentry->d_name.len + U2FS_WHLEN);
	if(IS_ERR(lower_wh_dentry))
		goto out;

	lower_dir_dentry = lock_parent(lower_wh_dentry);

	err = vfs_create(lower_dir_dentry->d_inode,
			lower_wh_dentry,
			current_umask() & S_IRUGO,
			NULL);

	if(DEBUG)
		printk(KERN_INFO "u2fs: create_whiteout: err %d\n", err);

	unlock_dir(lower_dir_dentry);
	dput(lower_wh_dentry);

out:
	kfree(name);
	return err;
}

static int u2fs_create(struct inode *dir, struct dentry *dentry,
		int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct path lower_path, saved_path;
	struct dentry *lower_parent_dentry = NULL;
	int branch_left = 0;
	int branch_right = 0;

	// only writable branch so trying it for left first
	u2fs_get_lower_path_left(dentry, &lower_path);

	if(lower_path.dentry){
		lower_dentry = lower_path.dentry;
		lower_parent_dentry = lock_parent(lower_dentry);
		err = mnt_want_write(lower_path.mnt);
		branch_left = 1;
		if (err){
			goto out_unlock;
		}
		pathcpy(&saved_path, &nd->path);
		pathcpy(&nd->path, &lower_path);
		err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
		pathcpy(&nd->path, &saved_path);
		if (err){
			goto out;
		}

		err = u2fs_interpose_new(dentry, dir->i_sb, &lower_path, NULL);
		if (err){
			goto out;
		}
		fsstack_copy_attr_times(dir, u2fs_lower_inode_left(dir));
		fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
		goto out;
	}else{
		u2fs_get_lower_path_right(dentry, &lower_path);
		if(lower_path.dentry){
			err = -EPERM;
			branch_right = 0;
		}
	}

out:
	if(lower_path.dentry)
		mnt_drop_write(lower_path.mnt);
out_unlock:
	if(branch_left){
		unlock_dir(lower_parent_dentry);
		u2fs_put_lower_path(dentry, &lower_path);
	}
	if(branch_right)
		u2fs_put_lower_path(dentry, &lower_path);

	return err;
}

static int u2fs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;
	file_size_save = i_size_read(old_dentry->d_inode);
	u2fs_get_lower_path(old_dentry, &lower_old_path);
	u2fs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = u2fs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
			u2fs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	u2fs_put_lower_path(old_dentry, &lower_old_path);
	u2fs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int u2fs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	int branch_left = 0;
	int branch_right = 0;

	struct path lower_path_left;
	struct path lower_path_right;
	struct inode *lower_dir_inode_left;
	struct inode *lower_dir_inode_right;
	struct dentry *lower_dentry_left;
	struct dentry *lower_dir_dentry_left;

	u2fs_get_lower_path_left(dentry, &lower_path_left);
	u2fs_get_lower_path_right(dentry, &lower_path_right);
	lower_dir_inode_left = u2fs_lower_inode_left(dir);
	lower_dir_inode_right = u2fs_lower_inode_right(dir);

	if(lower_path_left.dentry){
		lower_dentry_left = lower_path_left.dentry;
		dget(lower_dentry_left);
		lower_dir_dentry_left = lock_parent(lower_dentry_left);
		err = mnt_want_write(lower_path_left.mnt);
		branch_left = 1;
		if (err)
			goto out_unlock;
		err = vfs_unlink(lower_dir_inode_left , lower_dentry_left);
		if (err == -EBUSY && lower_dentry_left->d_flags & DCACHE_NFSFS_RENAMED)
			err = 0;
		if (err)
			goto out;

		fsstack_copy_attr_times(dir, lower_dir_inode_left);
		fsstack_copy_inode_size(dir, lower_dir_inode_left);
		set_nlink(dentry->d_inode, u2fs_lower_inode_left(dentry->d_inode)->i_nlink);
		dentry->d_inode->i_ctime = dir->i_ctime;
		d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */

	} else if(lower_path_right.dentry){
		branch_right = 1;
		err = create_whiteout(dentry);
	}

out:
	if(branch_left)
		mnt_drop_write(lower_path_left.mnt);
out_unlock:
	if(branch_left){
		unlock_dir(lower_dir_dentry_left);
		dput(lower_dentry_left);
		u2fs_put_lower_path(dentry, &lower_path_left);
	}

	return err;

}

static int u2fs_symlink(struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	u2fs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;
	err = u2fs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

static int u2fs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	int branch_left = 0;
	int branch_right = 0;

	u2fs_get_lower_path_left(dentry, &lower_path);
	if(lower_path.dentry){
		lower_dentry = lower_path.dentry;
		lower_parent_dentry = lock_parent(lower_dentry);
		err = mnt_want_write(lower_path.mnt);
		branch_left = 1;
		if (err)
			goto out_unlock;

		err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
		if (err)
			goto out;

		err = u2fs_interpose_new(dentry, dir->i_sb, &lower_path, NULL);
		if (err)
			goto out;

		fsstack_copy_attr_times(dir, u2fs_lower_inode_left(dir));
		fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
		/* update number of links on parent directory */
		set_nlink(dir, u2fs_lower_inode_left(dir)->i_nlink);
	}else{
		u2fs_get_lower_path_right(dentry, &lower_path);
		if(lower_path.dentry){
			err = -EPERM;
			branch_right = 0;
		}
	}

out:
	if(lower_path.dentry)
		mnt_drop_write(lower_path.mnt);
out_unlock:
	if(branch_left){
		unlock_dir(lower_parent_dentry);
		u2fs_put_lower_path(dentry, &lower_path);
	}
	if(branch_right)
		u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

static int u2fs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	int branch_left = 0;
	int branch_right = 0;

	struct path lower_path_left;
	struct path lower_path_right;
	struct dentry *lower_dentry_left;

	struct dentry *lower_dir_dentry_left;
	struct dentry *lower_dir_dentry_right = NULL;

	u2fs_get_lower_path_left(dentry, &lower_path_left);
	u2fs_get_lower_path_right(dentry, &lower_path_right);

	if(lower_path_left.dentry){
		lower_dentry_left = lower_path_left.dentry;
		lower_dir_dentry_left = lock_parent(lower_dentry_left);

		err = mnt_want_write(lower_path_left.mnt);
		branch_left = 1;
		if (err)
			goto out_unlock;

		err = vfs_rmdir(lower_dir_dentry_left->d_inode, lower_dentry_left);
		if (err)
			goto out;

		d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
		if (dentry->d_inode)
			clear_nlink(dentry->d_inode);
		fsstack_copy_attr_times(dir, lower_dir_dentry_left->d_inode);
		fsstack_copy_inode_size(dir, lower_dir_dentry_left->d_inode);
		set_nlink(dir, lower_dir_dentry_left->d_inode->i_nlink);

	}else if(lower_path_right.dentry){
		err = create_whiteout(dentry);
		branch_right = 0;
	}


out:
	if(branch_left)
		mnt_drop_write(lower_path_left.mnt);
	if(branch_right)
		mnt_drop_write(lower_path_right.mnt);
out_unlock:
	if(branch_left){
		unlock_dir(lower_dir_dentry_left);
		u2fs_put_lower_path(dentry, &lower_path_left);
	}
	if(branch_right){
		unlock_dir(lower_dir_dentry_right);
		u2fs_put_lower_path(dentry, &lower_path_right);
	}
	return err;
}

static int u2fs_mknod(struct inode *dir, struct dentry *dentry, int mode,
		dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	u2fs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = u2fs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in u2fs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int u2fs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	u2fs_get_lower_path(old_dentry, &lower_old_path);
	u2fs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
				lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	u2fs_put_lower_path(old_dentry, &lower_old_path);
	u2fs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int u2fs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	u2fs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
			!lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
			buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *u2fs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = u2fs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

/* this @nd *IS* still used */
static void u2fs_put_link(struct dentry *dentry, struct nameidata *nd,
		void *cookie)
{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
}

static int u2fs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err = 0;

	if(u2fs_lower_inode_left(inode)){
		lower_inode = u2fs_lower_inode_left(inode);
		err = inode_permission(lower_inode, mask);
	}

	if(u2fs_lower_inode_right(inode)){
		lower_inode = u2fs_lower_inode_right(inode);
		err = inode_permission(lower_inode, mask);
	}
	return err;
}

/*
 * Modified for sys calls that changes attributes (for example chmod).
 * returning -EPERM for right branch
 */
static int u2fs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	int branch_left = 0;
	int branch_right = 0;
	struct dentry *lower_dentry = NULL;
	struct inode *inode;
	struct inode *lower_inode = NULL;
	struct path lower_path;
	struct iattr lower_ia;

	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	u2fs_get_lower_path_left(dentry, &lower_path);
	if(lower_path.dentry){
		lower_dentry = lower_path.dentry;
		lower_inode = u2fs_lower_inode_left(inode);
		branch_left = 1;
	}else{
		u2fs_get_lower_path_right(dentry, &lower_path);
		if(lower_path.dentry){

			err = -EPERM;
			goto out_err;
		}
	}

	if(lower_dentry){
		memcpy(&lower_ia, ia, sizeof(lower_ia));
		if (ia->ia_valid & ATTR_FILE){
			if(branch_left)
				lower_ia.ia_file = u2fs_lower_file_left(ia->ia_file);
			if(branch_right)
				lower_ia.ia_file = u2fs_lower_file_right(ia->ia_file);
		}

		/*
		 * If shrinking, first truncate upper level to cancel writing dirty
		 * pages beyond the new eof; and also if its' maxbytes is more
		 * limiting (fail with -EFBIG before making any change to the lower
		 * level).  There is no need to vmtruncate the upper level
		 * afterwards in the other cases: we fsstack_copy_inode_size from
		 * the lower level.
		 */
		if (ia->ia_valid & ATTR_SIZE) {
			err = inode_newsize_ok(inode, ia->ia_size);
			if (err)
				goto out;
			truncate_setsize(inode, ia->ia_size);
		}

		/*
		 * mode change is for clearing setuid/setgid bits. Allow lower fs
		 * to interpret this in its own way.
		 */
		if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
			lower_ia.ia_valid &= ~ATTR_MODE;

		/* notify the (possibly copied-up) lower inode */
		/*
		 * Note: we use lower_dentry->d_inode, because lower_inode may be
		 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
		 * tries to open(), unlink(), then ftruncate() a file.
		 */
		mutex_lock(&lower_dentry->d_inode->i_mutex);
		err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
		if (err)
			goto out;

		/* get attributes from the lower inode */
		fsstack_copy_attr_all(inode, lower_inode);
		/*
		 * Not running fsstack_copy_inode_size(inode, lower_inode), because
		 * VFS should update our inode size, and notify_change on
		 * lower_inode should update its size.
		 */
	}
out:
	u2fs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

const struct inode_operations u2fs_symlink_iops = {
	.readlink	= u2fs_readlink,
	.permission	= u2fs_permission,
	.follow_link	= u2fs_follow_link,
	.setattr	= u2fs_setattr,
	.put_link	= u2fs_put_link,
};

const struct inode_operations u2fs_dir_iops = {
	.create		= u2fs_create,
	.lookup		= u2fs_lookup,
	.link		= u2fs_link,
	.unlink		= u2fs_unlink,
	.symlink	= u2fs_symlink,
	.mkdir		= u2fs_mkdir,
	.rmdir		= u2fs_rmdir,
	.mknod		= u2fs_mknod,
	.rename		= u2fs_rename,
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};

const struct inode_operations u2fs_main_iops = {
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};
