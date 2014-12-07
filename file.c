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

static ssize_t u2fs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	if (U2FS_D(dentry)->lower_path_left.dentry)
		lower_file = u2fs_lower_file_left (file);


	if (U2FS_D(dentry)->lower_path_right.dentry)
		lower_file = u2fs_lower_file_right (file);


	if (lower_file) {
		err = vfs_read (lower_file, buf, count, ppos);
		/* update our inode atime upon a successful lower read */
		if (DEBUG)
			printk(KERN_INFO "u2fs: u2fs_read: calling vfs_read for lower %d\n", err);
		if (err >= 0)
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}
	return err;
}

static ssize_t u2fs_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	if (U2FS_D(dentry)->lower_path_left.dentry)
		lower_file = u2fs_lower_file_left(file);
	else if (U2FS_D(dentry)->lower_path_right.dentry) {
		lower_file = u2fs_lower_file_right(file);
		err = -EPERM;
		goto out;
	}

	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

out:
	return err;
}

static int u2fs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	if (U2FS_D(dentry)->lower_path_left.dentry) {
		lower_file = u2fs_lower_file_left(file);
		if (lower_file) {
			err = vfs_readdir(lower_file, filldir, dirent);
			file->f_pos = lower_file->f_pos;
			if (err >= 0)
				/* copy the atime */
				fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

		}
	}

	if (U2FS_D(dentry)->lower_path_right.dentry) {
		lower_file = u2fs_lower_file_right(file);
		if (lower_file) {
			err = vfs_readdir(lower_file, filldir, dirent);
			file->f_pos = lower_file->f_pos;
			if (err >= 0)
				/* copy the atime */
				fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

		}
	}

	return err;
}

static long u2fs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = u2fs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long u2fs_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = u2fs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int u2fs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = u2fs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "u2fs: lower file system does not "
				"support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!U2FS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "u2fs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "u2fs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed (file);
	vma->vm_ops = &u2fs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &u2fs_aops; /* set our aops */
	if (!U2FS_F(file)->lower_vm_ops) /* save for our ->fault */
		U2FS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

/* u2fs_open helper function: open a directory */
static int __open_dir(struct inode *inode, struct file *file,
		struct dentry *parent)
{
	struct dentry *lower_dentry_left;
	struct dentry *lower_dentry_right;
	struct file *lower_file_left;
	struct file *lower_file_right;

	struct vfsmount *lower_mnt_left;
	struct vfsmount *lower_mnt_right;

	struct dentry *dentry = file->f_path.dentry;
	if (!parent) {
		parent=dentry->d_parent;
	}

	lower_dentry_left = U2FS_D(dentry)->lower_path_left.dentry;
	if (lower_dentry_left) {
		dget(lower_dentry_left);
		if (DEBUG)
			printk(KERN_INFO "u2fs: __open_dir: lower left: %s\n",
				lower_dentry_left->d_name.name);

		lower_mnt_left = mntget(U2FS_D(dentry)->lower_path_left.mnt);
		if (!lower_mnt_left)
			if(U2FS_D(parent)->lower_path_left.mnt)
			lower_mnt_left = 
				mntget(U2FS_D(parent)->lower_path_left.mnt);


		lower_file_left = dentry_open(lower_dentry_left,
			lower_mnt_left, file->f_flags,
				current_cred());

		if (IS_ERR(lower_file_left))
			return PTR_ERR(lower_file_left);

		u2fs_set_lower_file_left(file, lower_file_left);
		if (!mntget(U2FS_D(dentry)->lower_path_left.mnt))
			U2FS_D(dentry)->lower_path_left.mnt = lower_mnt_left;

	}

	lower_dentry_right = U2FS_D(dentry)->lower_path_right.dentry;
	if (lower_dentry_right) {
		dget(lower_dentry_right);
		if (DEBUG)
			printk(KERN_INFO "u2fs: __open_dir: lower right: %s\n",
				lower_dentry_right->d_name.name);

		lower_mnt_right = mntget(U2FS_D(dentry)->lower_path_right.mnt);

		if (!lower_mnt_right)
			if(U2FS_D(parent)->lower_path_right.mnt)
				lower_mnt_right = mntget(U2FS_D(parent)->
					lower_path_right.mnt);



		lower_file_right = dentry_open(lower_dentry_right, 
			lower_mnt_right, file->f_flags,
				current_cred());
		if (IS_ERR(lower_file_right))
			return PTR_ERR(lower_file_right);


		u2fs_set_lower_file_right(file, lower_file_right);
		if (!mntget(U2FS_D(dentry)->lower_path_right.mnt))
			U2FS_D(dentry)->lower_path_right.mnt = 
				lower_mnt_right;

	}

	return 0;
}

/* u2fs_open helper function: open a file */
static int __open_file(struct inode *inode, struct file *file,
		struct dentry *parent)
{
	struct dentry *lower_dentry_left;
	struct dentry *lower_dentry_right;
	struct file *lower_file_left;
	struct file *lower_file_right;

	struct vfsmount *lower_mnt_left;
	struct vfsmount *lower_mnt_right;
	int lower_flags_left;
	int lower_flags_right;
	//int err = 0;
	struct dentry *dentry = file->f_path.dentry;

	lower_dentry_left = U2FS_D(dentry)->lower_path_left.dentry;
	lower_flags_left = file->f_flags;

	if (lower_dentry_left) {
		if(lower_dentry_left->d_inode) {
			dget(lower_dentry_left);
			if(DEBUG)
				printk(KERN_INFO "u2fs: __open_file: lower left: %s\n",
					lower_dentry_left->d_name.name);

			lower_mnt_left = mntget(U2FS_D(dentry)->lower_path_left.mnt);
			lower_file_left = dentry_open(lower_dentry_left,
					lower_mnt_left, file->f_flags, current_cred());

			if (IS_ERR(lower_file_left))
				return PTR_ERR(lower_file_left);

			u2fs_set_lower_file_left(file, lower_file_left);
		}
	}

	lower_dentry_right = U2FS_D(dentry)->lower_path_right.dentry;
	lower_flags_right = file->f_flags;

	if (lower_dentry_right)
	{
		if (lower_dentry_right->d_inode) {
			dget(lower_dentry_right);
			if (DEBUG)
				printk(KERN_INFO "u2fs: __open_file: lower right: %s\n",
					lower_dentry_right->d_name.name);

			lower_mnt_right = mntget(U2FS_D(dentry)->lower_path_right.mnt); 
			lower_file_right = dentry_open(lower_dentry_right,
				lower_mnt_right, file->f_flags, current_cred());

			if (IS_ERR(lower_file_right))
				return PTR_ERR(lower_file_right);

			u2fs_set_lower_file_right(file, lower_file_right);
		}
	}

	return 0;
}

static int u2fs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *parent = NULL;
	int size;
	struct dentry *dentry = file->f_path.dentry;

	if (DEBUG)
		printk(KERN_INFO "u2fs: u2fs_open: opening a file %s\n",
			dentry->d_name.name);

	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct u2fs_file_info), GFP_KERNEL);
	if (!U2FS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	size = sizeof(struct file *);
	U2FS_F(file)->lower_file_left = kzalloc(size, GFP_KERNEL);
	if (!U2FS_F(file)->lower_file_left) {
		err = -ENOMEM;
		goto out_err;
	}

	U2FS_F(file)->lower_file_right = kzalloc(size, GFP_KERNEL);
	if (!U2FS_F(file)->lower_file_right) {
		err = -ENOMEM;
		goto out_err;
	}

	if (S_ISDIR(inode->i_mode))
		err = __open_dir(inode, file, parent); /* open a dir */
	else
		err = __open_file(inode, file, parent);	/* open a file */

	/* freeing the allocated resources, and fput the opened files */
	if (err) {
		lower_file = u2fs_lower_file_left(file);
		if (lower_file)
			fput(lower_file);
		lower_file = u2fs_lower_file_right(file);
		if (lower_file)
			fput(lower_file);
	}

	if (err)
		kfree(U2FS_F(file));
	else {
		if (u2fs_lower_inode_left(inode))
			fsstack_copy_attr_all(inode,
				u2fs_lower_inode_left(inode));
		if (u2fs_lower_inode_right(inode))
			fsstack_copy_attr_all(inode,
				u2fs_lower_inode_right(inode));
	}

out_err:
	return err;
}

static int u2fs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = u2fs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	return err;
}

/* release all lower object references & free the file info structure */
static int u2fs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = u2fs_lower_file(file);
	if (lower_file) {
		u2fs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(U2FS_F(file));
	return 0;
}

static int u2fs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = u2fs_lower_file(file);
	u2fs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	u2fs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int u2fs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = u2fs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations u2fs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= u2fs_read,
	.write		= u2fs_write,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.mmap		= u2fs_mmap,
	.open		= u2fs_open,
	.flush		= u2fs_flush,
	.release	= u2fs_file_release,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};

/* trimmed directory options */
const struct file_operations u2fs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= u2fs_readdir,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.open		= u2fs_open,
	.release	= u2fs_file_release,
	.flush		= u2fs_flush,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};
