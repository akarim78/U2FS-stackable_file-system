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
#include <linux/module.h>

#define DEBUG 1

/*
 * filling inode with lower inodes (left and right) and copying properties.
 * (from unionfs)
 */

static void u2fs_fill_inode(struct dentry *dentry,
		struct inode *inode)
{
	struct inode *lower_inode;
	struct dentry *lower_dentry;
	BUG_ON(!dentry);
	BUG_ON(!inode);

	lower_dentry = U2FS_D(dentry)->lower_path_left.dentry;
	lower_inode = lower_dentry->d_inode;
	u2fs_set_lower_inode_left(inode, lower_inode);

	lower_dentry = U2FS_D(dentry)->lower_path_right.dentry;
	lower_inode = lower_dentry->d_inode;
	u2fs_set_lower_inode_right(inode, lower_inode);

	lower_dentry = U2FS_D(dentry)->lower_path.dentry;
	lower_inode = lower_dentry->d_inode;
	u2fs_set_lower_inode(inode, lower_inode);

	lower_inode = u2fs_lower_inode_left(inode);

	/* Use different set of inode ops for symlinks & directories */
	if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &u2fs_symlink_iops;
	else if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &u2fs_dir_iops;

	/* Use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &u2fs_dir_fops;

	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
			S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
				lower_inode->i_rdev);

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
}

/*
 * There is no need to lock the u2fs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int u2fs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	struct super_block *lower_sb_left;
	struct super_block *lower_sb_right;
	struct path lower_path_left;
	struct path lower_path_right;

	char *dev_name = (char *) raw_data;
	struct inode *inode = NULL;
	char *optname;
	int ldirfound = 0;
	int rdirfound = 0;
  int pcount = 0;
	

	char *temp_path = NULL;

	if (!dev_name) {
		printk(KERN_ERR
				"u2fs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	if(DEBUG)
		printk(KERN_INFO "u2fs: read_super: dev_name: %s\n", dev_name);

	
	/* parse options to get paths */
	while((optname = strsep(&dev_name, ",")) != NULL){
		char *optarg;
		if(!optname || !*optname)
			continue;
		if(DEBUG)
			printk(KERN_INFO "u2fs: u2fs_parse_options: optname: %s\n", optname);
		optarg = strchr(optname, '=');
		if(optarg)
			*optarg++ = '\0';

		if (!optarg) {
			printk(KERN_ERR "u2fs: %s requires an argument\n",
					optname);
			err = -EINVAL;
			goto out;
		}
		if(!strcmp("ldir", optname)){
			if(++ldirfound > 1){
				printk(KERN_ERR "u2fs: multiple ldir specified\n");
				err = -EINVAL;
				goto out_error;
			}

			if(DEBUG)
				printk(KERN_INFO "u2fs: u2fs_parse_options: optname(ldir): %s, %s\n", optname, optarg);
			temp_path = optarg;
			err = kern_path(optarg, LOOKUP_FOLLOW, &lower_path_left);
			if (err) {
				printk(KERN_ERR "u2fs: error accessing lower directory '%s' (error %d)\n", optarg, err);
				goto out_error;
			}
		}

		if(!strcmp("rdir", optname)){
			if(++rdirfound > 1){
				printk(KERN_ERR "u2fs: multiple rdir specified\n");
				err = -EINVAL;
				goto out_error;
			}
			if(DEBUG)
				printk(KERN_INFO "u2fs: u2fs_parse_options: optname(rdir): %s, %s\n", optname, optarg);
			err = kern_path(optarg, LOOKUP_FOLLOW, &lower_path_right);
			if (err) {
				printk(KERN_ERR "u2fs: error accessing lower directory '%s' (error %d)\n", optarg, err);
				goto out_error;
			}

		}

	}

	if(ldirfound == 0 || rdirfound == 0){
		printk(KERN_ERR "u2fs: left or right directory specified\n");
		err = -EINVAL;
		goto out_error;
	}

	// from wrapfs
	err = kern_path(temp_path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"u2fs: error accessing "
				"lower directory '%s'\n", temp_path);
		goto out;
	}
  pcount =1;
	/* Allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct u2fs_sb_info), GFP_KERNEL);
	if (!U2FS_SB(sb)) {
		printk(KERN_CRIT "u2fs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out;
	}

	/*
	 * getting lower dentries(left and right), increment refcnt and
	 * setting lower sbs(left and right) from lower dentries
	 */

	lower_sb_left = lower_path_left.dentry->d_sb;
	atomic_inc(&lower_sb_left->s_active);
	u2fs_set_lower_super_left(sb, lower_sb_left);

	lower_sb_right = lower_path_right.dentry->d_sb;
	atomic_inc(&lower_sb_right->s_active);
	u2fs_set_lower_super_right(sb, lower_sb_right);

	/*
	 * set the lower superblock field of upper superblock
	 * for compatibility with unimplemented features
	 */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	u2fs_set_lower_super(sb, lower_sb);
	/* max Bytes is the maximum bytes from highest priority branch (LB)*/
	sb->s_maxbytes = u2fs_lower_super_left(sb)->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.  This is important for our
	 * time-based cache coherency.
	 */
	sb->s_time_gran = 1;
	sb->s_op = &u2fs_sops;

	/* get a new inode and allocate our root dentry */
	inode = u2fs_iget_root(sb, iunique(sb, U2FS_ROOT_INO));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}

	/* populate root dentry and inode */
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}

	d_set_d_op(sb->s_root, &u2fs_dops);
	sb->s_root->d_fsdata = NULL;

	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	u2fs_set_both_lower_path(sb->s_root, &lower_path, &lower_path_left, &lower_path_right);
	if (atomic_read(&inode->i_count) <= 1)
		u2fs_fill_inode(sb->s_root, inode);
	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
				"u2fs: mounted on top of %s type %s\n",
				dev_name, lower_sb->s_type->name);

	goto out; /* all is well */

out_freeroot:
	free_dentry_private_data(sb->s_root);
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	atomic_dec(&lower_sb->s_active);
	atomic_dec(&lower_sb_left->s_active);
	atomic_dec(&lower_sb_right->s_active);
	kfree(U2FS_SB(sb));
	sb->s_fs_info = NULL;

out_error:
     UDBG;
     if (pcount)
	       path_put(&lower_path);
     if (ldirfound)   
	       path_put(&lower_path_left);
     if (rdirfound)
	       path_put(&lower_path_right);

out:
	return err;
}

struct dentry *u2fs_mount(struct file_system_type *fs_type, int flags,
		const char *dev_name, void *raw_data)
{
	struct dentry *dentry;
	void *lower_path_name = (void *) raw_data;
	printk(KERN_INFO "u2fs: u2fs_mount: mounting u2fs: dev_name: %s raw_data: %s\n", dev_name, (char *)raw_data);
	dentry =  mount_nodev(fs_type, flags, lower_path_name,
			u2fs_read_super);
	if (!IS_ERR(dentry)){
		U2FS_SB(dentry->d_sb)->dev_name = kstrdup(dev_name, GFP_KERNEL);
	}

	return dentry;
}

static struct file_system_type u2fs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= U2FS_NAME,
	.mount		= u2fs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_u2fs_fs(void)
{
	int err;

	pr_info("Registering u2fs " U2FS_VERSION "\n");
	err = u2fs_init_inode_cache();
	if (err)
		goto out;
	err = u2fs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&u2fs_fs_type);
out:
	if (err) {
		u2fs_destroy_inode_cache();
		u2fs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_u2fs_fs(void)
{
	u2fs_destroy_inode_cache();
	u2fs_destroy_dentry_cache();
	unregister_filesystem(&u2fs_fs_type);
	pr_info("Completed u2fs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
		" (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("U2fs " U2FS_VERSION
		" (http://u2fs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_u2fs_fs);
module_exit(exit_u2fs_fs);
