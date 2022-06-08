//
// Created by Kondeti Rama Aiswarya on 4/29/22.
//
#include "includes.h"

//https://stackoverflow.com/questions/22186006/locks-required-for-vfs-rename
int rename(struct file *old, struct file *new)
{
    int err;
    struct dentry *old_dir_dentry = NULL, *new_dir_dentry =
            NULL, *res = NULL;

    old_dir_dentry = dget_parent(old->f_path.dentry);
    new_dir_dentry = dget_parent(new->f_path.dentry);

    res = lock_rename(old_dir_dentry, new_dir_dentry);
    if (res == new->f_path.dentry) {
        XDBG("New path is not empty or same file exists.");
        err = -ENOTEMPTY;
        goto out;
    }
    if (res == old->f_path.dentry) {
        XDBG("old file doesnot exsist.");
        err = -EINVAL;
        goto out;
    }
    err = vfs_rename(old_dir_dentry->d_inode, old->f_path.dentry, new_dir_dentry->d_inode, new->f_path.dentry, NULL,0);
out:
    dput(old_dir_dentry);
    dput(new_dir_dentry);
    unlock_rename(new_dir_dentry, old_dir_dentry);
    return err;
}

int renameWrapper(char *old, char *newFile){
    int err = 0;
    struct file *oldFilePtr, *newFilePtr;
    int inFileMode = 0;

    err = getInFilePtr(old, &oldFilePtr);

    if(err){
        XDBG("Error in getting old file name and path.");
        goto out;
    }

    inFileMode = getInputFileMode(old);

    if(inFileMode < 0){
        XDBG("Error in getting old file mode.");
        goto out;
    }

    err  = getOutFilePtr(newFile, &newFilePtr, inFileMode);

    if(err){
        XDBG("Error in getting new file path.");
        goto out;
    }
    err = rename(oldFilePtr, newFilePtr);
out:
    if(oldFilePtr)
        filp_close(oldFilePtr, NULL);
    if(newFilePtr)
        filp_close(newFilePtr, NULL);

    return err;
}
