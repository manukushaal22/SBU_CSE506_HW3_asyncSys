#include "includes.h"

//
// Created by Kondeti Rama Aiswarya on 4/30/22.
//
int unlink(struct file *filp)
{
    inode_lock_nested(filp->f_path.dentry->d_parent->d_inode, I_MUTEX_PARENT);
    if(vfs_unlink(filp->f_path.dentry->d_parent->d_inode, filp->f_path.dentry, NULL) < 0){
        XDBG("Unlink Failed");
        return -ENODATA;
    }
    inode_unlock(filp->f_path.dentry->d_parent->d_inode);
    return 0;
}

int unlinkWrapper(char *inFile){
    int err = 0;
    struct file *filePtr = NULL;

    err = getInFilePtr(inFile, &filePtr);
    if(err){
        XDBG("Error in getting old file name and path.");
        goto out;
    }
    err = unlink(filePtr);

out:
    if(filePtr)
        filp_close(filePtr, NULL);
    return err;

}
