#include "includes.h"
//
// Created by Kondeti Rama Aiswarya on 4/29/22.
//
int getCheckSum(struct file *inFilePtr, char *checkSum){
    int err = 0, err1=0, inFileSize = 0;
    char *buff;
    u32 cycRedCheck = 0;
    mm_segment_t oldfs;

    (inFilePtr)->f_pos = 0;
    buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buff) {
        err = -ENOMEM;
        printk(KERN_ERR "Unable to allocate space for in_Buffer : Buffer to read from input file\n");
        goto out;
    }
    memset((buff), 0, PAGE_SIZE);
    cycRedCheck = crc32(0L, NULL, 0);
    inFileSize = (unsigned int)inFilePtr->f_path.dentry->d_inode->i_size;

    while (inFileSize > 0) {
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        err1 = vfs_read(inFilePtr, buff, PAGE_SIZE, &inFilePtr->f_pos);
        if(err1 < 0){
            XDBG("Error in reading file");
            err = err1;
            goto out;
        }
        inFileSize = inFileSize - err1;
        cycRedCheck = crc32(cycRedCheck, buff, err1);
        set_fs(oldfs);
    }

    /* Convert checksum to string */
    sprintf(checkSum, "%0X", cycRedCheck);
    printk("checksum is %s", checkSum);
    out:
    filp_close(inFilePtr, NULL);
    if(buff)
        kfree(buff);
    return err;
}

int getCheckSumWrapper(char *inFile, char *checkSum){
    int err = 0;
    struct file *inFilePtr;
    err = getInFilePtr(inFile, &inFilePtr);
    if(err)
        goto out;
    printk("getting check sum");
    err = getCheckSum(inFilePtr, checkSum);
    if(err)
        goto out;
    XDBG(checkSum);
    out:
    return err;
}
