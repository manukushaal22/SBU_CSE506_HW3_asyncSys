//
// Created by Kondeti Rama Aiswarya on 4/29/22.
//
#include "includes.h"


int getInputFileMode(char *inFile){
    int err = 0;
    struct kstat in_stat;
    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    /* Check if input file exist or not */

    vfs_stat(inFile, &in_stat);

    set_fs(oldfs);

    /* Check if input file is a regular file or not */
    err = in_stat.mode;
    return err;
}

int checkFile(char *fileName, int isOutFile){
    int err = 0;
    struct kstat in;
    mm_segment_t oldfs;

    if(isOutFile){
        XDBG("checking out file");
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    /* Checking if the input file exist. */
    err = vfs_stat(fileName, &in);
    /*if out file doesnot exist we can ignore the err. cause we will create*/
    if(isOutFile && err){
        return 0;
    }
    if (err) {
        XDBG(KERN_ERR
        "File Doesn't exist\n");
        goto out;
    }
    /* Checking if the input file is regular. */
    if (S_ISREG(in.mode) == 0) {
        err = -EBADF;
        XDBG(KERN_ERR
        "File is not a Regular File\n");
        goto out;
    }
    out:
    set_fs(oldfs);
    return err;
}
int getInFilePtr(char *infile, struct file **inFilePtr){
    int err = 0;
    *inFilePtr = filp_open(infile, O_RDONLY, 0);
    /* Checking if input file pointer is valid or not */
    if (!(*inFilePtr) || IS_ERR(*inFilePtr)) {
        printk(KERN_ERR	"Line no.:[%d] ERROR in opening input file 1 %d\n", __LINE__, (int)PTR_ERR(*inFilePtr));
        err = PTR_ERR(*inFilePtr);
        return err;
    }

    return 0;
}

int getOutFilePtr(char *outFile, struct file **outFilePtr, int infile_mode){
    int err = 0;
    *outFilePtr = filp_open(outFile, O_WRONLY | O_CREAT | O_TRUNC,
                          infile_mode);
    if (!(*outFilePtr) || IS_ERR(*outFilePtr)) {
        printk(KERN_ERR	"Line no.:[%d] ERROR in opening input file 1 %d\n", __LINE__, (int)PTR_ERR(outFilePtr));
        err = PTR_ERR(*outFilePtr);
        return err;
    }
    return 0;
}
