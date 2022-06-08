#include "includes.h"
#include "fileops.h"
/*
 Created by Kondeti Rama Aiswarya on 4/29/22.
*/


/* Function to concat two input files into the output file */
int concat(filename *infiles, int files_len, char *outfile)
{
    int err = 0;
    struct file *in_filps[10] , *out_filp = NULL;
    mm_segment_t oldfs;
    int bytes_read = 0, bytes_write = 0;
    char *read_buf = NULL;
    int infile_size = 0;
    int ret = 0, i;

    for(i = 0; i < files_len; i++){
        in_filps[i] = NULL;
    }
    /* Check file validations and file pointers of input and output files */
    for(i = 0; i < files_len; i++){
        err = checkFile(infiles[i].name, 0);
        if (err) {
            printk(KERN_ERR	"Line no.:[%d] ERROR! function file_validations fails, err: %d\n", __LINE__, err);
            goto out;
        }
    }
    err = checkFile(outfile, 1);

    if (err) {
        printk(KERN_ERR	"Line no.:[%d] ERROR! function file_validations fails, err: %d\n", __LINE__, err);
        goto out;
    }

    for(i = 0; i < files_len; i++){
        err = getInFilePtr(infiles[i].name, &(in_filps[i]));
        if(err)
            goto out;
    }

    err = getInputFileMode(infiles[0].name);

    if(err < 0)
        goto out;

    err = getOutFilePtr(outfile, &out_filp, err);

    if(err)
        goto out;

    /* Call concat function, which reads data in PAGE_SIZE -> writes it to output file */
    read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    /* Allocate memory for read buffer, used for reading data from input file in blocks of PAGE_SIZE*/
    if (!read_buf) {
        printk(KERN_ERR	"Line no.:[%d] ERROR!! No memory allocated to read_buf buffer\n", __LINE__);
        ret = -ENOMEM;
        goto out;
    }
    out_filp->f_pos = 0;

    for(i = 0; i < files_len; i++){
        /* Start offset */
        in_filps[i]->f_pos = 0;


        /* Get the size of input file */
        infile_size = in_filps[i]->f_inode->i_size;

        /* Run loop till end of the input file 1 */
        while (in_filps[i]->f_pos < infile_size) {
            /* Read data in blocks of PAGE_SIZE from input file 1 */
            oldfs = get_fs();
            set_fs(KERNEL_DS);
            memset(read_buf, 0, PAGE_SIZE);
            bytes_read = vfs_read(in_filps[i], read_buf, PAGE_SIZE,
                                  &in_filps[i]->f_pos);
            set_fs(oldfs);

            /* Check if there is error in reading data from input file 1 */
            if (bytes_read < 0) {
                printk(KERN_ERR	"Line no.:[%d] ERROR in reading data from input file 1, bytes_read: %d\n", __LINE__, bytes_read);
                ret = bytes_read;
                goto out;
            }

            /* Write data block in output file */
            oldfs = get_fs();
            set_fs(KERNEL_DS);
            bytes_write = vfs_write(out_filp, read_buf, bytes_read,
                                    &out_filp->f_pos);
            set_fs(oldfs);

            /* Check if there is error in writing data to o/p file */
            if (bytes_write < bytes_read) {
                printk(KERN_ERR	"Line no.:[%d] ERROR in writing data to output file, bytes_write: %d\n", __LINE__, bytes_write);
                ret = bytes_write;
                goto out;
            }
        }
    }
    err = ret;
    if (err) {
        printk(KERN_ERR	"Line no.:[%d] ERROR! function concat_files fails, ret: %d\n", __LINE__, err);
        goto out;
    }

    out:
    for( i = 0; i < files_len ; i++){
        if (in_filps[i] && !IS_ERR(in_filps[i]))
            filp_close(in_filps[i], NULL);
    }
    if (out_filp && !IS_ERR(out_filp))
        filp_close(out_filp, NULL);
    if(read_buf)
        kfree(read_buf);
    return err;
}


