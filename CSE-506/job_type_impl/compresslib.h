#include "includes.h"

#define outFileSizeDigitsCount  2
#define outFileSizeDigits  10

static int get_outbufLen_to_decompress(struct file *inFilePtr) {
    int readBytes, err = 0, digitCountInt, outbufLenInt;
    char digitCount[outFileSizeDigitsCount], outbufLen[outFileSizeDigits];

    readBytes = vfs_read(inFilePtr, digitCount, outFileSizeDigitsCount-1, &inFilePtr->f_pos);
    if (readBytes <= 0) {
        XDBG("Cannot Read . No Data ");
        err = -ENODATA;
        goto out;
    }
    digitCount[outFileSizeDigitsCount - 1] = '\0';
    err = kstrtoint(digitCount, outFileSizeDigits, &digitCountInt);
    if (err){
        XDBG("Str to Int conversion error in digit Count");
        goto out;
    }
    readBytes = vfs_read(inFilePtr, outbufLen, digitCountInt, &inFilePtr->f_pos);
    if (readBytes <= 0) {
        XDBG("Cannot Read . No Data ");
        err = -ENODATA;
        goto out;
    }
    outbufLen[digitCountInt] = '\0';
    XDBG(outbufLen);
    err = kstrtoint(outbufLen, outFileSizeDigits, &outbufLenInt);
    if (err) {
        XDBG("Str to Int conversion error in outBufLen");
        goto out;
    }
    return outbufLenInt;
out:
    return err;
}

static int decompresswrap(struct file *inFilePtr, struct file *outFilePtr,
                          struct crypto_comp *tfm) {
    char *inBuf = NULL, *outBuf = NULL;
    int err = 0, outbufLen_to_read, readBytes, outBuf_len = PAGE_SIZE;

    inBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!inBuf) {
        XDBG("No Memory for in Buffer");
        err = -ENOMEM;
        goto out;
    }
    outBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!outBuf) {
        XDBG("No Memory for out Buffer");
        err = -ENOMEM;
        goto out;
    }
    XDBG("Trying to decompress");
    outbufLen_to_read = get_outbufLen_to_decompress(inFilePtr);
    if (outbufLen_to_read == -ENODATA) {
        XDBG("No Data to convert");
        err = -EINVAL;
        goto out;
    } else if (outbufLen_to_read < 0) {
        XDBG("Error reading bytes to decompress");
        err = outbufLen_to_read;
        goto out;
    }
    printk("to read : %d\n", outbufLen_to_read);
    while ((readBytes = vfs_read(inFilePtr, inBuf, outbufLen_to_read,
                                 &inFilePtr->f_pos)) > 0) {
        crypto_comp_decompress(tfm, inBuf, readBytes, outBuf,
                               &outBuf_len);

        vfs_write(outFilePtr, outBuf, outBuf_len,
                  &outFilePtr->f_pos);

        outbufLen_to_read = get_outbufLen_to_decompress(inFilePtr);
        if (outbufLen_to_read == -ENODATA) {
            XDBG("No Data to convert");
            goto out;
        } else if (outbufLen_to_read < 0) {
            XDBG("Error reading bytes to decompress");
            err = outbufLen_to_read;
            goto out;
        }
    }
out:
    if(inBuf)
        kfree(inBuf);
    if(outBuf)
        kfree(outBuf);
    return err;
}

static int compresswrap(struct file *inFilePtr, struct file *outFilePtr,
                        struct crypto_comp *tfm) {
    char *inBuf = NULL, *outBuf = NULL;
    int err = 0, readBytes, outBuf_len = PAGE_SIZE;
    char digitCount[outFileSizeDigitsCount], outbufLen[outFileSizeDigits];

    inBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (inBuf == NULL) {
        XDBG("No Memory for out Buffer");

        err = -ENOMEM;
        goto out;
    }
    outBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!outBuf) {
        XDBG("No Memory for out Buffer");

        err = -ENOMEM;
        goto out;
    }

    while ((readBytes = vfs_read(inFilePtr, inBuf, PAGE_SIZE, &inFilePtr->f_pos)) > 0) {
        crypto_comp_compress(tfm, inBuf, readBytes, outBuf,
                             &outBuf_len);
        snprintf(outbufLen, outFileSizeDigits, "%d", outBuf_len);
        snprintf(digitCount, outFileSizeDigitsCount, "%ld", strlen(outbufLen));

        vfs_write(outFilePtr, digitCount, outFileSizeDigitsCount - 1,
                  &outFilePtr->f_pos);
        vfs_write(outFilePtr, outbufLen, strlen(outbufLen),
                  &outFilePtr->f_pos);
        vfs_write(outFilePtr, outBuf, outBuf_len,
                  &outFilePtr->f_pos);
    }

    out:
    if(inBuf)
        kfree(inBuf);
    if(outBuf)
        kfree(outBuf);
    return err;
}

int compress(char *algo, char *inFile, char *outfile, int flag) {
    int err = 0;
    struct file *inFilePtr, *outFilePtr;
    struct crypto_comp *tfm = NULL;
    mm_segment_t fs = get_fs();

    err = getInFilePtr(inFile, &inFilePtr);

    if (err < 0)
        goto out;

    err = getInputFileMode(inFile);

    if (err < 0)
        goto out;

    err = getOutFilePtr(outfile, &outFilePtr, err);

    if (err)
        goto out;

    tfm = crypto_alloc_comp(algo, 0, 0);

    if (!tfm || IS_ERR(tfm)) {
        printk("Cannot alloc crypto comp . please check if option enabled in conf\n");
        err = PTR_ERR(tfm);
        goto out;
    }

    set_fs(KERNEL_DS);

    if (!flag) {
        err = compresswrap(inFilePtr, outFilePtr, tfm);
        if (err) {
            XDBG("Failed to do compression");
        }
    } else {
        err = decompresswrap(inFilePtr, outFilePtr, tfm);
        if (err) {
            XDBG("Failed to do decompression");
        }
    }


    out:

    if (inFilePtr && !IS_ERR(inFilePtr))
        filp_close(inFilePtr, NULL);

    if (inFilePtr && !IS_ERR(inFilePtr))
        filp_close(outFilePtr, NULL);

    if (tfm && !IS_ERR(tfm))
        crypto_free_comp(tfm);
    set_fs(fs);

    return err;
}

