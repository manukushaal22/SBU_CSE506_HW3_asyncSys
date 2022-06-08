#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>

#if 1
#define XDBG(x) printk(KERN_DEFAULT "XDBG:%s:%s:%d  %s\n", __FILE__, __func__, __LINE__, x)
#else
#define XDBG(x)
#endif

struct cryptocopy_args {
    char* infile;
    char* outfile;
    void* keybuf;
    int keylen;
    int flags;
};

static int apply_skcipher(u8* data, size_t datasize, int encrypt, char* key, u8* iv);

static int md5_hash(char *result, const char* data, size_t len);

static int remove_file(struct file* filp);

static long cryptocopy(struct cryptocopy_args* c_args);



/*
 * This method overwrites file data with 0s and deletes it
 * INPUT:
 * filename:- path of file which must be deleted
 * Returns err code in cae of error, 0 on success
 */
static int secure_delete(char *filename) {
    int err, ret=0, buf_len;
    struct kstat infile_stat;
    struct file *in_filp = NULL;
    unsigned long long init_offset, cur_offset;
    char* buf = NULL;
    mm_segment_t old_fs = get_fs();

    if(filename == NULL) {
        return -1;
    }
    set_fs(KERNEL_DS);

    err = vfs_stat(filename, &infile_stat) ;
    if (err < 0) {
        XDBG("Problem with input file stats");
        ret = -ENOENT;
        goto out_secdel;
    }

    in_filp = filp_open(filename, O_RDWR, 0);
    if (IS_ERR(in_filp)) {
        XDBG("Can't open input file");
        ret = PTR_ERR(in_filp);
        goto out_secdel;
    }
    if(!S_ISREG(in_filp->f_inode->i_mode)){
        XDBG("Input file is not regular");
        ret = -EBADF;
        goto out_secdel;
    }

    init_offset = in_filp->f_pos;

    buf = (char*) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (buf == NULL) {
        XDBG("Cannot allocate mem for buffer");
        ret = -ENOMEM;
        goto out_secdel;
    }

    cur_offset = in_filp->f_pos;

    XDBG("Starting the file generating process");
    while(cur_offset < init_offset + infile_stat.size){

        /* logic to calculate remaining bytes of last page */
        buf_len = PAGE_SIZE;
        if ( infile_stat.size - cur_offset < PAGE_SIZE)
            buf_len = infile_stat.size - cur_offset;

        /* set buffer to zeros to overwrite the file */
        memset(buf, 0, buf_len);

        /* If we are in last page, set last byte to EOF */
        if(cur_offset + buf_len >= init_offset + infile_stat.size)
            buf[buf_len-1] = '\0';

        ret = vfs_write(in_filp, buf, buf_len, &cur_offset);
        if (ret < 0){
            XDBG("File write failed in loop");
            goto out_secdel;
        }
    }

    ret = remove_file(in_filp);
    if(ret < 0){
        XDBG("Unable to unlink");
    }

out_secdel:
    XDBG("cryptocopy error handling if any");

    if(NULL != buf)
        kfree(buf);
    if(NULL != in_filp && !IS_ERR(in_filp))
        filp_close(in_filp, NULL);
    set_fs(old_fs);
    return ret;
}

/*
 * This method collects args, forms a request and calls cryptocopy
 * INPUT:
 * infile: path of file which must be copied
 * outfile: path of file to which infile must be copied
 * flag: 1 for encrypt, 2 for decrypt, 4 for copy
 * keybuf: key for flag 1 and 2, NULL for flag 4
 * Returns err code in cae of error, 0 on success
 */
static long call_crypto(char* infile, char* outfile, int flag, char* keybuf){

    struct cryptocopy_args c_args;

    c_args.flags = flag;
    c_args.infile = infile;
    c_args.outfile = outfile;
    if (flag != 4){
        c_args.keybuf = keybuf;
        c_args.keylen = strlen(keybuf);
    }

    return cryptocopy(&c_args);
}

/*
 * Helper function to call cryptocopy
 * Returns err code in cae of error, 0 on success
 */
static long encrypt(char* infile, char* outfile, char* keybuf){
    
    if(infile == NULL || outfile == NULL || keybuf == NULL){
        return -1;
    }

    return call_crypto(infile, outfile, 1, keybuf);
}

/*
 * Helper function to call cryptocopy
 * Returns err code in cae of error, 0 on success
 */
static long decrypt(char* infile, char* outfile, char* keybuf){

    if(infile == NULL || outfile == NULL || keybuf == NULL){
        return -1;
    }

    return call_crypto(infile, outfile, 2, keybuf);
}

/*
 * Helper function to call cryptocopy
 * Returns err code in cae of error, 0 on success
 */
static long copy_file(char* infile, char* outfile){

    return call_crypto(infile, outfile, 4, NULL);
}

static void dummy(void){
    encrypt(NULL, NULL, NULL);
    decrypt(NULL, NULL, NULL);
    secure_delete(NULL);
}

/*
 * This method takes input file, processes a copy of it based on flags,
 * and generates the outputfile. Use the above helper functions to call this
 * Returns err code in cae of error, 0 on success
 */
static long cryptocopy(struct cryptocopy_args* c_args)
{
    int ret = 0, err, buf_len, keylen = 32;
    void* buf = NULL;
    struct kstat infile_stat;
    ssize_t res;
    char* key = NULL, *key_from_file = NULL;
    unsigned long long init_offset, cur_offset;
    u8* tmp = NULL;
    struct file *in_filp = NULL, *out_filp = NULL;
    mm_segment_t old_fs = get_fs();

    XDBG("cryptocopy syscall started");

    set_fs(KERNEL_DS);

    if (c_args->flags != 1 && c_args->flags != 2 && c_args->flags != 4){
        XDBG("Invalid input: flag not supported");
        ret = -EINVAL;
        goto err_handle;
    }

    printk("Input args: \nflag: %d\ninfile: %s\noutfile: %s", c_args->flags, c_args->infile, c_args->outfile);

    err = vfs_stat(c_args->infile, &infile_stat) ;
    dummy();
    if (err < 0) {
        XDBG("Problem with input file stats");
        ret = -ENOENT;
        goto err_handle;
    }

    in_filp = filp_open(c_args->infile, O_RDONLY, 0);
    if (IS_ERR(in_filp)) {
        XDBG("Can't open input file");
        ret = PTR_ERR(in_filp);
        goto err_handle;
    }
    if(!S_ISREG(in_filp->f_inode->i_mode)){
        XDBG("Input file is not regular");
        ret = -EBADF;
        goto err_handle;
    }

    init_offset = in_filp->f_pos;

    out_filp = filp_open(c_args->outfile, O_WRONLY|O_CREAT|O_TRUNC, infile_stat.mode);
    if (IS_ERR(out_filp)) {
        XDBG("Can't open output file");
        ret = PTR_ERR(out_filp);
        goto err_handle;
    }
    if (in_filp->f_inode == out_filp->f_inode) {
        XDBG("Output and Input cant be same");
        ret = -EPERM;
        goto err_handle;
    }

    buf = (void*) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (buf == NULL) {
        XDBG("Cannot allocate mem for buffer");
        ret = -ENOMEM;
        goto file_err_handle;
    }

    key = (char*) kmalloc(32, GFP_KERNEL);
    memset(key, '0', 31);
    key[31] = '\0';
    if (buf == NULL) {
        XDBG("Cannot allocate mem for key");
        ret = -ENOMEM;
        goto file_err_handle;
    }

    if (c_args->flags != 4) {
        XDBG("Generating hash for key");
        res = md5_hash(key, c_args->keybuf, 32);
        if(res < 0){
            XDBG("md5 hashing failed");
            ret = res;
            goto err_handle;
        }
    }

    tmp = (u8*) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(NULL == tmp) {
        XDBG("Failed to allocate temp buffer");
        ret = -ENOMEM;
        goto file_err_handle;
    }

    if(c_args->flags == 2){
        XDBG("Verifying decryption key...");

        key_from_file = (char*) kmalloc(keylen, GFP_KERNEL);
        if(NULL == key_from_file) {
            XDBG("No space to verify key");
            ret = -ENOMEM;
            goto err_handle;
        }

        res = vfs_read(in_filp, key_from_file, keylen, &in_filp->f_pos);
        if (res < 0){
            XDBG("File read failed");
            ret = res;
            goto file_err_handle;
        }

        if (strcmp(key, key_from_file) != 0) {
            printk("key verification fail %s %s", (char *)key, key_from_file);
            ret = -EACCES;
            goto file_err_handle;
        }

    } else if(c_args->flags == 1) {
        XDBG("Processing ecryption key...");

        res = vfs_write(out_filp, key, keylen, &out_filp->f_pos);
        if (res < 0){
            XDBG("File write failed");
            ret = res;
            goto file_err_handle;
        }
    }

    cur_offset = in_filp->f_pos;

    XDBG("Starting the file generating process");
    while(cur_offset < init_offset + infile_stat.size){

        /* logic to calculate remaining bytes of last page */
        buf_len = PAGE_SIZE;
        if ( infile_stat.size - cur_offset < PAGE_SIZE)
            buf_len = infile_stat.size - cur_offset;

        res = vfs_read(in_filp, buf, PAGE_SIZE, &cur_offset);
        if (res < 0){
            XDBG("File read failed in loop");
            ret = res;
            goto file_err_handle;
        }

        memcpy(tmp, buf, buf_len);

        /* Apply encryption/decryption if copy flag not set */
        if (c_args->flags != 4) {
            err = apply_skcipher(tmp, buf_len, c_args->flags, key, NULL);
            if (err < 0){
                XDBG("Data encryption failed in loop");
                ret = err;
                goto file_err_handle;
            }
        }

        res = vfs_write(out_filp, tmp, buf_len, &out_filp->f_pos);
        if (res < 0){
            XDBG("File write failed in loop");
            ret = res;
            goto file_err_handle;
        }
    }

    XDBG("Syscall processed successfully");

    /* Skip File deletion as there is no error */
    goto err_handle;

    file_err_handle:
    XDBG("Deleting partially written out file\n");
    err = remove_file(out_filp);
    if(err < 0){
        printk("Unable to delete partial file");
    }

    err_handle:
    XDBG("cryptocopy error handling if any");

    if(NULL != buf)
        kfree(buf);
    if(NULL != out_filp && !IS_ERR(out_filp))
        filp_close(out_filp, NULL);
    if(NULL != in_filp && !IS_ERR(in_filp))
        filp_close(in_filp, NULL);
    if(NULL != key)
        kfree(key);
    if(NULL != tmp)
        kfree(tmp);
    if(NULL != key_from_file)
        kfree(key_from_file);
    set_fs(old_fs);
    return ret;
}


static int md5_hash(char *result, const char* data, size_t len){

    struct shash_desc *hash_desc;
    int err, ret = 0;

    hash_desc = kmalloc(sizeof(*hash_desc), GFP_KERNEL);
    if(NULL == hash_desc){
        XDBG("No memory for md5_hash");
        ret = -ENOMEM;
        goto md5_err_handle;
    }

    hash_desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
    if(NULL == hash_desc->tfm){
        XDBG("md5 hash not found in crypto");
        ret = -ESRCH;
        goto md5_err_handle;
    }


    err = crypto_shash_init(hash_desc);
    if(err < 0){
        XDBG("md5 crypto init failed");
        ret = err;
        goto md5_err_handle;
    }

    err = crypto_shash_update(hash_desc, data, len);
    if(err < 0){
        XDBG("md5 crypto update failed");
        ret = err;
        goto md5_err_handle;
    }

    err = crypto_shash_final(hash_desc, result);
    if(err < 0){
        XDBG("md5 crypto final failed");
        ret = err;
        goto md5_err_handle;
    }


    md5_err_handle:
XDBG("handling md5 hash errors if any");

    if(NULL != hash_desc->tfm)
        crypto_free_shash(hash_desc->tfm);
    if(NULL != hash_desc)
        kfree(hash_desc);
    return ret;
}

static int remove_file(struct file* filp){
    inode_lock_nested(filp->f_path.dentry->d_parent->d_inode, I_MUTEX_PARENT);
    if(vfs_unlink(filp->f_path.dentry->d_parent->d_inode, filp->f_path.dentry, NULL) < 0){
        XDBG("Unlink Failed");
        return -ENODATA;
    }
    inode_unlock(filp->f_path.dentry->d_parent->d_inode);
    return 0;
}

static int apply_skcipher(u8* data, size_t datasize, int encrypt, char* keycode, u8* iv_data){
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int i, err;
    char key[32];
    char iv[16] = "abcdefghijklmnop";

    for(i = 0; i < 32; i++)
        key[i] = keycode[i];

    tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        XDBG("Unable to alloc tfm skcipher");
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, sizeof(key));
    if (err) {
        XDBG("Unable to set key skcipher");
        goto out;
    }
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        XDBG("Unable to alloc request skcipher");
        err = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg, data, datasize);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, iv);
    if(encrypt == 2) {
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    } else if (encrypt == 1) {
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    }

    if (err) {
        XDBG("Unable to apply skcipher");
        goto out;
    }

    XDBG("skcipher was successful\n");
    out:
    if(NULL != tfm)
        crypto_free_skcipher(tfm);
    if(NULL != req)
        skcipher_request_free(req);
    return err;
}



