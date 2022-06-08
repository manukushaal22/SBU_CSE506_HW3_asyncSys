#include <linux/export.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/workqueue.h>
#include "common_symbols.h"
#include "cryptolib.h"
#include "job_type_impl/concat.h"
#include "job_type_impl/delete.h"
#include "job_type_impl/checksum.h"
#include "job_type_impl/rename.h"
#include "job_type_impl/compresslib.h"

asmlinkage extern long (*sysptr)(void *arg);

typedef struct job_item_struct {
    operation operation;
    job job;
    struct work_struct work;
    void *out_data;
    int out_len;
} job_item;

typedef struct job_item_user_struct {
    operation operation;
    job job;
    void *out_data;
    int out_len;
} job_item_user;

typedef struct job_queue_struct {
    job *job;
    job_item *job_item;
    struct job_queue_struct *next_job;
} job_queue;

struct sock *nl_sk = NULL;

static struct workqueue_struct *async_jobs_q;
static struct workqueue_struct *async_jobs_hi_q;

DEFINE_SPINLOCK(queue_lock);
extern int queue_len;
//DEFINE_SPINLOCK(queue_lock);
int queue_len;

DEFINE_SPINLOCK(queue_lock_hi);
extern int queue_len_hi;
//DEFINE_SPINLOCK(queue_lock_hi);
int queue_len_hi;

static job_queue *waiting_jobs;
static job_queue *waiting_jobs_hi;

static int file_out_status_to_user(int job_id, socket_out *sock_out)
{
    struct file *out_filp = NULL;
    char *data = NULL, *filp_name = NULL;
    int res, err = 0;

    filp_name = (char *) kmalloc(PATH_MAX, GFP_KERNEL);
    if(filp_name == NULL){
        XDBG("No mem");
        err = -ENOMEM;
        return err;
    };
    sprintf(filp_name, "/async_job_outs/job.%d.out.file", job_id);
    out_filp = filp_open(filp_name, O_WRONLY|O_CREAT|O_TRUNC, 655);
    if (IS_ERR(out_filp)) {
        XDBG("Can't open output file");
        err = -PTR_ERR(out_filp);
        goto out;
    }
    data = (char*) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if(data == NULL){
        XDBG("No mem");
        err = -ENOMEM;
        return err;
    }
    if(sock_out->len > 0)
        sprintf(data, "Job Id: %d\nStatus: %d\nchecksum: %s\n", job_id, sock_out->err, sock_out->data);
    else
        sprintf(data, "Job Id: %d\nStatus: %d\n", job_id, sock_out->err);

    res = vfs_write(out_filp, data, strlen(data)+2, &out_filp->f_pos);
    if (res < 0){
        XDBG("File write failed");
        err = res;
        goto out;
    }
    out:
    if(data)
        kfree(data);
    if(out_filp)
        filp_close(out_filp, NULL);
    return err;
}

static void cast_status_to_user(int job_id, socket_out *sock_out)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;

    skb_out = nlmsg_new(sizeof(socket_out), 0);
    if (!skb_out) {
        XDBG("msg alloc fail\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(socket_out), 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), sock_out, sizeof(socket_out));

    msleep(4);
    res = nlmsg_unicast(nl_sk, skb_out, job_id);

    if (res < 0)
        XDBG("NL uni-cast fail!\n");
}

job_queue *dequeue_oldest_job(priority_level pri){
    job_queue *node = NULL;
    if(pri == HIGH_PRI){
        if (waiting_jobs_hi == NULL) {
            return NULL;
        }
        node = waiting_jobs_hi;
        waiting_jobs_hi = waiting_jobs_hi->next_job;
        queue_len_hi--;

    } else {
        if (waiting_jobs == NULL) {
            return NULL;
        }
        node = waiting_jobs;
        waiting_jobs = waiting_jobs->next_job;
        queue_len--;
    }

    return node;
}

int enqueue_job(job_item *new_job) {
    job_queue *node;
    job_queue *curr;

    node = (job_queue*) kmalloc(sizeof(job_queue), GFP_KERNEL);
    if(node == NULL) {
        XDBG("Memory Error\n");
        return -ENOMEM;
    }
    node->job_item = new_job;
    node->job = &(new_job->job);
    node->job->status = WAITING;
    node->next_job = NULL;

    switch (new_job->job.priority) {
        case NORMAL_PRI:
            if (waiting_jobs == NULL) {
                waiting_jobs = node;
                return 0;
            }
            curr = waiting_jobs;
            queue_len++;
            break;
        case HIGH_PRI:
            if (waiting_jobs_hi == NULL) {
                waiting_jobs_hi = node;
                return 0;
            }
            curr = waiting_jobs_hi;
            queue_len_hi++;
            break;
        default:
            XDBG("Wrong pri option");
            kfree(node);
            return -EINVAL;
    }
    while(curr->next_job != NULL){
        curr = curr->next_job;
    }
    curr->next_job = node;
    return 0;
}

void dealloc_job_q_node(job_queue *node){
    kfree(node->job_item);
    kfree(node);
}

void clear_queue(priority_level pri){
    if(pri == HIGH_PRI){
        while(waiting_jobs_hi != NULL){
            dealloc_job_q_node(dequeue_oldest_job(pri));
        }
    }
    if(pri == NORMAL_PRI){
        while(waiting_jobs != NULL){
            dealloc_job_q_node(dequeue_oldest_job(pri));
        }
    }
}

job_queue *delete_job(int job_id, priority_level pri) {
    job_queue *curr_job;
    job_queue *tmp;
    if(pri == HIGH_PRI){
        curr_job = waiting_jobs_hi;
        if(waiting_jobs_hi->job->id == job_id) {
            waiting_jobs_hi = waiting_jobs_hi->next_job;
            curr_job->next_job = NULL;
            return curr_job;
        }
    } else {
        curr_job = waiting_jobs;
        if(waiting_jobs->job->id == job_id) {
            waiting_jobs = waiting_jobs->next_job;
            curr_job->next_job = NULL;
            return curr_job;
        }
    }

    while(curr_job->next_job != NULL && curr_job->next_job->job->id != job_id){
        curr_job = curr_job->next_job;
    }
    if(curr_job->next_job->job->id == job_id) {
        tmp = curr_job->next_job;
        curr_job->next_job = curr_job->next_job->next_job;
        tmp->next_job = NULL;
        return tmp;
    }
    return NULL;
}

job_queue *fetch_job_node_by_id(int job_id, priority_level pri) {
    job_queue *curr_job;

    if(pri == HIGH_PRI){
        curr_job = waiting_jobs_hi;
    } else {
        curr_job = waiting_jobs;
    }

    while(curr_job != NULL){
        if(curr_job->job->id == job_id)
            return curr_job;
        curr_job = curr_job->next_job;
    }
    return NULL;
}

void* user_to_kernel(void *user_ptr, int len) {
    void *kernel_ptr = NULL;
    int unread = 0;

    if (!access_ok(user_ptr, len)) {
        XDBG("arg no access");
        return NULL;
    }
    kernel_ptr = (void*) kmalloc(len+1, GFP_KERNEL);
    if ( kernel_ptr == NULL ) {
        XDBG("No mem for user_arg");
        return NULL;
    }
    unread = copy_from_user(kernel_ptr, user_ptr, len);
    if (unread > 0) {
        printk("unread: %d\n", unread);
        goto out;
    }

    goto success;
    out:
    if(kernel_ptr != NULL){
        kfree(kernel_ptr);
        kernel_ptr = NULL;
    }
    success:
    return kernel_ptr;
}

job *fetch_oldest_waiting_job(priority_level pri){
    job_queue *node = NULL;

    if(pri == HIGH_PRI){
        node = waiting_jobs_hi;

    } else {
        node = waiting_jobs;
    }
    while(node != NULL && node->job->status != WAITING) {
        node = node->next_job;
    }
    if(node){
        return node->job;
    }
    return NULL;
}

void lock_queue(priority_level pri){
    unsigned long flags;
    flags = 0;
    if(pri == HIGH_PRI){
        spin_lock_irqsave(&queue_lock_hi, flags);
    } else{
        spin_lock_irqsave(&queue_lock, flags);
    }
}

void unlock_queue(priority_level pri){
    unsigned long flags;
    flags = 0;
    if(pri == HIGH_PRI){
        spin_unlock_irqrestore(&queue_lock_hi, flags);
    } else{
        spin_unlock_irqrestore(&queue_lock, flags);
    }
}

static int perform_job(priority_level pri, job_item *cur_job_item){
    int err = 0, i;
    job_args *job_args;
    job *cur_job;
    job_queue *tmp;
    char *checkSum = NULL;
    socket_out *sock_out = NULL;

    cur_job = &cur_job_item->job;
    printk("Executing job: id: %d pri: %d", waiting_jobs->job->id, pri);
    cur_job->status = RUNNING;
    switch (cur_job->type) {
        case CRYPTO:
            job_args = &(cur_job->args);
            switch (job_args->flag) {
                case 1:
                    err = encrypt(job_args->infile_path, job_args->outfile_path, job_args->key);
                    break;
                case 2:
                    err = decrypt(job_args->infile_path, job_args->outfile_path, job_args->key);
                    break;
                case 4:
                    err = copy_file(job_args->infile_path, job_args->outfile_path);
                    break;
            }
            if(err != 0){
                XDBG("File Crypto operation fail");
                goto out;
            }
            XDBG("File Crypto Success!");
            break;

        case RENAME:
            job_args = &(cur_job->args);
            for(i= 0; i < job_args->infiles_len; i+=2){
                err = renameWrapper(job_args->infile_names[i].name, job_args->infile_names[i+1].name);
                kfree(job_args->infile_names[i].name);
                kfree(job_args->infile_names[i+1].name);
            }
            if(err != 0){
                XDBG("File RENAME operation fail");
                goto out;
            }
            XDBG("File RENAME Success!");
            break;

        case COMPRES:
            job_args = &(cur_job->args);
            err = compress("deflate", job_args->infile_path, job_args->outfile_path, job_args->flag);
            if(err != 0){
                XDBG("File COMPRES operation fail");
                goto out;
            }
            XDBG("File COMPRES Success!");
            break;

        case CONCAT:
            job_args = &(cur_job->args);

            err = concat(job_args->infile_names, job_args->infiles_len,job_args->outfile_path);
            if(err != 0){
                XDBG("File Concat operation fail");
                goto out;
            }
            XDBG("File Concat Success!");
            break;

        case DELETE:
            job_args = &(cur_job->args);
            for(i= 0; i < job_args->infiles_len; i++){
                err = unlinkWrapper(job_args->infile_names[i].name);
                kfree(job_args->infile_names[i].name);
            }
            if(err != 0){
                XDBG("File Delete operation fail");
                goto out;
            }
            XDBG("File Delete Success!");
            break;

        case CHKSUM:
            job_args = &(cur_job->args);
            checkSum = kmalloc(64, GFP_KERNEL);
            err = getCheckSumWrapper(job_args->infile_path, checkSum);
            if(err != 0){
                XDBG("File CHECKSUM operation fail");
                goto out;
            }
            XDBG("File CHECKSUM Success!");
            break;

        default:
        XDBG("Invalid job command!\n");
            err = -ENOTSUPP;
            goto out;
    }
    out:
    sock_out = (socket_out *) kmalloc(sizeof(socket_out), GFP_KERNEL);
    if(sock_out == NULL){
        XDBG("Unable to alloc sock_out\n");
        err = -ENOMEM;
        goto out2;
    }
    sock_out->err = err;
    sock_out->len = 0;
    if(cur_job->type == CHKSUM && err == 0) {
        strcpy(sock_out->data, checkSum);
        sock_out->len = strlen(checkSum);
    }
    if(cur_job->out_mode == POLL){
        cast_status_to_user(cur_job->id, sock_out);
    } else {
        file_out_status_to_user(cur_job->id, sock_out);
    }
out2:
    if(sock_out != NULL)
        kfree(sock_out);
    lock_queue(pri);
    tmp =  delete_job(cur_job_item->job.id, pri);
    if(tmp == NULL){
        XDBG("Possible concurrency bug!!\n");
        unlock_queue(pri);
        goto out1;
    }
    unlock_queue(pri);
    dealloc_job_q_node(tmp);
    out1:
    if(cur_job->args.infile_path != NULL)
        kfree(cur_job->args.infile_path);
    if(cur_job->args.outfile_path != NULL)
        kfree(cur_job->args.outfile_path);
    if(cur_job->args.key != NULL)
        kfree(cur_job->args.key);
    if(checkSum != NULL)
        kfree(checkSum);

    return err;
}

static void perform_job_lo(struct work_struct *work){
    job_item *jobItem;

    jobItem = container_of(work, job_item, work);
    printk("id: %d", jobItem->job.id);
    perform_job(NORMAL_PRI, jobItem);
}

static void perform_job_hi(struct work_struct *work){
    job_item *jobItem;

    jobItem = container_of(work, job_item, work);
    printk("id: %d", jobItem->job.id);
    perform_job(HIGH_PRI, jobItem);
}

static DECLARE_WORK(perform_job_work, perform_job_lo);
static DECLARE_WORK(perform_job_work_hi, perform_job_hi);

int job_q_kernel_to_user(job_item_user *user_job_item) {
    job_queue *curr_kernel_job;
    job *curr_user_job = NULL;

    curr_kernel_job = waiting_jobs;
    if(user_job_item->job.priority == HIGH_PRI)
        curr_kernel_job = waiting_jobs_hi;
    curr_user_job = user_job_item->out_data;
    user_job_item->out_len = 0;
    while(curr_kernel_job != NULL) {
        if(current->cred->uid.val == 0 || curr_kernel_job->job->uid == current->cred->uid.val) {
            if (copy_to_user((void *)curr_user_job, curr_kernel_job->job, sizeof(job))) {
                XDBG("unable to copy to usr space");
                return -EFAULT;
            }
            curr_user_job++;
            (user_job_item->out_len)++;
        }
        curr_kernel_job = curr_kernel_job->next_job;
    }
    return 0;
}

int manage_job(job_item_user* user_job_item){
    job_item *new_job_item;
    job_item_user *new_job_item_user;
    int err = 0, flag = -1, i;
    priority_level new_pri;
    job_queue *job_node, *cur_node;

    new_job_item_user = (job_item_user *) user_to_kernel(user_job_item, sizeof(job_item_user));
    if ( new_job_item_user == NULL ) {
        XDBG("No mem for job");
        return -ENOMEM;
    }
    new_job_item = (job_item *) kmalloc(sizeof(job_item), GFP_KERNEL);
    memcpy(&new_job_item->job, &new_job_item_user->job, sizeof(job));
    new_job_item->operation = new_job_item_user->operation;
    kfree(new_job_item_user);
    switch (new_job_item->operation) {
        case LIST_JOBS:
            printk("pri: %d\n", user_job_item->job.priority);
            lock_queue(user_job_item->job.priority);
            XDBG("Listing jobs");
            if(0 > job_q_kernel_to_user(user_job_item)) {
                XDBG("job_q_kernel_to_user err");
                lock_queue(user_job_item->job.priority);
                kfree(new_job_item);
                return -ENOMEM;
            }
            unlock_queue(user_job_item->job.priority);
            break;

        case DELETE_JOB:
            if(new_job_item->job.id < 0) {
                XDBG("negative id received");
                kfree(new_job_item);
                return -EINVAL;
            }
            lock_queue(NORMAL_PRI);
            job_node = fetch_job_node_by_id(new_job_item->job.id, NORMAL_PRI);
            if( job_node == NULL ){
                XDBG("Job not found in wq");
                unlock_queue(NORMAL_PRI);
                lock_queue(HIGH_PRI);
                job_node = fetch_job_node_by_id(new_job_item->job.id, HIGH_PRI);
                if(job_node == NULL){
                    XDBG("Job not found in wq_hi");
                    unlock_queue(HIGH_PRI);
                    kfree(new_job_item);
                    return -ENOENT;
                } else {
                    if(job_node->job->uid != 0 && job_node->job->uid != current->cred->uid.val){
                        XDBG("Not your job!");
                        unlock_queue(HIGH_PRI);
                        kfree(new_job_item);
                        return -ENOENT;
                    }
                    if(job_node->job->status == RUNNING) {
                        XDBG("Already running!");
                        unlock_queue(HIGH_PRI);
                        kfree(new_job_item);
                        return -EINPROGRESS;
                    } else {
                        job_node = delete_job(new_job_item->job.id, HIGH_PRI);
                        cancel_work_sync(job_node->job->work);
                        dealloc_job_q_node(job_node);
                        unlock_queue(HIGH_PRI);
                        kfree(new_job_item);
                    }
                }
            } else {
                if(job_node->job->uid != 0 && job_node->job->uid != current->cred->uid.val){
                    XDBG("Not your job!");
                    unlock_queue(NORMAL_PRI);
                    kfree(new_job_item);
                    return -ENOENT;
                }
                if(job_node->job->status == RUNNING) {
                    XDBG("Already running!");
                    unlock_queue(NORMAL_PRI);
                    kfree(new_job_item);
                    return -EINPROGRESS;
                } else {
                    job_node = delete_job(new_job_item->job.id, NORMAL_PRI);
                    cancel_work_sync(job_node->job->work);
                    dealloc_job_q_node(job_node);
                    unlock_queue(NORMAL_PRI);
                    kfree(new_job_item);
                }
            }
            break;

        case SWITCH_PRI:
            if(new_job_item->job.id < 0) {
                XDBG("negative id received");
                kfree(new_job_item);
                return -EINVAL;
            }
            lock_queue(HIGH_PRI);
            lock_queue(NORMAL_PRI);
            job_node = fetch_job_node_by_id(new_job_item->job.id, new_job_item->job.priority);
            if(job_node == NULL) {
                XDBG("Job not found in wq");
                unlock_queue(NORMAL_PRI);
                unlock_queue(HIGH_PRI);
                kfree(new_job_item);
                return -EINVAL;
            } else {
                if(job_node->job->uid != 0 && job_node->job->uid != current->cred->uid.val){
                    XDBG("Not your job!");
                    unlock_queue(NORMAL_PRI);
                    unlock_queue(HIGH_PRI);
                    kfree(new_job_item);
                    return -ENOENT;
                }
                if(job_node->job->status == RUNNING){
                    XDBG("Job already started");
                    unlock_queue(NORMAL_PRI);
                    unlock_queue(HIGH_PRI);
                    kfree(new_job_item);
                    return -EINPROGRESS;
                }
                job_node = delete_job(new_job_item->job.id, NORMAL_PRI);
                cancel_work_sync(job_node->job->work);
                switch (new_job_item->job.priority) {
                    case HIGH_PRI:
                        new_pri = NORMAL_PRI;
                        cur_node = waiting_jobs;
                        INIT_WORK(&new_job_item->work, perform_job_lo);
                        break;
                    default:
                        new_pri = HIGH_PRI;
                        cur_node = waiting_jobs_hi;
                        INIT_WORK(&new_job_item->work, perform_job_hi);
                        break;
                }
                while(cur_node->next_job != NULL){
                    cur_node = cur_node->next_job;
                }
                cur_node->next_job = job_node;
                switch (new_pri) {
                    case HIGH_PRI:
                        queue_work(async_jobs_hi_q, &new_job_item->work);
                        XDBG("job: enqueued to hi_WQ\n");
                        break;
                    default:
                        queue_work(async_jobs_q, &new_job_item->work);
                        XDBG("job: enqueued to WQ\n");
                }
            }
            unlock_queue(NORMAL_PRI);
            unlock_queue(HIGH_PRI);
            kfree(new_job_item);
            break;

        case INSERT_JOB:
            new_job_item->job.uid = current->cred->uid.val;
            flag = new_job_item->job.args.flag;
            XDBG("INSERT Oper");
            switch (new_job_item->job.type) {
                case CRYPTO:
                    XDBG("CRYPTO type");
                    if(flag != 1 && flag != 2 && flag != 4){
                        XDBG("Invalid flag for crypto\n");
                        kfree(new_job_item);
                        return -EINVAL;
                    }
                    if(flag != 4){
                        new_job_item->job.args.key =
                                (char *) user_to_kernel(new_job_item->job.args.key,
                                                        new_job_item->job.args.key_len);
                    }
                    break;
                case COMPRES:
                    XDBG("COMPRES type");
                    if(flag != 1 && flag != 0){
                        XDBG("Invalid flag for compress\n");
                        kfree(new_job_item);
                        return -EINVAL;
                    }
                    break;
                default:
                    break;
            }
            for(i = 0; i < new_job_item->job.args.infiles_len; i++){
                new_job_item->job.args.infile_names[i].name =
                        (char *) user_to_kernel(new_job_item->job.args.infile_names[i].name,
                                                new_job_item->job.args.infile_names[i].len);
            }
            switch (new_job_item->job.type) {
                case CONCAT:
                    new_job_item->job.args.infile_path2 =
                            (char *) user_to_kernel(new_job_item->job.args.infile_path2,
                                                    new_job_item->job.args.infile_path_len2);
                    /* Falls through. */
                case COMPRES:
                    /* Falls through. */
                case CRYPTO:
                    /* Falls through. */
                case RENAME:
                    new_job_item->job.args.outfile_path =
                            (char *) user_to_kernel(new_job_item->job.args.outfile_path,
                                                    new_job_item->job.args.outfile_path_len);
                    /* Falls through. */
                case CHKSUM:
                    /* Falls through. */
                case DELETE:
                    new_job_item->job.args.infile_path =
                            (char *) user_to_kernel(new_job_item->job.args.infile_path,
                                                    new_job_item->job.args.infile_path_len);
                    break;
            }
            queue_len = 0;
            switch (new_job_item->job.priority) {
                case HIGH_PRI:
                    INIT_WORK(&new_job_item->work, perform_job_hi);
                    break;
                default:
                    INIT_WORK(&new_job_item->work, perform_job_lo);
            }
            new_job_item->job.work = &new_job_item->work;
            err = enqueue_job(new_job_item);
            if (0 == err) {
                XDBG("job: enqueueing\n");
                printk("job: enq %d", waiting_jobs->job->id);
            } else {
                XDBG("job enqueue FAIL\n");
                unlock_queue(new_job_item->job.priority);
                kfree(new_job_item);
                return err;
            }
            switch (new_job_item->job.priority) {
                case HIGH_PRI:
                    queue_work(async_jobs_hi_q, &new_job_item->work);
                    XDBG("job: enqueued to hi_WQ\n");
                    break;
                default:
                    queue_work(async_jobs_q, &new_job_item->work);
                    XDBG("job: enqueued to WQ\n");
            }
            unlock_queue(new_job_item->job.priority);
            break;
    }
    return 0;
}

asmlinkage long jobmanager(void *arg) {
    int err = 0;

    XDBG("Inside jobmanager syscall");
    if (arg == NULL) {
        XDBG("arg null");
        err = -EINVAL;
        goto out;
    }
    err = manage_job((job_item_user *)arg);

    out:
    return err;
}

static int create_dir(const char *name, umode_t mode)
{
    struct dentry *dentry;
    struct path path;
    int err;

    dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry))
        return PTR_ERR(dentry);

    err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
    done_path_create(&path, dentry);
    return err;
}

static int __init init_async_sys(void)
{
    int err = 0;
    struct netlink_kernel_cfg cfg = { .flags  = NL_CFG_F_NONROOT_RECV, };

    XDBG("installing new async_sys module\n");

    create_dir("/async_job_outs/", 777);

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        XDBG("Error creating socket.\n");
        return -ENOMEM;
    }

    waiting_jobs = NULL;

    async_jobs_q = alloc_workqueue("async_jobs", 0, 0);
    if(!async_jobs_q){
        XDBG("Cannot initiate async_jobs wq\n");
        err = -ENOMEM;
        goto out;
    }
    async_jobs_hi_q = alloc_workqueue("async_jobs_hi", WQ_HIGHPRI, 0);
    if(!async_jobs_hi_q){
        XDBG("Cannot initiate async_jobs_hi wq\n");
        err = -ENOMEM;
        goto out;
    }

    if(sysptr == NULL){
        sysptr = jobmanager;
    }

    goto success;
    out:
    if(async_jobs_q){
        destroy_workqueue(async_jobs_q);
    }
    if(async_jobs_hi_q){
        destroy_workqueue(async_jobs_hi_q);
    }
    success:
    if(err == 0)
        XDBG("installed new async_sys module\n");
    return err;
}

static void  __exit exit_async_sys(void)
{
    if(sysptr != NULL)
        sysptr = NULL;

    lock_queue(HIGH_PRI);
    clear_queue(HIGH_PRI);
    unlock_queue(HIGH_PRI);

    lock_queue(NORMAL_PRI);
    clear_queue(NORMAL_PRI);
    unlock_queue(NORMAL_PRI);


    if(async_jobs_q){
        destroy_workqueue(async_jobs_q);
    }
    if(async_jobs_hi_q){
        destroy_workqueue(async_jobs_hi_q);
    }

    netlink_kernel_release(nl_sk);

    XDBG("removed async_sys module\n");
}

module_init(init_async_sys);
module_exit(exit_async_sys);
MODULE_LICENSE("GPL");
