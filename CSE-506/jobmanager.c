#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/limits.h>
#include <pthread.h>
#include <openssl/md5.h>
#include "common_symbols.h"

#define MAX_PAYLOAD 1024
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int waitflag;

typedef struct job_item_struct {
    operation operation;
    job job;
    void *out_data;
    int out_len;
} job_item;

void *get_job_status_from_kernel(void *job_id_ref) {
    int err_status;
    int job_id = *(int *)job_id_ref;
    socket_out *sout;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = job_id;

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);

    nlh->nlmsg_pid = job_id;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Waiting for syscall status...\n");
    recvmsg(sock_fd, &msg, 0);

    sout = (socket_out *)NLMSG_DATA(nlh);
    err_status = sout->err;
    printf("Syscall Status received: %d\n", err_status);
    if(sout->len > 0){
        printf("socket data received: %s\n", (char*)sout->data);
    }
    if(nlh)
        free(nlh);
}

int main(int argc, const char *argv[]) {
    int rc = -2;
    job_item new_job_item;
    char oper, cmd;
    int opt_idx = 1, i, job_id, flag;
    job *job_list;
    pthread_t thread_id;
    filename *filenames;

    new_job_item.job.args.infile_path =  NULL;
    new_job_item.job.args.infile_path2 =  NULL;
    new_job_item.job.args.outfile_path = NULL;
    new_job_item.out_data = NULL;
    new_job_item.job.args.key = NULL;
    new_job_item.job.args.infiles_len = 0;
    for(i = 0; i < new_job_item.job.args.infiles_len; i++) {
        new_job_item.job.args.infile_names[i].name = NULL;
    }

    oper = argv[opt_idx++][1];
    switch(oper) {
        case 'i':
            printf("Operation: insert_job\n");
            new_job_item.operation = INSERT_JOB;
            new_job_item.job.id = getpid();
            printf("Job Id: %d\n", new_job_item.job.id);
            cmd = argv[opt_idx++][1];
            switch(cmd) {
                case 'e':
                    printf("Job type: encrypt\n");
                    new_job_item.job.args.flag = 1;
                    /* Falls Through */
                case 'd':
                    printf("Job type: decrypt\n");
                    new_job_item.job.type = CRYPTO;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    new_job_item.job.args.outfile_path = (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx++], new_job_item.job.args.infile_path);
                    realpath(argv[opt_idx++], new_job_item.job.args.outfile_path);
                    printf("in: %s\n", new_job_item.job.args.infile_path);
                    printf("out: %s\n", new_job_item.job.args.outfile_path);
                    new_job_item.job.args.key = (char *) malloc(33);
                    MD5((unsigned char *) argv[opt_idx++], strlen(argv[opt_idx]), new_job_item.job.args.key);
                    if(new_job_item.job.args.flag != 1)
                        new_job_item.job.args.flag = 2;
                    new_job_item.job.args.outfile_path_len = strlen(new_job_item.job.args.outfile_path)+2;
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    new_job_item.job.args.key_len = 32;
                    break;
                case 'c':
                    printf("Job type: copy\n");
                    new_job_item.job.type = CRYPTO;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    new_job_item.job.args.outfile_path = (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx++], new_job_item.job.args.infile_path);
                    realpath(argv[opt_idx++], new_job_item.job.args.outfile_path);
                    printf("in: %s\n", new_job_item.job.args.infile_path);
                    printf("out: %s\n", new_job_item.job.args.outfile_path);
                    new_job_item.job.args.flag = 4;
                    new_job_item.job.args.outfile_path_len = strlen(new_job_item.job.args.outfile_path)+2;
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    break;
                case 'a':
                    printf("Job type: concat\n");
                    new_job_item.job.type = CONCAT;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    new_job_item.job.args.infile_path2 =  (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx], new_job_item.job.args.infile_path);
                    realpath(argv[opt_idx+1], new_job_item.job.args.infile_path2);
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    new_job_item.job.args.infile_path_len2 = strlen(new_job_item.job.args.infile_path2)+2;
                    new_job_item.job.args.infiles_len = argc - 6;
                    filenames = new_job_item.job.args.infile_names;
                    for(i = 0; i < new_job_item.job.args.infiles_len; i++) {
                        new_job_item.job.args.infile_names[i].name  = (char *) malloc(PATH_MAX);
                        realpath(argv[opt_idx++], new_job_item.job.args.infile_names[i].name);
                        new_job_item.job.args.infile_names[i].len = strlen(new_job_item.job.args.infile_names[i].name)+2;
                        printf("in: %s\n", new_job_item.job.args.infile_path);
                    }
                    new_job_item.job.args.outfile_path = (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx++], new_job_item.job.args.outfile_path);
                    printf("out: %s\n", new_job_item.job.args.outfile_path);
                    new_job_item.job.args.outfile_path_len = strlen(new_job_item.job.args.outfile_path)+2;
                    break;
                case 'x':
                    printf("Job type: delete\n");
                    new_job_item.job.type = DELETE;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx], new_job_item.job.args.infile_path);
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    new_job_item.job.args.infiles_len = argc - 5;
                    filenames = new_job_item.job.args.infile_names;
                    for(i = 0; i < new_job_item.job.args.infiles_len; i++) {
                        new_job_item.job.args.infile_names[i].name  = (char *) malloc(PATH_MAX);
                        realpath(argv[opt_idx++], new_job_item.job.args.infile_names[i].name);
                        new_job_item.job.args.infile_names[i].len = strlen(new_job_item.job.args.infile_names[i].name)+2;
                        printf("in: %s\n", new_job_item.job.args.infile_path);
                    }
                    break;
                case 's':
                    printf("Job type: checksum\n");
                    new_job_item.job.type = CHKSUM;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx++], new_job_item.job.args.infile_path);
                    printf("in: %s\n", new_job_item.job.args.infile_path);
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    break;
                case 'r':
                    printf("Job type: rename\n");
                    new_job_item.job.type = RENAME;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    new_job_item.job.args.outfile_path = (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx], new_job_item.job.args.infile_path);
                    realpath(argv[opt_idx+1], new_job_item.job.args.outfile_path);
                    new_job_item.job.args.outfile_path_len = strlen(new_job_item.job.args.outfile_path)+2;
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
                    new_job_item.job.args.infiles_len = argc - 5;
                    if(new_job_item.job.args.infiles_len % 2 != 0) {
                        printf("Filenames insufficient\n");
                        goto out;
                    }
                    filenames = new_job_item.job.args.infile_names;
                    for(i = 0; i < new_job_item.job.args.infiles_len; i++) {
                        new_job_item.job.args.infile_names[i].name  = (char *) malloc(PATH_MAX);
                        realpath(argv[opt_idx++], new_job_item.job.args.infile_names[i].name);
                        new_job_item.job.args.infile_names[i].len = strlen(new_job_item.job.args.infile_names[i].name)+2;
                        printf("file: %s\n", new_job_item.job.args.infile_path);
                    }
                    break;
                case 'u':
                    printf("Job type: Decompress\n");
                    new_job_item.job.args.flag = 1;
                    /* Falls Through */
                case 'p':
                    printf("Job type: Compress\n");
                    new_job_item.job.type = COMPRES;
                    if(new_job_item.job.args.flag != 1)
                        new_job_item.job.args.flag = 0;
                    new_job_item.job.args.infile_path =  (char *) malloc(PATH_MAX);
                    new_job_item.job.args.outfile_path = (char *) malloc(PATH_MAX);
                    realpath(argv[opt_idx++], new_job_item.job.args.infile_path);
                    realpath(argv[opt_idx++], new_job_item.job.args.outfile_path);
                    printf("in: %s\n", new_job_item.job.args.infile_path);
                    printf("out: %s\n", new_job_item.job.args.outfile_path);
                    new_job_item.job.args.outfile_path_len = strlen(new_job_item.job.args.outfile_path)+2;
                    new_job_item.job.args.infile_path_len = strlen(new_job_item.job.args.infile_path)+2;
            }
            switch(argv[opt_idx++][1]){
                case 'h':
                    new_job_item.job.priority = HIGH_PRI;
                    printf("High Priority jobs\n");
                    break;
                default:
                    new_job_item.job.priority = NORMAL_PRI;
                    printf("Low Priority jobs\n");
            }
            cmd = argv[opt_idx++][1];
            switch (cmd) {
                case 'p':
                    printf("Out mode: Poll\n");
                    new_job_item.job.out_mode = POLL;
                    pthread_create(&thread_id, NULL, get_job_status_from_kernel, (void *)&new_job_item.job.id);
                    break;
                case 'f':
                    printf("Out mode: File\n");
                    new_job_item.job.out_mode = FILE_OUT;
                    break;
                default:
                    printf("Invalid out mode\n");
                    goto out;
            }
            rc = syscall(335, &new_job_item);
            if (rc == 0){
                if(cmd == 'p'){
                    if(pthread_join(thread_id, NULL)) {
                        printf("Polling Fail\n");
                    }else {
                        printf("Polling Success\n");
                    }
                }
            }
            break;

        case 'l':
            printf("Operation: list_jobs\n");
            new_job_item.out_data = (void *)calloc(QUEUE_BOUND, sizeof(job));
            new_job_item.operation = LIST_JOBS;
            new_job_item.out_len = 0;
            switch(argv[opt_idx++][1]){
                case 'h':
                    new_job_item.job.priority = HIGH_PRI;
                    printf("High Priority jobs\n");
                    break;
                default:
                    new_job_item.job.priority = NORMAL_PRI;
                    printf("Low Priority jobs\n");
            }
            rc = syscall(335, &new_job_item);
            job_list = (job *)new_job_item.out_data;
            printf("No. of jobs: %d\n", new_job_item.out_len);
            if(new_job_item.out_len > 0) {
                printf("id\ttype\tuid\tstatus\n");
                for (i = 0; i < new_job_item.out_len && i < QUEUE_BOUND; i++) {
                    switch (job_list->type) {
                        case CRYPTO:
                            printf("%d\tcrypto\t%d\t", job_list->id, job_list->uid);
                            break;
                        case CONCAT:
                            printf("%d\tconcat\t%d\t", job_list->id, job_list->uid);
                            break;
                        case DELETE:
                            printf("%d\tdelete\t%d\t", job_list->id, job_list->uid);
                            break;
                        case CHKSUM:
                            printf("%d\tchksum\t%d\t", job_list->id, job_list->uid);
                            break;
                        case COMPRES:
                            printf("%d\tcompres\t%d\t", job_list->id, job_list->uid);
                            break;
                        default:
                            printf("%d\t-\t%d\t", job_list->id, job_list->uid);
                    }
                    switch (job_list->status) {
                        case RUNNING:
                            printf("Run\n");
                            break;
                        case WAITING:
                            printf("Wait\n");
                            break;
                        default:
                            printf("-\n");
                    }
                    job_list++;
                }
            }
            break;

        case 'g':
            printf("Operation: list_jobs\n");
            new_job_item.out_data = (void *)calloc(QUEUE_BOUND, sizeof(job));
            new_job_item.operation = LIST_JOBS;
            new_job_item.out_len = 0;
            switch(argv[opt_idx++][1]){
                case 'h':
                    new_job_item.job.priority = HIGH_PRI;
                    printf("High Priority jobs\n");
                    break;
                default:
                    new_job_item.job.priority = NORMAL_PRI;
                    printf("Low Priority jobs\n");
            }
            rc = syscall(335, &new_job_item);
            new_job_item.job.id = atoi(argv[opt_idx++]);
            job_list = (job *)new_job_item.out_data;
            flag = 0;
            if(new_job_item.out_len > 0) {
                for (i = 0; i < new_job_item.out_len && i < QUEUE_BOUND; i++) {
                    if(new_job_item.job.id == job_list->id){
                        flag = 1;
                        switch (job_list->type) {
                            case CRYPTO:
                                printf("%d\tcrypto\t%d\t", job_list->id, job_list->uid);
                                break;
                            case CONCAT:
                                printf("%d\tconcat\t%d\t", job_list->id, job_list->uid);
                                break;
                            case DELETE:
                                printf("%d\tdelete\t%d\t", job_list->id, job_list->uid);
                                break;
                            case CHKSUM:
                                printf("%d\tchksum\t%d\t", job_list->id, job_list->uid);
                                break;
                            case COMPRES:
                                printf("%d\tcompres\t%d\t", job_list->id, job_list->uid);
                                break;
                            default:
                                printf("%d\t-\t%d\t", job_list->id, job_list->uid);
                        }
                        switch (job_list->status) {
                            case RUNNING:
                                printf("Run\n");
                                break;
                            case WAITING:
                                printf("Wait\n");
                                break;
                            default:
                                printf("-\n");
                        }
                        break;
                    }
                    job_list++;
                }
            }
            if(flag == 0){
                printf("No job found\n");
            }

            break;

        case 'd':
            printf("Operation: delete_job\n");
            new_job_item.operation = DELETE_JOB;
            new_job_item.job.id = atoi(argv[opt_idx++]);
            rc = syscall(335, &new_job_item);
            break;
        case 'p':
            new_job_item.job.id = atoi(argv[opt_idx++]);
            new_job_item.operation = SWITCH_PRI;
            rc = syscall(335, &new_job_item);
            switch(argv[opt_idx++][1]){
                case 'h':
                    new_job_item.job.priority = HIGH_PRI;
                    break;
                default:
                    new_job_item.job.priority = NORMAL_PRI;
            }
            break;
        default:
            printf("Operation not supported!\n");
            goto out;
    }

    if (rc == 0){
        printf("syscall returned %d\n", rc);
    }
    else {
        printf("syscall returned %d (errno=%d)\n", rc, errno);
    }
    out:
        if(new_job_item.job.args.infile_path)
            free(new_job_item.job.args.infile_path);
        if(new_job_item.job.args.infile_path2)
            free(new_job_item.job.args.infile_path2);
        if(new_job_item.job.args.outfile_path)
            free(new_job_item.job.args.outfile_path);
        if(new_job_item.job.args.key)
            free(new_job_item.job.args.key);
        if(new_job_item.out_data)
            free(new_job_item.out_data);
    for(i = 0; i < new_job_item.job.args.infiles_len; i++) {
        if(new_job_item.job.args.infile_names[i].name) {
            free(new_job_item.job.args.infile_names[i].name);
        }
    }
    exit(rc);
}
