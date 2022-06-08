#if ! defined XDBG
#if 1
#define XDBG(x) printk(KERN_DEFAULT "XDBG:%s:%s:%d  %s\n", __FILE__, __func__, __LINE__, x)
#else
#define XDBG(x)
#endif
#endif

#define NETLINK_USER 31

#define QUEUE_BOUND 20

#define JOB_DELAY 10000

typedef enum operation {
    INSERT_JOB,
    LIST_JOBS,
    DELETE_JOB,
    SWITCH_PRI
} operation;

typedef enum job_type {
    CRYPTO,
    CONCAT,
    DELETE,
    CHKSUM,
    RENAME,
    COMPRES
} job_type;

typedef enum job_output_mode {
    POLL,
    FILE_OUT
} job_out_mode;

typedef enum priority_level_struct {
    NORMAL_PRI,
    HIGH_PRI
} priority_level;

typedef enum job_status_struct {
    WAITING,
    RUNNING
} job_status;

typedef struct filename_struct {
    char *name;
    int len;
} filename;

typedef struct job_args_struct {
    char *infile_path;
    char *infile_path2;
    char *outfile_path;
    filename infile_names[10];
    int infiles_len;
    char *key;
    int flag;
    int key_len;
    int infile_path_len;
    int infile_path_len2;
    int outfile_path_len;
} job_args;

typedef struct job_struct {
    int id;
    int uid;
    priority_level priority;
    job_status status;
    job_type type;
    job_args args;
    job_out_mode out_mode;
    struct work_struct *work;
} job;

typedef struct socket_out_struct {
    char data[512];
    int err;
    int len;
} socket_out;
