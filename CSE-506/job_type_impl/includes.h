/*
 Created by Kondeti Rama Aiswarya on 4/29/22.
*/

#include <linux/linkage.h>
#include <linux/mutex.h>
#include <linux/moduleloader.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/crc32.h>

#if ! defined XDBG

#if 1
#define XDBG(x) printk(KERN_DEFAULT "XDBG:%s:%s:%d %s\n", \
                       __FILE__, __func__, __LINE__, x)
#else
#define XDBG
#endif

#endif

int checkFile(char *inFileName, int isOutFile);

int getInputFileMode(char *inFile);

int getInFilePtr(char *infile, struct file **inFilePtr);

int getOutFilePtr(char *outFile, struct file **outFilePtr, int infile_mode);

int getCheckSum(struct file *inFilePtr, char *checkSum);

int concat_files(struct file **in_filps, int len, struct file *out_filp);

int concat(filename*,  int, char *outfile);

int getCheckSumWrapper(char *inFile, char*);

int rename(struct file *old, struct file *new);

int renameWrapper(char *old, char *newFile);

int unlinkWrapper(char *inFile);

int unlink(struct file *structfile);

int compress(char *algo, char *inFile, char *outfile, int flag);

