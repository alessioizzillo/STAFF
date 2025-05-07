#ifndef DECAF_FILEIO_H
#define DECAF_FILEIO_H

#include "tsk/libtsk.h"
#include "extern_vars.h"

// AVB, this struct is used to store info about the disk images opened by qemu
// We use this to open the disk using Sleuthkit and read files from it
typedef struct {
  TSK_FS_INFO *fs;
  TSK_IMG_INFO *img;
  void *bs;
} disk_info_t;


// List of loaded disk images
// This could be more than 5. We just assume 5 for now
extern disk_info_t disk_info_internal[5];

extern uint64_t fs_offset;
extern int block_size;
extern uint32_t sink_id;

#ifdef __cplusplus

int add_base_addr(int pid, uint64_t inode_num, uintptr_t base_addr, const std::string &module_name);
void copy_inode_trace_to_shmem(int pid, char proc_name[MAX_PROCESS_NAME_LENGTH], trace_t *cur_crashes);
void insert_inode_pc_trace(int pid, uint64_t inode, uint32_t pc);
int get_func_and_module_name(int pid, uintptr_t pc, std::string &func_name, std::string &module_name);
int get_pc_text_info(int pid, uintptr_t pc, int &adjusted_pc, TSK_INUM_T &inode_num);
int get_module_name_from_inode(int pid, uint64_t inode, char name_buf[MAX_MODULE_NAME_LENGTH]);

extern "C" {
#endif

extern void process_fs_info(TSK_FS_INFO *fs, int debug);

extern void handle_open_syscall(int pid, int fd, const char *path, int mode);
extern void handle_chdir_syscall(int pid, const char *path);
extern void handle_fchdir_syscall(int pid, int fd);
extern void handle_chroot_syscall(int pid, const char *path);
extern void handle_close_syscall(int pid, int fd);

// Store functions
extern void handle_write_syscall(int pid, int fd);
extern void handle_unlink_syscall(int pid, const char *path);
extern void handle_rename_syscall(int pid, const char *old_path, const char *new_path);
extern void handle_mkdir_syscall(int pid, const char *path);
extern void handle_rmdir_syscall(int pid, const char *path);
extern void handle_truncate_syscall(int pid, const char *path, off_t length);
extern void handle_ftruncate_syscall(int pid, int fd, off_t length);
extern void handle_symlink_syscall(int pid, const char *target, const char *linkpath);
extern void handle_link_syscall(int pid, const char *target, const char *linkpath);
extern void handle_fsync_syscall(int pid, int fd);
extern void handle_fdatasync_syscall(int pid, int fd);

// Load functions
extern void handle_read_syscall(int pid, int fd);
extern void handle_stat_syscall(int pid, const char *path);
extern void handle_lstat_syscall(int pid, const char *path);
extern void handle_fstat_syscall(int pid, int fd);
extern void handle_getdents_syscall(int pid, int fd);
extern void handle_access_syscall(int pid, const char *path);
extern void handle_faccessat_syscall(int pid, const char *path);
extern void handle_statfs_syscall(int pid, const char *path);

extern void output_sink_relations_to_json(const char* output_file);

void insert_coverage_value(int pid, const char* cov_name, int value, int index);
int get_coverage_value(int pid, const char* cov_name, int index);
void remove_coverage_by_pid(int pid);
void insert_syscall_value(int pid, const char* cov_name, int value);
int get_syscall_value(int pid, const char* cov_name);
void remove_syscall_by_pid(int pid);
void insert_accept_fd(int pid, int fd);
void copy_accept_fds(int src_pid, int dst_pid);
int is_accept_fd_open(int pid, int fd);
void remove_accept_fd(int pid, int fd);
void remove_pid(int pid);
void clear_storage();
#ifdef __cplusplus
}
#endif

#endif