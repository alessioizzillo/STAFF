/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DECAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
#include "qemu/osdep.h"

#include "config.h"
#include <dlfcn.h>
#include <assert.h>
#include <sys/queue.h>
#include "hw/hw.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "hw/hw.h" /* {de,}register_savevm */
#include "cpu.h"
#include "DECAF_main.h"
#include "DECAF_main_internal.h"
#include "shared/tainting/tainting.h"
#include "shared/tainting/taintcheck_opt.h"
#include "shared/DECAF_fileio.h" //zyw
//#include "shared/tainting/taintcheck.h"
#include "shared/DECAF_vm_compress.h"
#include "shared/tainting/taint_memory.h"
#include "tcg.h" // tcg_abort()
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include "taint_mem_log.h"

/*uint64_t*/uint8_t nic_bitmap[1024 * 32 /*/ 64*/]; //!<bitmap for nic

#ifndef min
#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#endif

typedef struct disk_record{
  void *bs;
  uint64_t index;
  uint64_t bitmap;
  LIST_ENTRY(disk_record) entry;
  uint8_t records[0];
} disk_record_t;

#define DISK_HTAB_SIZE (1024)
static LIST_HEAD(disk_record_list_head, disk_record)
        disk_record_heads[DISK_HTAB_SIZE];

int taintcheck_taint_disk(const uint64_t index, const uint32_t taint,
                          const int offset, const int size, const void *bs)
{
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec,  *new_drec;
  int found = 0;
  // AWH int size2 = 0;
  uint64_t taint2 = 0;

  if (taint & 0x000000FF) taint2 |= 1;
  if (taint & 0x0000FF00) taint2 |= 2;
  if (taint & 0x00FF0000) taint2 |= 4;
  if (taint & 0xFF000000) taint2 |= 8;

  //if (taint)
  //  fprintf(stderr, "taintcheck_taint_disk() taint -> 0x%08x\n", taint);

#if 0 // AWH
  if (offset + size > 64) {
    size = 64 - offset, taint &= size_to_mask(size);
    size2 = offset + size - 64;
    taint2 = taint >> offset;
  }
#endif // AWH
  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }
  if (!found) {
    if (!taint)
      return 0;

//fprintf(stderr, "taintcheck_taint_disk() -> Not found w/ taint\n");
    if (!(new_drec = g_malloc0((size_t)sizeof(disk_record_t) /*+
                              64 * temu_plugin->taint_record_size*/)))
      return 0;

    new_drec->index = index;
    new_drec->bs = bs;
    new_drec->bitmap = taint2 << offset;
    LIST_INSERT_HEAD(head, new_drec, entry);
//fprintf(stderr, "taintcheck_taint_disk() -> Adding new taint record\n");
  }
  else {
//fprintf(stderr, "taintcheck_taint_disk() -> Changing taint record\n");
    drec->bitmap &= ~(size_to_mask(size) << offset);
    if (taint) {
      drec->bitmap |= taint2 << offset;
      /*memcpy(drec->records + offset * temu_plugin->taint_record_size,
             record, size * temu_plugin->taint_record_size);*/
    }
    else if (!drec->bitmap) {
      LIST_REMOVE(drec, entry);
      g_free(drec);
    }
  }
#if 0 // AWH
  if (size2)
    taintcheck_taint_disk(index + 1, taint2, 0, size2,
                          /*record + size * temu_plugin->taint_record_size,*/
                          bs);
#endif // AWH
  return 0;
}

uint32_t taintcheck_disk_check(const uint64_t index, const int offset,
                               const int size, const void *bs)
{
  //if(!TEMU_emulation_started) return 0;

  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec;
  int found = 0;
  uint64_t taint;
  uint32_t retval = 0;
  uint32_t ourSize = size;
  if (offset + size > 64)
    ourSize = 64 - offset, taint &= size_to_mask(size);   //fixme:ignore the unalignment

  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }

  if (!found)
    return 0;

  taint = (drec->bitmap >> offset) & size_to_mask(ourSize);
  if (taint & 1) retval |= 0x000000FF;
  if (taint & 2) retval |= 0x0000FF00;
  if (taint & 4) retval |= 0x00FF0000;
  if (taint & 8) retval |= 0xFF000000;
  //fprintf(stderr, "taintcheck_disk_check() -> taint 0x%08x\n", retval);
    //memcpy(record, drec->records + offset * temu_plugin->taint_record_size,
    //       size * temu_plugin->taint_record_size);
  return retval;
}

int taintcheck_init(void)
{
  int i;
  for (i = 0; i < DISK_HTAB_SIZE; i++)
    LIST_INIT(&disk_record_heads[i]);

  // AWH assert(tpage_table == NULL); //make sure it is not double created
  // AWH tpage_table = (tpage_entry_t **) qemu_malloc((ram_size/64) * sizeof(void*));

  return 0;
}

void taintcheck_cleanup(void)
{
  //clean nic buffer
  bzero(nic_bitmap, sizeof(nic_bitmap));
  //clean disk
  //TODO:
  // AWH - deregister_savevm(), first parm NULL
  unregister_savevm(NULL, "taintcheck", 0);
}

int taintcheck_chk_hdout(const int size, const int64_t sect_num,
  const uint32_t offset, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  //uint8_t taint_rec;
  //zyw
  CPUArchState * cpu_single_env = (CPUArchState *)current_cpu->env_ptr;
#if defined(TARGET_MIPS)
  int taint = cpu_single_env->tempidx;
  if (size > 4) tcg_abort();

  //taint_rec = taint_reg_check_slow(reg, 0, size);
  taintcheck_taint_disk(sect_num * 8 + offset / 64, taint, offset & 63,
                        size,
                        /*regs_records +
                        reg * temu_plugin->taint_record_size,*/ s);
#endif
#endif /* CONFIG_TCG_TAINT */
  return 0;
}

int taintcheck_chk_hdin(const int size, const int64_t sect_num,
  const uint32_t offset, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  //zyw
  CPUArchState * cpu_single_env = (CPUArchState *)current_cpu->env_ptr;
#if defined(TARGET_MIPS)
  /*taint_rec*/ cpu_single_env->tempidx =
      taintcheck_disk_check(sect_num * 8 + offset / 64, offset & 63, size,
                            /*records,*/ s);
#endif
#endif /*CONFIG_TCG_TAINT*/
  return 0;
}

int taintcheck_chk_hdwrite(const ram_addr_t paddr,unsigned long vaddr, const int size,
  const int64_t sect_num, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  uint32_t i;

  if ((paddr & 63))
    return 0;

  for (i = paddr; i < paddr + size; i += 4) {
    __taint_ldl_raw_paddr(0, i, vaddr+i-paddr, -1);
    CPUArchState * cpu_single_env = (CPUArchState *)current_cpu->env_ptr;
    //if (cpu_single_env->tempidx) fprintf(stderr, "taintcheck_chk_hdwrite() -> Writing taint 0x%08x to disk\n", cpu_single_env->tempidx);
#if defined(TARGET_MIPS)
    taintcheck_taint_disk(sect_num * 8 + (i - paddr) / 64,
                          /*(entry) ? entry->bitmap[((paddr & 63) >> 2)] : 0*/cpu_single_env->tempidx, 0, 4/*size*/,
                          /*(entry) ? entry->records : NULL,*/ s);
#endif
  } // end for
#endif /* CONFIG_TCG_TAINT */
  return 0;
}

int taintcheck_chk_hdread(const ram_addr_t paddr,unsigned long vaddr, const int size,
		const int64_t sect_num, const void *s) {
#ifdef CONFIG_TCG_TAINT
	unsigned long i;
	CPUArchState * cpu_single_env = (CPUArchState *)current_cpu->env_ptr;
#if defined(TARGET_MIPS)
	for (i = paddr; i < paddr + size; i += 4) {
		cpu_single_env->tempidx = taintcheck_disk_check(
				sect_num * 8 + (i - paddr) / 64, 0, 4, s);
		__taint_stl_raw_paddr(0, i, vaddr+i-paddr, -1);
	}
#endif
#endif /* CONFIG_TCG_TAINT */
	return 0;
}

#ifdef CONFIG_TCG_TAINT

/// \brief check the taint of a memory buffer given the start virtual address.
///
/// \param vaddr the virtual address of the memory buffer
/// \param size  the memory buffer size
/// \param taint the output taint array, it must hold at least [size] bytes
///  \return 0 means success, -1 means failure
int  taintcheck_check_virtmem(gva_t vaddr, uint32_t size, uint8_t * taint)
{
	gpa_t paddr = 0, offset;
	uint32_t size1, size2;
	// uint8_t taint=0;
	CPUState *env;
	//zyw
	env = current_cpu ? current_cpu : first_cpu;

	// AWH - If tainting is disabled, return no taint
	if (!taint_tracking_enabled) {
		bzero(taint, size);
		return 0;
	}

	paddr = DECAF_get_phys_addr(env,vaddr);
	if(paddr == -1) return -1;

	offset = vaddr& ~TARGET_PAGE_MASK;
	if(offset+size > TARGET_PAGE_SIZE) {
		size1 = TARGET_PAGE_SIZE-offset;
		size2 = size -size1;
	} else
		size1 = size, size2 = 0;

	taint_mem_check(paddr, size1, taint);
	if(size2) {
		paddr = DECAF_get_phys_addr(env, (vaddr&TARGET_PAGE_MASK) + TARGET_PAGE_SIZE);
		if(paddr == -1)
			return -1;

		taint_mem_check(paddr, size2, (uint8_t*)(taint+size1));
	}

	return 0;
}

int taintcheck_taint_physmem(uint32_t addr,int size,uint8_t *taint)
{
	taint_mem(addr, size, taint);
  return 0;
}

/// \brief set taint for a memory buffer given the start virtual address.
///
/// \param vaddr the virtual address of the memory buffer
/// \param size  the memory buffer size
/// \param taint the taint array, it must hold at least [size] bytes
/// \return 0 means success, -1 means failure
int  taintcheck_taint_virtmem(gva_t vaddr, uint32_t size, uint8_t * taint)
{
	gpa_t paddr = 0, offset;
	uint32_t size1, size2;
	// uint8_t taint=0;
	CPUState *env;
	//zyw
	env = current_cpu ? current_cpu : first_cpu;

	// AWH - If tainting is disabled, return no taint
	if (!taint_tracking_enabled) {
		return 0;
	}

	paddr = DECAF_get_phys_addr(env,vaddr);
	if(paddr == -1) return -1;

	offset = vaddr& ~TARGET_PAGE_MASK;
	if(offset+size > TARGET_PAGE_SIZE) {
		size1 = TARGET_PAGE_SIZE-offset;
		size2 = size -size1;
	} else
		size1 = size, size2 = 0;

	taint_mem(paddr, size1, taint);
	if(size2) {
		paddr = DECAF_get_phys_addr(env, (vaddr&TARGET_PAGE_MASK) + TARGET_PAGE_SIZE);
		if(paddr == -1)
			return -1;

		taint_mem(paddr, size2, (uint8_t*)(taint+size1));
	}

	return 0;
}



void taintcheck_nic_writebuf(const uint32_t addr, const int size, const uint8_t * taint)
{
	memcpy(&nic_bitmap[addr], taint, size);
}

void taintcheck_nic_readbuf(const uint32_t addr, const int size, uint8_t *taint)
{
  memcpy(taint, &nic_bitmap[addr], size);
}

void taintcheck_nic_cleanbuf(const uint32_t addr, const int size)
{
	memset(&nic_bitmap[addr], 0, size);
}

int get_next_log_id(const char *syscall_dir, const char *syscall_name) {
    int id = 0;
    char log_file[256];

    while (1) {
        snprintf(log_file, sizeof(log_file), "%s/%s_%d.log", syscall_dir, syscall_name, id);
        if (access(log_file, F_OK) == -1) {
            break;
        }
        id++;
    }
    return id;
}

#define MAX_BUF_SIZE 4096
#define NUM_BUFFERS 8

static uint8_t qem_trace_current_buffer = 0;
static uint32_t qem_trace_buffer_sizes[NUM_BUFFERS] = {0};
static uint8_t qem_trace_buffer[NUM_BUFFERS][MAX_BUF_SIZE * sizeof(TaintEvent)];
static uint64_t qem_file_size = 0;
static FILE* qem_trace_file_fd;
static pthread_mutex_t qem_trace_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qem_trace_buffer_cond = PTHREAD_COND_INITIALIZER;
static pthread_t qem_trace_flush_thread;

static void* flush_routine(void* arg) {
  uint8_t last_buffer = (uint8_t)(uintptr_t)arg;
  int ret;
  size_t total_written = 0;
  size_t bytes_to_write = qem_trace_buffer_sizes[last_buffer] * sizeof(TaintEvent);
  size_t write_size = sizeof(TaintEvent);
  
  while (total_written < bytes_to_write) {
    ret = fwrite(qem_trace_buffer[last_buffer] + total_written, write_size, (bytes_to_write - total_written) / write_size, qem_trace_file_fd);
    if (ret < 0) {
      perror("Error writing to file");
      exit(1);
    }
    total_written += ret * write_size;
  }

  fflush(qem_trace_file_fd);
  
  qem_trace_buffer_sizes[last_buffer] = 0;

  return NULL;
}

void taint_log_init() {
  int error;

  qem_trace_file_fd = fopen(taint_json_path, "w");
  if (qem_trace_file_fd == NULL) {
    perror("Error opening taint log file");
    exit(1);
  }
}

void taint_log_close(void) {
  int ret;

  ret = pthread_mutex_lock(&qem_trace_buffer_mutex);
  if (ret != 0) {
    perror("Error locking mutex");
    exit(1);
  }

  if (qem_trace_buffer_sizes[qem_trace_current_buffer] != 0) {
    flush_routine((void*)(uintptr_t)qem_trace_current_buffer);
  }

  ret = pthread_mutex_unlock(&qem_trace_buffer_mutex);
  if (ret != 0) {
    perror("Error unlocking mutex");
    exit(1);
  }

  if (fclose(qem_trace_file_fd) < 0) {
    perror("Error closing taint log file");
    exit(1);
  }
}

void taint_mem_log(uint8_t event, uint32_t pc, uint32_t pid, uint32_t gpa, uint8_t op_name, uint8_t value) {
  int error;
  uint8_t last_buffer;

  if (sink_id != -1)
    taint_mem_ops_count++;

  if (qem_trace_buffer_sizes[qem_trace_current_buffer] >= MAX_BUF_SIZE) {
    last_buffer = qem_trace_current_buffer;

    error = pthread_mutex_lock(&qem_trace_buffer_mutex);
    if (error != 0) {
      perror("Error locking mutex");
      exit(1);
    }

    error = pthread_create(&qem_trace_flush_thread, NULL, flush_routine, (void*)(uintptr_t)last_buffer);
    if (error != 0) {
      perror("Error creating flush thread");
      exit(1);
    }
    error = pthread_detach(qem_trace_flush_thread);
    if (error != 0) {
      perror("Error detaching flush thread");
      exit(1);
    }

    qem_trace_current_buffer = (qem_trace_current_buffer + 1) % NUM_BUFFERS;

    error = pthread_mutex_unlock(&qem_trace_buffer_mutex);
    if (error != 0) {
      perror("Error unlocking mutex");
      exit(1);
    }
  }

  TaintEvent new_trace;
  new_trace.event = event;
  new_trace.sink_id = sink_id;
  new_trace.cov_xxhash = get_coverage_value(pid, "xxhash", 1);
  new_trace.app_tb_pc = get_coverage_value(pid, "app_tb_pc", 0);
  new_trace.gpa = gpa;
  new_trace.op_name = op_name;
  new_trace.value = value;
  new_trace.inode = get_coverage_value(pid, "app_tb_pc", 1);

  uint64_t offset = qem_trace_buffer_sizes[qem_trace_current_buffer] * sizeof(TaintEvent);
  memcpy(qem_trace_buffer[qem_trace_current_buffer] + offset, &new_trace, sizeof(TaintEvent));
  ++qem_trace_buffer_sizes[qem_trace_current_buffer];
}

// static TaintEvent** taint_buffers = NULL;
// static atomic_int* buffer_sizes = NULL;
// static int current_buffer = 0;
// static sem_t buffer_sem;
// static pthread_t* flush_threads = NULL;
// static int taint_fd = -1;
// static struct io_uring ring;
// static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
// volatile sig_atomic_t sigint_received = 0;
// sem_t flush_complete_sem;

// void* flush_routine(void* arg) {
//     while (1) {
//         sem_wait(&buffer_sem);

//         pthread_mutex_lock(&flush_mutex);
//         int buffer_to_flush = (current_buffer + num_buffers - 1) % num_buffers;
//         size_t bytes_to_write = atomic_load(&buffer_sizes[buffer_to_flush]) * sizeof(TaintEvent);

//         // Ensure there's data to write before proceeding
//         if (bytes_to_write > 0) {
//             // Check if the first event in the buffer is zeroed
//             if (taint_buffers[buffer_to_flush][0].cov_xxhash == 0) {
//                 FILE* fd = fopen("CHECK", "a+");
//                 fprintf(fd, "Buffer %d: First event is zeroed, no valid data to write.\n", buffer_to_flush);
//                 fclose(fd);
//             }

//             struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
//             io_uring_prep_write(sqe, taint_fd, taint_buffers[buffer_to_flush], bytes_to_write, -1);
//             io_uring_submit(&ring);
//         }

//         // Do not reset the buffer size yet, wait for completion
//         pthread_mutex_unlock(&flush_mutex);

//         if (bytes_to_write > 0) {
//             // Wait until io_uring finishes writing before resetting the buffer size
//             struct io_uring_cqe* cqe;
//             io_uring_wait_cqe(&ring, &cqe);
//             io_uring_cqe_seen(&ring, cqe);  // Acknowledge completion

//             // Reset buffer size only after data has been written
//             atomic_store(&buffer_sizes[buffer_to_flush], 0);
//         }

//         if (sigint_received) {
//             sem_post(&flush_complete_sem);
//             break;
//         }
//     }
//     return NULL;
// }



// void taint_log_init(const char* filepath) {
//     taint_fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0666);
//     if (taint_fd < 0) {
//         perror("Error opening taint file");
//         exit(1);
//     }

//     sigint_received = 0;
//     taint_buffers = malloc(num_buffers * sizeof(TaintEvent*));
//     buffer_sizes = malloc(num_buffers * sizeof(atomic_int));
//     flush_threads = malloc(num_flush_threads * sizeof(pthread_t));

//     for (int i = 0; i < num_buffers; i++) {
//         taint_buffers[i] = mmap(NULL, max_buf_size * sizeof(TaintEvent), 
//                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//         if (taint_buffers[i] == MAP_FAILED) {
//             perror("mmap failed");
//             exit(1);
//         }
//         atomic_init(&buffer_sizes[i], 0);
//     }

//     sem_init(&buffer_sem, 0, 0);
//     io_uring_queue_init(32, &ring, 0);

//     for (int i = 0; i < num_flush_threads; i++) {
//         pthread_create(&flush_threads[i], NULL, flush_routine, NULL);
//     }
// }

// void taint_log_close() {
//     sigint_received = 1;

//     if (atomic_load(&buffer_sizes[current_buffer]) > 0) {
//       sem_post(&buffer_sem);
//     }

//     if (sigint_received) {
//         sem_wait(&flush_complete_sem);

//         if (atomic_load(&buffer_sizes[current_buffer]) == 0) {
//             close(taint_fd);
//             sem_destroy(&buffer_sem);
//             io_uring_queue_exit(&ring);

//             for (int i = 0; i < num_buffers; i++) {
//                 munmap(taint_buffers[i], max_buf_size * sizeof(TaintEvent));
//             }
//             free(taint_buffers);
//             free(buffer_sizes);
//             free(flush_threads);
//         }
//         else {
//           FILE *fd = fopen("CHECK","a+"); 
//           fprintf(fd, "ERROR: %d, %d\n", current_buffer, atomic_load(&buffer_sizes[current_buffer]));
//           fclose(fd);          
//         }
//     }
// }


// void taint_mem_log(uint8_t event, uint32_t pc, uint32_t pid, uint32_t gpa, uint8_t op_name, uint8_t value) {
//     int index = atomic_fetch_add(&buffer_sizes[current_buffer], 1);
    
//     if (index >= max_buf_size) {
//         pthread_mutex_lock(&flush_mutex);
//         current_buffer = (current_buffer + 1) % num_buffers;
//         pthread_mutex_unlock(&flush_mutex);
        
//         sem_post(&buffer_sem);
//         index = atomic_fetch_add(&buffer_sizes[current_buffer], 1);
//     }

//     int adjusted_pc = 0;
//     uint64_t inode_num = 0;
//     get_pc_text_info_wrapper(pid, pc, &adjusted_pc, &inode_num);
//     uint32_t cov_xxhash = get_coverage_value(pid, "xxhash", 1);
//     uint32_t app_tb_pc = get_coverage_value(pid, "app_tb_pc", 0);

//     TaintEvent* buf_ptr = &taint_buffers[current_buffer][index];
//     buf_ptr->event = event;
//     buf_ptr->sink_id = sink_id;
//     buf_ptr->cov_xxhash = cov_xxhash;
//     buf_ptr->app_tb_pc = app_tb_pc;
//     buf_ptr->gpa = gpa;
//     buf_ptr->op_name = op_name;
//     buf_ptr->value = value;
//     buf_ptr->inode = inode_num;
// }

void taint_log(unsigned char *buffer, bool *taint_map, unsigned char *addr, int size, const char *base_dir,
                const char *syscall_name, int pid, const char *process_name) {
    char dir[256], log_file[256];

    snprintf(dir, sizeof(dir), "%s/%s/%s/", base_dir, proto, pcap_filename);
    snprintf(log_file, sizeof(log_file), "%s/taint.json", dir);

    FILE *file = fopen(log_file, "a+");
    if (file == NULL) {
        perror("Error opening taint file");
        return;
    }

    fprintf(file, "{\n");
    fprintf(file, "  \"process_name\": \"%s\",\n", process_name);
    fprintf(file, "  \"pid\": %d,\n", pid);
    fprintf(file, "  \"syscall_name\": \"%s\",\n", syscall_name);
    fprintf(file, "  \"sink_id\": %d,\n", sink_id);

    fprintf(file, "  \"buffer_address\": \"0x%lx\",\n", (unsigned char *)addr);

    fprintf(file, "  \"buffer_hex\": \"");
    for (int i = 0; i < size; i++) {
        fprintf(file, "%02X", buffer[i]);
    }
    fprintf(file, "\",\n");

    fprintf(file, "  \"buffer_str\": \"");
    for (int i = 0; i < size; i++) {
        unsigned char c = buffer[i];
        if (c < 32 || c > 126 || c == '"') {
            fprintf(file, ".");
        } else {
            fprintf(file, "%c", c);
        }
    }
    fprintf(file, "\",\n");

    fprintf(file, "  \"tainted_bytes\": [\n");

    bool first_entry = true;
    for (int i = 0; i < size; i++) {
        if (taint_map[i]) {
            if (!first_entry) {
                fprintf(file, ",\n");
            }
            fprintf(file, "    { \"index\": %d, \"address\": \"0x%lx\", \"byte\": \"0x%02X\", \"char\": \"%c\" }",
                    i, (unsigned long)&addr[i], buffer[i], (buffer[i] >= 32 && buffer[i] <= 126 && buffer[i] != '"') ? buffer[i] : '.');
            first_entry = false;
        }
    }
    fprintf(file, "\n  ]\n");

    fprintf(file, "}\n");

    fclose(file);
}

void log_taint_sink(unsigned char *buffer, bool *taint_map, unsigned char *addr, int size, const char *base_dir,
                    const char *syscall_name, int pid, const char *process_name) {
    char process_dir[256], syscall_dir[256], log_file[256];

    snprintf(process_dir, sizeof(process_dir), "%s/%s/%s/sinks/%d/process_%d_%s", base_dir, proto, pcap_filename, sink_id, pid, process_name);

    snprintf(syscall_dir, sizeof(syscall_dir), "%s/%s", process_dir, syscall_name);
    create_nested_directories(syscall_dir);

    int log_id = get_next_log_id(syscall_dir, syscall_name);
    snprintf(log_file, sizeof(log_file), "%s/%s_%d.log", syscall_dir, syscall_name, log_id);

    FILE *file = fopen(log_file, "w");
    if (file == NULL) {
        perror("Error opening taint file");
        return;
    }

    fprintf(file, "Process: %s (PID: %d)\n", process_name, pid);
    fprintf(file, "Syscall: %s\n", syscall_name);

    fprintf(file, "Buffer 0x%lx (as string):\n\n", addr);
    for (int i = 0; i < size; i++) {
        fputc(buffer[i], file);
    }
    fprintf(file, "\n");

    fprintf(file, "Taint Analysis of Buffer:\n");
    fprintf(file, "----------------------------------\n");

    for (int i = 0; i < size; i++) {
        unsigned char taint_status = taint_map[i] ? 0x01 : 0x00;
        fprintf(file, "[%d] - 0x%02X ('%c') - Taint: 0x%02X\n", i, buffer[i], (buffer[i] >= 32 && buffer[i] <= 126) ? buffer[i] : '.', taint_status);
    }

    fprintf(file, "----------------------------------\n");

    fclose(file);
}

void log_taint_source(unsigned char *buffer, bool *taint_map, unsigned char *addr, int size,
                      const char *base_dir, const char *source_name) {
    char source_dir[256], log_file[256];

    snprintf(source_dir, sizeof(source_dir), "%s/%s/%s/sources/%s/", base_dir, proto, pcap_filename, source_name);

    snprintf(log_file, sizeof(log_file), "%s/src_%d.log", source_dir, sink_id);

    FILE *file = fopen(log_file, "w");
    if (file == NULL) {
        perror("Error opening taint file");
        return;
    }

    fprintf(file, "Buffer 0x%lx (as string):\n\n", addr);
    for (int i = 0; i < size; i++) {
        fputc(buffer[i], file);
    }
    fprintf(file, "\n");

    fprintf(file, "Taint Analysis of Buffer:\n");
    fprintf(file, "----------------------------------\n");

    for (int i = 0; i < size; i++) {
        unsigned char taint_status = taint_map[i] ? 0x01 : 0x00;
        fprintf(file, "[%d] - 0x%02X ('%c') - Taint: 0x%02X\n", i, buffer[i], (buffer[i] >= 32 && buffer[i] <= 126) ? buffer[i] : '.', taint_status);
    }

    fprintf(file, "----------------------------------\n");

    fclose(file);
}


#endif //CONFIG_TCG_TAINT
