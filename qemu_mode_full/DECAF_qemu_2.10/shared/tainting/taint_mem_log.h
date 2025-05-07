#ifndef TAINT_MEM_LOG_H
#define TAINT_MEM_LOG_H

#include <stdint.h>
#include "extern_vars.h"

#ifdef __cplusplus
extern "C" {
#endif

void taint_mem_log_cpp(const char *event, const char *json_path, const char *op_name,
                              int sink_id, uintptr_t guest_pc, uintptr_t gpa, uintptr_t gva, int pid,
                              const char *process_name, uint8_t value, uint8_t taint_value,
                              uintptr_t app_tb_pc, uintptr_t cov_xxhash);

#ifdef __cplusplus
}
#endif

#endif // TAINT_MEM_LOG_H
