#ifndef TAINT_METRICS_DRIVEN_QUEUE_H
#define TAINT_METRICS_DRIVEN_QUEUE_H

#include "config2.h"
#include "alloc-inl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int region_num;
    int offset;
    int length;
    int *regions_to_keep;
} QueueElement;

void initialize_queue(char* fn, char* out_dir, const char* config_file, int debug);
int fetch_element_from_alias_app_tb_pc(char* alias, QueueElement* result);
int fetch_element_from_alias_cov(char* alias, QueueElement* result);
void add_alias_app_tb_pc(char* fn, char* alias);
void add_alias_cov(char* fn, char* alias);
void rename_alias(char* old_alias, char* new_alias);

#ifdef __cplusplus
}
#endif

#endif  // TAINT_METRICS_DRIVEN_QUEUE_H
