#ifndef MEMTRACE_SHM_H
#define MEMTRACE_SHM_H

#define MAX_BUF_SIZE 50000

#define SHM_NAME "/memtrace_shm"
#define MUTEX_SEM_NAME "/mutex_sem"
#define EMPTY_SLOTS_SEM_NAME "/empty_slots_sem"
#define FULL_SLOTS_SEM_NAME "/full_slots_sem"

#define COMMAND_LOAD                  0
#define COMMAND_STORE                 1
#define COMMAND_START_REQ             2
#define COMMAND_END_REQ               3
#define COMMAND_END_REQ_AFTER_WAITPID 4
#define COMMAND_START_SEQ             5
#define COMMAND_END_SEQ_WRITE         6
#define COMMAND_END_SEQ_CLOSE         7
#define COMMAND_END_SEQ_SIGINT        8
#define COMMAND_END_SEQ_SIGTSTP       9
#define COMMAND_END_SEQ_AFTER_WAITPID 10

typedef struct {
    uint8_t command;
    int64_t pc;
    int64_t memoryAddress;
    int64_t value;
} __attribute__((packed)) CommandData;

typedef struct {
    CommandData buffer[MAX_BUF_SIZE];
    int read_index;
    int write_index;
} __attribute__((packed)) CircularBuffer;

#endif