#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <sstream>
#include <queue>

extern "C" {
    #include "taint_mem_log.h"
}

struct TaintMemLogEntry {
    char event[8];
    int sink_id;
    char process_name[MAX_PROCESS_NAME_LENGTH];
    uintptr_t cov_xxhash;
    uintptr_t app_tb_pc;
    int pid;
    uintptr_t gpa;
    uintptr_t gva;
    char op_name[6];
    uint8_t value;
    uint8_t taint_value;
    char value_char;
    char taint_value_char;
};

static std::queue<TaintMemLogEntry> log_queue;
static std::mutex log_mutex;
static std::condition_variable log_cv;
static std::atomic<bool> stop_logging(false);
static std::ofstream log_file;
static constexpr size_t BUFFER_FLUSH_THRESHOLD = 10000;

void log_worker() {
    while (!stop_logging.load()) {
        std::vector<TaintMemLogEntry> local_buffer;
        
        {
            std::unique_lock<std::mutex> lock(log_mutex);
            log_cv.wait(lock, [] { return !log_queue.empty() || stop_logging.load(); });

            while (!log_queue.empty()) {
                local_buffer.push_back(std::move(log_queue.front()));
                log_queue.pop();
            }
        }

        if (!local_buffer.empty()) {
            std::stringstream ss;
            for (const auto &entry : local_buffer) {
                ss << "{\n"
                   << "  \"event\": \"" << entry.event << "\",\n"
                   << "  \"sink_id\": " << entry.sink_id << ",\n";

                if (strcmp(entry.event, "sink") == 0) {
                    ss << "  \"process_name\": \"" << entry.process_name << "\",\n"
                       << "  \"cov_xxhash\": \"0x" << std::hex << entry.cov_xxhash << "\",\n"
                       << "  \"app_tb_pc\": \"0x" << std::hex << entry.app_tb_pc << "\",\n"
                       << "  \"pid\": " << std::dec << entry.pid << ",\n"
                       << "  \"gpa\": \"0x" << std::hex << entry.gpa << "\",\n"
                       << "  \"gva\": \"0x" << std::hex << entry.gva << "\",\n"
                       << "  \"op_name\": \"" << entry.op_name << "\",\n"
                       << "  \"value_hex\": \"0x" << std::hex << static_cast<int>(entry.value) << "\",\n"
                       << "  \"taint_value_hex\": \"0x" << std::hex << static_cast<int>(entry.taint_value) << "\",\n"
                       << "  \"value_char\": \"" << entry.value_char << "\",\n"
                       << "  \"taint_value_char\": \"" << entry.taint_value_char << "\"\n";
                } else if (strcmp(entry.event, "source") == 0) {
                    ss << "  \"value_hex\": \"0x" << std::hex << static_cast<int>(entry.value) << "\",\n"
                       << "  \"value_char\": \"" << entry.value_char << "\",\n"
                       << "  \"gpa\": \"0x" << std::hex << entry.gpa << "\"\n";
                } else if (strcmp(entry.event, "crash") == 0) {
                    ss << "  \"process_name\": \"" << entry.process_name << "\",\n"
                       << "  \"cov_xxhash\": \"0x" << std::hex << entry.cov_xxhash << "\",\n"
                       << "  \"app_tb_pc\": \"0x" << std::hex << entry.app_tb_pc << "\",\n"
                       << "  \"pid\": " << std::dec << entry.pid << "\n";
                }
                ss << "},\n";
            }

            log_file << ss.str();
            log_file.flush();
        }
    }
}

extern "C" void taint_mem_log_cpp(const char *event, const char *json_path, const char *op_name,
                              int sink_id, uintptr_t guest_pc, uintptr_t gpa, uintptr_t gva, int pid,
                              const char *process_name, uint8_t value, uint8_t taint_value,
                              uintptr_t app_tb_pc, uintptr_t cov_xxhash) {
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        log_file.open(json_path, std::ios::trunc);
        if (!log_file.is_open()) {
            std::cerr << "Error opening log file: " << json_path << std::endl;
            return;
        }
        log_file << "[\n";
        std::thread(log_worker).detach();
    });

    if (strcmp(event, "start") == 0) {
        return;
    } 
    else if (strcmp(event, "end") == 0) {
        stop_logging.store(true);
        log_cv.notify_all();
        log_file << "\n]";
        log_file.close();
        return;
    }

    TaintMemLogEntry entry{};
    strncpy(entry.event, event, sizeof(entry.event) - 1);
    entry.sink_id = sink_id;
    strncpy(entry.process_name, process_name, sizeof(entry.process_name) - 1);
    entry.cov_xxhash = cov_xxhash;
    entry.app_tb_pc = app_tb_pc;
    entry.pid = pid;
    entry.gpa = gpa;
    entry.gva = gva;
    strncpy(entry.op_name, op_name, sizeof(entry.op_name) - 1);
    entry.value = value;
    entry.taint_value = taint_value;
    entry.value_char = (value < 32 || value > 126 || value == '"' || value == '\\') ? '.' : static_cast<char>(value);
    entry.taint_value_char = (taint_value < 32 || taint_value > 126 || taint_value == '"' || taint_value == '\\') ? '.' : static_cast<char>(taint_value);

    {
        std::lock_guard<std::mutex> lock(log_mutex);
        log_queue.push(entry);
    }

    if (log_queue.size() >= BUFFER_FLUSH_THRESHOLD) {
        log_cv.notify_one();
    }
}
