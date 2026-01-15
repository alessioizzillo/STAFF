import os
import subprocess
import signal
import shutil
import re
import fcntl
import errno
import time
import pyshark
import socket
import argparse
import configparser
from analysis.convert_pcap import convert_pcap_into_single_seed_file, convert_pcap_into_multiple_seed_files
from analysis.taint_analysis import taint, pre_analysis_exp, cleanup
import csv
import stat
import glob
import tempfile
import angr
import tarfile
from FirmAE.sources.extractor.extractor import Extractor
from typing import Dict, Optional, Tuple, List
import bisect
import sys
from itertools import groupby
from datetime import datetime
import capstone

SKIP_MODULES = {("dap2310_v1.00_o772.bin", "any", "neaps_array"), ("dap2310_v1.00_o772.bin", "any", "neapc"),
                ("dap2310_v1.00_o772.bin", "any", "ethlink"), ("dap2310_v1.00_o772.bin", "any", "aparraymsg"),
                ("dir300_v1.03_7c.bin", "any", "ethlink"), ("dir300_v1.03_7c.bin", "any", "aparraymsg"), 
                ("FW_RT_N10U_B1_30043763754.zip", "any", "u2ec"), ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "potcounter"),
                ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "busybox"), ("FW_RE1000_1.0.02.001_US_20120214_SHIPPING.bin", "any", "upnp"),
                ("FW_WRT320N_1.0.05.002_20110331.bin", "any", "upnp"), ("TL-WPA8630_US__V2_171011.zip", "any", "wifiSched"),
                ("JNR3210_Firmware_Version_1.1.0.14.zip", "any", "busybox"), ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "any", "unknown"),
                ("FW_RT_N53_30043763754.zip", "any", "rc"), ("FW_TV-IP651WI_V1_1.07.01.zip", "aflnet_base", "alphapd"),
                ("FW_TV-IP651WI_V1_1.07.01.zip", "aflnet_state_aware", "alphapd"), ("JNR3210_Firmware_Version_1.1.0.14.zip", "any", "rc"),
                ("dir300_v1.03_7c.bin", "triforce", "xmldb"), ("TL-WPA8630_US__V2_171011.zip", "triforce", "ledschd"), 
                ("DGN3500-V1.1.00.30_NA.zip", "triforce", "setup.cgi"), ("DGND3300_Firmware_Version_1.1.00.22__North_America_.zip", "triforce", "setup.cgi")}

patterns = [
    "FirmAE/scratch/staff*",
    "FirmAE/scratch/aflnet*",
    "FirmAE/scratch/triforce*",
    "FirmAE/scratch/pre_analysis*",
    "FirmAE/scratch/pre_exp*",
    "FirmAE/scratch/crash_analysis*",
    "FirmAE/images/staff*",
    "FirmAE/images/aflnet*",
    "FirmAE/images/triforce*",
    "FirmAE/images/pre_analysis*",
    "FirmAE/images/pre_exp*",
    "FirmAE/images/crash_analysis*",
    "FirmAE/firm_db_aflnet*",
    "FirmAE/firm_db_staff*",
    "FirmAE/firm_db_triforce*",
    "FirmAE/firm_db_pre_analysis*",
    "FirmAE/firm_db_pre_exp*",
    "FirmAE/firm_db_crash_analysis*",
]

DEFAULT_CONFIG = {
    "GENERAL": {
        "mode": ("run", str),
        "firmware": ("dlink/dap2310_v1.00_o772.bin", str)
    },
    "CAPTURE": {
        "whitelist_keywords": ("POST/PUT/.php/.cgi/.xml", str),
        "blacklist_keywords": (".gif/.jpg/.png/.css/.js/.ico/.htm/.html", str)
    },
    "PRE-ANALYSIS": {
        "pre_analysis_id": (0, int),
        "subregion_divisor": (10, int),
        "min_subregion_len": (3, int),
        "delta_threshold": (0.15, float)
    },
    "EMULATION_TRACING": {
        "include_libraries": (1, int)
    },
    "GENERAL_FUZZING": {
        "map_size_pow2": (25, int),
        "fuzz_tmout": (86400, int),
        "timeout": (120, int),
        "afl_no_arith": (1, int),
        "afl_no_bitflip": (0, int),
        "afl_no_interest": (1, int),
        "afl_no_user_extras": (1, int),
        "afl_no_extras": (1, int),
        "afl_calibration": (1, int),
        "afl_shuffle_queue": (1, int)
    },
    "AFLNET_FUZZING": {
        "region_delimiter": ("\x1A\x1A\x1A\x1A", bytes),
        "proto": ("http", str),
        "region_level_mutation": (1, int)
    },
    "STAFF_FUZZING": {
        "taint_hints_all_at_once": (0, int),
        "sequence_minimization": (1, int),
        "taint_metrics": ("rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes", str),
        "checkpoint_strategy": (1, int)
    },    
    "EXTRA_FUZZING": {
        "coverage_tracing": ("taint_block", str),
        "stage_max": (1, int)
    },
    "TEST": {
        "seed_input": ("", str),
        "port": (80, int),
        "timeout": (150, int),
        "process_name": ("", str)
    }
}

STAFF_DIR = os.getcwd()
EXPERIMENTS_DIR_0 = os.path.join(STAFF_DIR, "experiments_0")
CRASH_DIR = os.path.join(STAFF_DIR, "extracted_crashes")
FIRMAE_DIR = os.path.join(STAFF_DIR, "FirmAE")
PCAP_DIR = os.path.join(STAFF_DIR, "pcap")
TAINT_DIR = os.path.join(STAFF_DIR, "pre_analysis_db")
FIRMWARE_DIR = os.path.join(STAFF_DIR, "firmwares")
ANALYSIS_DIR = os.path.join(STAFF_DIR, "analysis")
CONFIG_INI_PATH=os.path.join(STAFF_DIR, "config.ini")
SCHEDULE_CSV_PATH_0=os.path.join(STAFF_DIR, "schedule_0.csv")
SCHEDULE_CSV_PATH_1=os.path.join(STAFF_DIR, "schedule_1.csv")
EXP_DONE_PATH=os.path.join(STAFF_DIR, "experiments_done")
PRE_ANALYSIS_EXP_DIR=os.path.join(STAFF_DIR, "pre_analysis_exp5_new")
CRASH_ANALYSIS_LOG=os.path.join(STAFF_DIR, "crash_analysis.log")
CRASH_PROCESSING_LOG = os.path.join(STAFF_DIR, "crash_analysis_processed.log")
CRASH_SEED_COUNT_LOG = os.path.join(STAFF_DIR, "crash_seed_count.log")
CRASH_REPORTS_DIR = os.path.join(STAFF_DIR, "crash_reports_analysis")
CRASH_ANALYSIS_PROMPT_FILE = os.path.join(CRASH_REPORTS_DIR, "ANALYZE_ALL_CRASHES_PROMPT.md")

removed_wait_for_container_init = False
captured_pcap_path = None
PSQL_IP = None
config = None

def find_firmware_with_brand(firmware_name):
    if os.path.dirname(firmware_name):
        return firmware_name

    for brand in os.listdir(FIRMWARE_DIR):
        brand_path = os.path.join(FIRMWARE_DIR, brand)
        if not os.path.isdir(brand_path):
            continue

        firmware_path = os.path.join(brand_path, firmware_name)
        if os.path.exists(firmware_path):
            return os.path.join(brand, firmware_name)

    return None

def set_permissions_recursive(dir_path):
    for root, dirs, files in os.walk(dir_path):
        for d in dirs:
            os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        
        for f in files:
            os.chmod(os.path.join(root, f), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

def update_schedule_status(schedule_csv_path, status, exp_name):
    lock = open(os.path.join(os.path.dirname(schedule_csv_path), "schedule.lock"), 'w')
    fcntl.lockf(lock, fcntl.LOCK_EX)

    updated_rows = []
    with open(schedule_csv_path, "r") as infile:
        reader = csv.reader(infile)
        
        try:
            header1 = next(reader)
            header2 = next(reader)
        except StopIteration:
            print("CSV file is empty or missing headers. Exiting...")
            return

        updated_rows.append(header1)
        updated_rows.append(header2)

        status_idx = header2.index("status")
        exp_name_idx = header2.index("exp_name")
        container_name_idx = header2.index("container_name")

        for row in reader:
            if len(row) > 1:
                if row[exp_name_idx] == exp_name:
                    row[status_idx] = status
                updated_rows.append(row)

    with open(schedule_csv_path, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(updated_rows)

    fcntl.lockf(lock, fcntl.LOCK_UN)

def get_taint_dir(pre_analysis_id, taint_db):
    if not os.path.exists(taint_db):
        os.makedirs(taint_db, exist_ok=True)
        os.chmod(taint_db, 0o777)

    if pre_analysis_id is None or pre_analysis_id < 0:
        pre_analysis_id = 0

    taint_dir = os.path.join(taint_db, f"pre_analysis_{pre_analysis_id}")
    return taint_dir

def get_pcap_application_layer_protocol(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    fourth_layers = []

    for packet in capture:
        layers = packet.layers

        if len(layers) >= 4:
            fourth_layer = layers[3].layer_name
            fourth_layers.append(fourth_layer)

    filtered_layers = [layer for layer in fourth_layers if layer != "DATA"]

    if filtered_layers:
        if all(layer == filtered_layers[0] for layer in filtered_layers):
            return filtered_layers[0]
        else:
            return "mixed"
    else:
        return "none"

def cleanup_and_exit(work_dir):
    cleanup(FIRMAE_DIR, work_dir)
    print("[+] ..End")
    exit(0)

def send_signal_recursive(target_pid, signal_code):
    try:
        child_pids = subprocess.check_output(["sudo", "-E", "pgrep", "-P", str(target_pid)]).decode('utf-8').splitlines()
        for child_pid in child_pids:
            send_signal_recursive(int(child_pid), signal_code)
    except subprocess.CalledProcessError:
        pass
    finally:
        os.kill(target_pid, signal_code)

def get_next_filename(directory_path, word):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        os.chmod(directory_path, 0o777)

    pattern = "{}_([0-9]+).*".format(word)

    highest_i = -1
    for filename in os.listdir(directory_path):
        match = re.match(pattern, filename)
        if match:
            i = int(match.group(1))
            if i > highest_i:
                highest_i = i

    next_i = highest_i + 1
    return "{}_{}".format(word, next_i)

def run_capture_signal_handler(signum, frame):
    global config
    global captured_pcap_path

    if config["GENERAL"]["mode"] == "run_capture":
        time.sleep(1)

        dst_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]), get_pcap_application_layer_protocol(captured_pcap_path))

        if not os.path.exists(dst_dir):
            os.makedirs(dst_dir)
        try:
            next_pcap_name = get_next_filename(dst_dir, "user_interaction")
            final_pcap_path = os.path.join(dst_dir, "{}.pcap".format(next_pcap_name))
            shutil.move(captured_pcap_path, final_pcap_path)
            print(f"[INFO] File moved to {final_pcap_path}")
        except Exception as e:
            print(f"[ERROR] Failed to move file: {e}")
        
        set_permissions_recursive(PCAP_DIR)

    exit(0)

def copy_file(src_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    filename = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, filename)
    shutil.copy2(src_path, dest_path)

def fast_copytree(source, destination, delay=1):
    os.makedirs(os.path.dirname(destination.rstrip("/")), exist_ok=True)

    while True:
        result = subprocess.run(
            ["rsync", "-a", "--info=progress2", source + "/", destination],
            capture_output=True
        )

        if result.returncode in (0, 24):
            return

        print(f"[!] rsync failed with code {result.returncode}. Retrying in {delay}s...")
        if result.stderr:
            print(result.stderr.decode(errors="ignore"))
        time.sleep(delay)

def replace_pattern_in_file(file_path, pattern, replacement):
    with open(file_path, 'r') as file:
        content = file.read()

    content = re.sub(pattern, replacement, content)

    with open(file_path, 'w') as file:
        file.write(content)

def copy_image(dst_mode, firmware):
    src_iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, "run"]).decode('utf-8').strip()

    if not src_iid or not os.path.exists(os.path.join(FIRMAE_DIR, "scratch", "run", src_iid)):
        return False

    mode = "run"
    source_csv = os.path.join(FIRMAE_DIR, f"firm_db_{mode}.csv")
    dst_csv = os.path.join(FIRMAE_DIR, f"firm_db_{dst_mode}.csv")
    os.makedirs(os.path.dirname(dst_csv), exist_ok=True)

    if not os.path.exists(dst_csv):
        with open(dst_csv, mode='w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['id', 'firmware', 'brand', 'arch', 'result'])

    row_to_copy = None
    with open(source_csv, mode='r', newline='', encoding='utf-8') as src_file:
        reader = csv.reader(src_file)
        next(reader)
        for row in reader:
            if row[0] == src_iid:
                row_to_copy = row
                break

    if not row_to_copy:
        return False

    existing_ids = set()
    existing_id = None
    with open(dst_csv, mode='r', newline='', encoding='utf-8') as dst_file:
        reader = csv.reader(dst_file)
        next(reader, None)
        for row in reader:
            if row[0].isdigit():
                existing_ids.add(int(row[0]))
            if row[1] == os.path.basename(firmware):
                existing_id = row[0]

    dst_iid = existing_id if existing_id else str(max(existing_ids) + 1 if existing_ids else 1)

    row_to_copy[0] = dst_iid
    with open(dst_csv, mode='a', newline='', encoding='utf-8') as dst_file:
        writer = csv.writer(dst_file)
        writer.writerow(row_to_copy)

    source_img = os.path.join(FIRMAE_DIR, "scratch", "run", src_iid)
    dest_img = os.path.join(FIRMAE_DIR, "scratch", dst_mode, dst_iid)

    fast_copytree(source_img, dest_img)

    run_file = os.path.join(dest_img, "run.sh")
    if not os.path.islink(run_file.replace(".sh", "_%s.sh" % dst_mode)):
        os.symlink(run_file, run_file.replace(".sh", "_%s.sh" % dst_mode))

    replace_pattern_in_file(run_file, f'IID={src_iid}', f'IID={dst_iid}')

    if "staff_base" in dst_mode:
        suffix = dst_mode.split("staff_base", 1)[1]
        dst_abbr_mode = f"sb{suffix}"
    elif "staff_state_aware" in dst_mode:
        suffix = dst_mode.split("staff_state_aware", 1)[1]
        dst_abbr_mode = f"ss{suffix}"
    elif "triforce" in dst_mode:
        suffix = dst_mode.split("triforce", 1)[1]
        dst_abbr_mode = f"t{suffix}"
    elif "aflnet_base" in dst_mode:
        suffix = dst_mode.split("aflnet_base", 1)[1]
        dst_abbr_mode = f"ab{suffix}"
    elif "aflnet_state_aware" in dst_mode:
        suffix = dst_mode.split("aflnet_state_aware", 1)[1]
        dst_abbr_mode = f"as{suffix}"
    elif "pre_analysis" in dst_mode:
        suffix = dst_mode.split("pre_analysis", 1)[1]
        dst_abbr_mode = f"pa{suffix}"
    elif "pre_exp" in dst_mode:
        suffix = dst_mode.split("pre_exp", 1)[1]
        dst_abbr_mode = f"pe{suffix}"
    elif "crash_analysis" in dst_mode:
        suffix = dst_mode.split("crash_analysis", 1)[1]
        dst_abbr_mode = f"ca{suffix}"
    else:
        assert(0)

    replace_pattern_in_file(run_file, '_run_', f'_{dst_abbr_mode}_')
    replace_pattern_in_file(run_file, f'_{src_iid}', f'_{dst_iid}')
    
    prev_dir = os.getcwd()
    os.chdir(STAFF_DIR)
    subprocess.run(["sudo", "-E", "python3", os.path.join(STAFF_DIR, "update_executables.py"), dst_mode])
    os.chdir(prev_dir)

    return True

def check_firmware(firmware, mode, log_to_csv=False, csv_path=None):
    result = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'firmware': os.path.basename(firmware),
        'firmware_path': firmware,
        'mode': mode,
        'status': 'success',
        'iid': '',
        'error': ''
    }

    iid = ""

    try:
        subprocess.run(["sudo", "-E", "./flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
            if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
                error_msg = "Docker container failed to connect to PostgreSQL"
                print(f"[\033[31m-\033[0m] {error_msg}")
                result['status'] = 'failed'
                result['error'] = error_msg

                if log_to_csv and csv_path:
                    _write_check_result_to_csv(csv_path, result)
                if log_to_csv:
                    return result
                else:
                    exit(1)

        try:
            iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, mode]).decode('utf-8').strip()
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to get image ID: {e}"
            result['status'] = 'failed'
            result['error'] = error_msg
            if log_to_csv and csv_path:
                _write_check_result_to_csv(csv_path, result)
            if log_to_csv:
                return result
            else:
                raise

        if iid == "" or not os.path.exists(os.path.join(FIRMAE_DIR, "scratch", mode, iid)):
            try:
                copy_image(mode, firmware)
            except Exception as e:
                error_msg = f"Failed to copy image: {e}"
                result['status'] = 'failed'
                result['error'] = error_msg
                if log_to_csv and csv_path:
                    _write_check_result_to_csv(csv_path, result)
                if log_to_csv:
                    return result
                else:
                    raise

        print("\033[32m[+]\033[0m\033[32m[+]\033[0m FirmAE: Creating Firmware Scratch Image")
        try:
            ret = subprocess.run(["sudo", "-E", "./run.sh", "-c", os.path.basename(os.path.dirname(firmware)),
                                 os.path.join(FIRMWARE_DIR, firmware), mode, PSQL_IP],
                                capture_output=True, text=True)

            if ret.returncode != 0:
                error_msg = f"Image creation failed with return code {ret.returncode}"
                if ret.stderr:
                    error_msg += f": {ret.stderr[:200]}"
                result['status'] = 'failed'
                result['error'] = error_msg
                if log_to_csv and csv_path:
                    _write_check_result_to_csv(csv_path, result)
                if log_to_csv:
                    return result

        except subprocess.CalledProcessError as e:
            error_msg = f"Image creation subprocess failed: {e}"
            result['status'] = 'failed'
            result['error'] = error_msg
            if log_to_csv and csv_path:
                _write_check_result_to_csv(csv_path, result)
            if log_to_csv:
                return result
            else:
                raise

        try:
            iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", firmware, PSQL_IP, mode]).decode('utf-8').strip()
            result['iid'] = iid
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to get final image ID: {e}"
            result['status'] = 'failed'
            result['error'] = error_msg
            if log_to_csv and csv_path:
                _write_check_result_to_csv(csv_path, result)
            if log_to_csv:
                return result
            else:
                raise

        if log_to_csv and csv_path:
            _write_check_result_to_csv(csv_path, result)

    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        result['status'] = 'failed'
        result['error'] = error_msg
        if log_to_csv and csv_path:
            _write_check_result_to_csv(csv_path, result)
        if log_to_csv:
            return result
        else:
            raise

    if log_to_csv:
        return result
    else:
        return iid

def _write_check_result_to_csv(csv_path, result):
    fieldnames = ['timestamp', 'firmware', 'firmware_path', 'mode', 'status', 'iid', 'error']

    with open(csv_path, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow(result)
        csvfile.flush()

def search_recursive(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if any(filename.endswith(extension) for extension in ('.zip', '.tar.gz', '.ZIP')):
                yield os.path.abspath(os.path.join(root, filename))

def check(mode, enable_csv_logging=False):
    global config

    csv_path = None
    if enable_csv_logging:
        csv_path = os.path.join(STAFF_DIR, "check_mode_results.csv")
        fieldnames = ['timestamp', 'firmware', 'firmware_path', 'mode', 'status', 'iid', 'error']

        if not os.path.exists(csv_path):
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
            print(f"[\033[32m✓\033[0m] CSV logging initialized (new file): {csv_path}\n")
        else:
            print(f"[\033[32m✓\033[0m] CSV logging enabled (append mode): {csv_path}\n")

    if config["GENERAL"]["firmware"] != "all":
        return check_firmware(config["GENERAL"]["firmware"], mode, log_to_csv=enable_csv_logging, csv_path=csv_path)
    else:
        main_files = []
        subdir_files = []
        subdirs = []
        for root, dirs, files in os.walk(FIRMWARE_DIR):
            if root == FIRMWARE_DIR:
                main_files.extend([os.path.join(root, f) for f in files])
                subdirs = [os.path.join(root, d) for d in dirs]
            else:
                subdir_files.extend([os.path.join(root, f) for f in files])

        subdir_groups = {}

        for subdir in subdirs:
            subdir_groups[subdir] = [
                os.path.join(root, f)
                for root, _, files in os.walk(subdir)
                for f in files
            ]

        if not subdir_groups:
            return

        max_files = max(len(files) for files in subdir_groups.values())

        total_checked = 0
        total_success = 0
        total_failed = 0

        for i in range(max_files):
            for subdir in subdirs:
                if i < len(subdir_groups[subdir]):
                    file = subdir_groups[subdir][i]
                    print("Checking %s" % file)
                    total_checked += 1

                    result = check_firmware(file, mode, log_to_csv=enable_csv_logging, csv_path=csv_path)

                    if enable_csv_logging and isinstance(result, dict):
                        if result['status'] == 'success':
                            total_success += 1
                            print(f"  [\033[32m✓\033[0m] Success - IID: {result['iid']}")
                        else:
                            total_failed += 1
                            print(f"  [\033[31m✗\033[0m] Failed: {result['error']}")
                    else:
                        total_success += 1

        if enable_csv_logging:
            print(f"\n{'='*60}")
            print(f"[\033[32m+\033[0m] CHECK MODE SUMMARY")
            print(f"{'='*60}")
            print(f"Total firmwares checked: {total_checked}")
            print(f"Successful: {total_success}")
            print(f"Failed: {total_failed}")
            print(f"Results appended to: {csv_path}")
            print(f"{'='*60}\n")

        return 0

def load_config(file_path="config.ini"):
    global config

    config = configparser.ConfigParser()
    config.read(file_path)

    final_config = {}

    for section, options in DEFAULT_CONFIG.items():
        final_config[section] = {}

        if not config.has_section(section):
            config.add_section(section)

        for key, default_info in options.items():
            if isinstance(default_info, tuple) and len(default_info) == 2:
                default_value, data_type = default_info
            else:
                print(f"Warning: Invalid default entry for {section}.{key}, skipping.")
                continue

            if config.has_option(section, key):
                value = config.get(section, key)
                try:
                    if data_type == int:
                        value = int(value)
                    elif data_type == float:
                        value = float(value)
                    elif data_type == str:
                        value = str(value)
                    elif data_type == bytes:
                        value = bytes.fromhex(value.replace('\\x', ''))
                    else:
                        assert(0)
                except ValueError:
                    print(f"Warning: Invalid type for {section}.{key}, using default value.")
                    value = default_value
            else:
                value = default_value

            final_config[section][key] = value

    return final_config

def send_seed_to_firmware(firmware_name, seed_path, port=80, timeout=150, work_dir=None,
                          check_crashes=False, process_name=None):
    global config

    if work_dir is None:
        iid = str(check("run"))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep_time = file.read().strip()
    sleep_time = int(float(sleep_time))

    if check_crashes:
        os.environ["MONITOR_CRASHES"] = "1"

    process = subprocess.Popen(
        ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(firmware_name)),
         os.path.join(FIRMWARE_DIR, firmware_name), "run", PSQL_IP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    qemu_pid = process.pid

    print(f"Booting firmware, wait {sleep_time} seconds...")
    time.sleep(sleep_time)

    with open(os.path.join(work_dir, "ip"), 'r') as f:
        target_ip = f.read().strip()

    command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"),
               seed_path, target_ip, str(port), str(timeout), "50"]

    if check_crashes:
        command.append(f"--work-dir={work_dir}")
        if process_name:
            command.append(f"--process={process_name}")

    print(" ".join(command))
    result = subprocess.run(command)

    crash_detected = False
    if check_crashes and result.returncode == 10:
        crash_detected = True
        print(f"[\033[31m!\033[0m] CRASH DETECTED (reported by client)")

    return {
        "qemu_pid": qemu_pid,
        "crash_detected": crash_detected
    }

def replay_firmware(firmware, work_dir, crash_analysis=False, crash_seed=None, target_procname=None):
    global config

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    if crash_analysis:
        os.environ["CRASH_ANALYSIS"] = "1"
        os.environ["TRACE_LEN"] = "300"
        os.environ["TARGET_PROCNAME"] = target_procname
        os.environ["DEBUG"] = "1"
        os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")
        os.environ["MONITOR_CRASHES"] = "1"
    else:
        os.environ["TAINT"] = "1"
        os.environ["FD_DEPENDENCIES_TRACK"] = "1"
        os.environ["DEBUG"] = "1"
        os.environ["DEBUG_DIR"] = os.path.join(work_dir, "debug", "interaction")

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()
    sleep=int(float(sleep))

    if (crash_analysis):
        print(f"\n[\033[32m+\033[0m] Crash mode (seed: {crash_seed})")

        result = send_seed_to_firmware(firmware, crash_seed, port=80,
                                       timeout=config["GENERAL_FUZZING"]["timeout"],
                                       work_dir=work_dir,
                                       check_crashes=True,
                                       process_name=target_procname)

        send_signal_recursive(result["qemu_pid"], signal.SIGINT)

        return result["crash_detected"]
    else:
        pcap_dir = os.path.join(PCAP_DIR, firmware)
                    
        print("\n[\033[32m+\033[0m] Replay mode")

        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        start_fork_executed = False
        for proto in sub_dirs:
            print("\n[\033[33m*\033[0m] Protocol: {}".format(proto))
            for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
                pcap_path = os.path.join(pcap_dir, proto, pcap_file)
                print("\n[\033[34m*\033[0m] PCAP #{}".format(pcap_file))

                seed_path = os.path.join(work_dir, "inputs", "%s.seed"%(pcap_file))
                sources_hex = convert_pcap_into_single_seed_file(pcap_path, seed_path, config["AFLNET_FUZZING"]["region_delimiter"])

                process = subprocess.Popen(
                    ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(firmware)), os.path.join(FIRMWARE_DIR, firmware), "run", PSQL_IP],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                qemu_pid = process.pid
                print("Booting firmware, wait %d seconds..."%(sleep))
                time.sleep(sleep)

                port = None
                try:
                    port = socket.getservbyname(proto)
                    print(f"The port for {proto.upper()} is {port}.")
                except OSError:
                    print(f"Protocol {proto.upper()} not found.")
                command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"), seed_path, open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(config["GENERAL_FUZZING"]["timeout"]), "10"]    
                print(" ".join(command))
                subprocess.run(command)

                send_signal_recursive(qemu_pid, signal.SIGINT)
                try:
                    os.waitpid(qemu_pid, 0)
                except:
                    pass
                time.sleep(2)


####################################################################

def replay():
    global config

    if config["GENERAL"]["firmware"] != "all":
        iid = str(check("run"))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

        if "true" in open(os.path.join(work_dir, "web_check")).read():
            replay_firmware(config["GENERAL"]["firmware"], work_dir)
    else:
        firmware_brands = {}
        
        for brand in os.listdir(PCAP_DIR):
            brand_path = os.path.join(PCAP_DIR, brand)
            if os.path.isdir(brand_path):
                firmware_brands[brand] = {}
                for device in os.listdir(brand_path):
                    device_path = os.path.join(brand_path, device)
                    if os.path.isdir(device_path):
                        firmware_brands[brand][device] = [
                            os.path.join(root, f)
                            for root, _, files in os.walk(device_path)
                            for f in files
                        ]

        if not firmware_brands:
            return

        for brand, devices in firmware_brands.items():
            for device, files in devices.items():
                print(f"Replaying {os.path.basename(brand)}/{os.path.basename(device)}")
                iid = str(check_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), "run"))
                work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

                if "true" in open(os.path.join(work_dir, "web_check")).read():
                    replay_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), work_dir)

def replay_with_mem_counting(output_csv="mem_ops_replay_results.csv", firmware_filter=None):
    global config

    if not os.path.isabs(output_csv):
        output_csv = os.path.join(STAFF_DIR, output_csv)

    results = []
    total_firmwares = 0
    total_pcaps = 0

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])
    os.environ["MEM_OPS"] = "1"
    os.environ["TAINT"] = "1"

    print(f"\n[\033[32m+\033[0m] Replay mode with memory operations counting")
    print(f"Output CSV: {output_csv}")
    print("="*60)

    csv_fieldnames = ['firmware', 'protocol', 'pcap', 'total_requests',
                     'total_mem_ops', 'total_taint_mem_ops',
                     'total_reduction_pct', 'avg_reduction_pct', 'median_reduction_pct',
                     'min_reduction_pct', 'max_reduction_pct', 'stddev_reduction_pct', 'error']

    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
        writer.writeheader()

    print(f"[\033[32m✓\033[0m] CSV file initialized: {output_csv}\n")

    if firmware_filter and firmware_filter != "all":
        firmware_list = [firmware_filter]
    else:
        firmware_list = []
        for brand in os.listdir(PCAP_DIR):
            brand_path = os.path.join(PCAP_DIR, brand)
            if os.path.isdir(brand_path):
                for device in os.listdir(brand_path):
                    device_path = os.path.join(brand_path, device)
                    if os.path.isdir(device_path):
                        firmware_list.append(os.path.join(brand, device))

    for firmware in sorted(firmware_list):
        print(f"\n{'='*60}")
        print(f"[\033[33m*\033[0m] Processing firmware: {firmware}")
        print(f"{'='*60}")

        try:
            iid = str(check_firmware(firmware, "run"))
        except Exception as e:
            print(f"[\033[31mERROR\033[0m] Failed to check firmware {firmware}: {e}")
            continue

        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

        web_check_file = os.path.join(work_dir, "web_check")

        if not os.path.exists(web_check_file):
            print(f"[\033[31m!\033[0m] Skipping {firmware}: web_check file not found")
            continue

        with open(web_check_file, 'r') as f:
            if "true" not in f.read():
                print(f"[\033[31m!\033[0m] Skipping {firmware}: web service not enabled")
                continue

        total_firmwares += 1
        pcap_dir = os.path.join(PCAP_DIR, firmware)

        if not os.path.isdir(pcap_dir):
            print(f"[\033[31m!\033[0m] PCAP directory not found: {pcap_dir}")
            continue

        with open(os.path.join(work_dir, "time_web"), 'r') as f:
            sleep_time = int(float(f.read().strip()))

        for proto in sorted(os.listdir(pcap_dir)):
            proto_path = os.path.join(pcap_dir, proto)
            if not os.path.isdir(proto_path):
                continue

            print(f"\n[\033[34m→\033[0m] Protocol: {proto}")

            for pcap_file in sorted(os.listdir(proto_path)):
                pcap_path = os.path.join(proto_path, pcap_file)
                if not os.path.isfile(pcap_path):
                    continue

                print(f"  [\033[36m•\033[0m] PCAP: {pcap_file}")
                total_pcaps += 1

                seed_path = os.path.join(work_dir, "inputs", f"{pcap_file}.seed")
                try:
                    convert_pcap_into_single_seed_file(pcap_path, seed_path,
                                                       config["AFLNET_FUZZING"]["region_delimiter"])
                except Exception as e:
                    print(f"    [\033[31m✗\033[0m] Failed to convert PCAP: {e}")
                    error_row = {
                        'firmware': firmware,
                        'protocol': proto,
                        'pcap': pcap_file,
                        'total_requests': 'ERROR',
                        'total_mem_ops': 'ERROR',
                        'total_taint_mem_ops': 'ERROR',
                        'total_reduction_pct': 'ERROR',
                        'avg_reduction_pct': 'ERROR',
                        'median_reduction_pct': 'ERROR',
                        'min_reduction_pct': 'ERROR',
                        'max_reduction_pct': 'ERROR',
                        'stddev_reduction_pct': 'ERROR',
                        'error': str(e)
                    }
                    results.append(error_row)

                    with open(output_csv, 'a', newline='') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
                        writer.writerow(error_row)
                        csvfile.flush()

                    print(f"    [\033[36m→\033[0m] Error written to CSV")
                    continue

                mem_ops_log = os.path.join(work_dir, "mem_ops_count.log")
                if os.path.exists(mem_ops_log):
                    os.remove(mem_ops_log)

                process = subprocess.Popen(
                    ["sudo", "-E", "./run.sh", "-r",
                     os.path.basename(os.path.dirname(firmware)),
                     os.path.join(FIRMWARE_DIR, firmware), "run", PSQL_IP],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                qemu_pid = process.pid

                print(f"    Booting firmware, waiting {sleep_time} seconds...")
                time.sleep(sleep_time)

                port = None
                try:
                    port = socket.getservbyname(proto)
                    print(f"The port for {proto.upper()} is {port}.")
                except OSError:
                    print(f"Protocol {proto.upper()} not found.")
                command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"), seed_path, open(os.path.join(work_dir, "ip")).read().strip(), str(port), str(config["GENERAL_FUZZING"]["timeout"])]    
                print(" ".join(command))
                subprocess.run(command)

                send_signal_recursive(qemu_pid, signal.SIGINT)
                try:
                    os.waitpid(qemu_pid, 0)
                except:
                    pass
                time.sleep(2)

                total_mem_ops = 0
                total_taint_mem_ops = 0
                total_requests = 0
                reduction_percentages = []
                error_msg = None

                print(f"{mem_ops_log}")
                if os.path.exists(mem_ops_log):
                    try:
                        with open(mem_ops_log, 'r') as f:
                            lines = f.readlines()
                            if lines:
                                for line in lines:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    parts = line.split(',')
                                    if len(parts) >= 2:
                                        try:
                                            mem_ops = int(parts[0])
                                            taint_mem_ops = int(parts[1])
                                            total_mem_ops += mem_ops
                                            total_taint_mem_ops += taint_mem_ops
                                            total_requests += 1

                                            if mem_ops > 0:
                                                reduction_pct = ((mem_ops - taint_mem_ops) / mem_ops) * 100
                                                reduction_percentages.append(reduction_pct)
                                        except (ValueError, ZeroDivisionError):
                                            continue

                                if total_requests > 0 and total_mem_ops > 0:
                                    total_reduction_pct = ((total_mem_ops - total_taint_mem_ops) / total_mem_ops) * 100
                                    avg_reduction_pct = sum(reduction_percentages) / len(reduction_percentages) if reduction_percentages else 0

                                    sorted_reductions = sorted(reduction_percentages)
                                    n = len(sorted_reductions)
                                    if n > 0:
                                        if n % 2 == 0:
                                            median_reduction_pct = (sorted_reductions[n//2-1] + sorted_reductions[n//2]) / 2
                                        else:
                                            median_reduction_pct = sorted_reductions[n//2]
                                    else:
                                        median_reduction_pct = 0

                                    min_reduction_pct = min(reduction_percentages) if reduction_percentages else 0
                                    max_reduction_pct = max(reduction_percentages) if reduction_percentages else 0

                                    if len(reduction_percentages) > 1:
                                        mean = avg_reduction_pct
                                        variance = sum((x - mean) ** 2 for x in reduction_percentages) / len(reduction_percentages)
                                        stddev_reduction_pct = variance ** 0.5
                                    else:
                                        stddev_reduction_pct = 0

                                    print(f"    [\033[32m✓\033[0m] Requests: {total_requests}, Total mem_ops: {total_mem_ops}, taint: {total_taint_mem_ops}")
                                    print(f"    [\033[32m→\033[0m] Total reduction: {total_reduction_pct:.2f}%, Avg: {avg_reduction_pct:.2f}%, Median: {median_reduction_pct:.2f}%")
                                else:
                                    error_msg = "No valid data in log"
                                    print(f"    [\033[31m✗\033[0m] No valid data")
                            else:
                                error_msg = "Empty log file"
                                print(f"    [\033[31m✗\033[0m] Empty log file")
                    except Exception as e:
                        error_msg = f"Failed to read log: {e}"
                        print(f"    [\033[31m✗\033[0m] {error_msg}")
                else:
                    error_msg = "mem_ops_count.log not created"
                    print(f"    [\033[31m✗\033[0m] Log file not created")

                result_row = {
                    'firmware': firmware,
                    'protocol': proto,
                    'pcap': pcap_file,
                    'total_requests': total_requests if not error_msg else 'ERROR',
                    'total_mem_ops': total_mem_ops if not error_msg else 'ERROR',
                    'total_taint_mem_ops': total_taint_mem_ops if not error_msg else 'ERROR',
                    'total_reduction_pct': f"{total_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'avg_reduction_pct': f"{avg_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'median_reduction_pct': f"{median_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'min_reduction_pct': f"{min_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'max_reduction_pct': f"{max_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'stddev_reduction_pct': f"{stddev_reduction_pct:.2f}" if not error_msg and total_requests > 0 else 'ERROR',
                    'error': error_msg or ''
                }

                results.append(result_row)

                with open(output_csv, 'a', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
                    writer.writerow(result_row)
                    csvfile.flush()

                print(f"    [\033[36m→\033[0m] Result written to CSV")

    print(f"\n\n{'='*60}")
    print(f"[\033[32m+\033[0m] REPLAY WITH MEMORY COUNTING COMPLETE")
    print(f"{'='*60}")

    print(f"\nTotal firmwares processed: {total_firmwares}")
    print(f"Total PCAPs processed: {total_pcaps}")

    valid_results = [r for r in results if r.get('error') == '']
    if valid_results:
        total_all_mem_ops = sum(int(r['total_mem_ops']) for r in valid_results if r['total_mem_ops'] != 'ERROR')
        total_all_taint_mem_ops = sum(int(r['total_taint_mem_ops']) for r in valid_results if r['total_taint_mem_ops'] != 'ERROR')

        if total_all_mem_ops > 0:
            overall_reduction_pct = ((total_all_mem_ops - total_all_taint_mem_ops) / total_all_mem_ops) * 100
            print(f"\n[\033[32m+\033[0m] Overall Taint Analysis Effectiveness:")
            print(f"  Total memory operations: {total_all_mem_ops:,}")
            print(f"  Tainted memory operations: {total_all_taint_mem_ops:,}")
            print(f"  Overall reduction: {overall_reduction_pct:.2f}%")

            pcap_reductions = [float(r['total_reduction_pct']) for r in valid_results if r['total_reduction_pct'] != 'ERROR']
            if pcap_reductions:
                avg_pcap_reduction = sum(pcap_reductions) / len(pcap_reductions)
                print(f"  Average per-PCAP reduction: {avg_pcap_reduction:.2f}%")

    print(f"\nResults written to: {output_csv}")
    print(f"{'='*60}\n")

def check_crash_in_log(work_dir, process_name=None, crash_patterns=None):
    if crash_patterns is None:
        crash_patterns = [
            "sending SIGSEGV to",
        ]

    log_file = os.path.join(work_dir, "qemu.final.serial.log")

    if not os.path.exists(log_file):
        return False, None

    for pattern in crash_patterns:
        if process_name:
            full_pattern = f"{pattern} {process_name}"
        else:
            full_pattern = pattern

        result = subprocess.run(
            ["grep", "-q", full_pattern, log_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return True, full_pattern

    return False, None

def send_and_monitor_seed(container_name, firmware_name, seed_path, port=80, timeout=150,
                                work_dir=None, check_crashes=True,
                                output_minimized=None, process_name=None):
    global config

    if "test" in config["GENERAL"]["mode"] or "unique_crash_report" in config["GENERAL"]["mode"]:
        mode = "run"
        os.environ["DEBUG"] = "1"
    else:
        mode = container_name if container_name else config["GENERAL"]["mode"]

    if work_dir is None:
        iid = str(check(mode))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", mode, iid)

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)

    web_check_file = os.path.join(work_dir, "web_check")

    if not os.path.exists(web_check_file):
        raise RuntimeError(f"Firmware analysis incomplete: web_check file not found. The firmware may have failed during FirmAE extraction/analysis.")

    with open(web_check_file, 'r') as f:
        web_check_content = f.read().strip()

    if "true" not in web_check_content:
        raise RuntimeError(f"Firmware {firmware_name} does not have web service enabled (web_check is FALSE). This firmware cannot be tested via network interface.")

    delimiter = config["AFLNET_FUZZING"]["region_delimiter"]
    with open(seed_path, 'rb') as f:
        seed_data = f.read()

    regions = [r for r in seed_data.split(delimiter) if r]

    print(f"[INFO] Parsed {len(regions)} request(s) from seed")

    if check_crashes:
        os.environ["MONITOR_CRASHES"] = "1"

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep_time = file.read().strip()
    sleep_time = int(float(sleep_time))

    process = subprocess.Popen(
        ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(firmware_name)),
         os.path.join(FIRMWARE_DIR, firmware_name), mode, PSQL_IP],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    qemu_pid = process.pid

    print(f"Booting firmware, wait {sleep_time} seconds...")
    time.sleep(sleep_time)

    with open(os.path.join(work_dir, "ip"), 'r') as f:
        target_ip = f.read().strip()

    crash_detected = False
    crash_pattern = None
    crash_at_request = -1

    print(f"\n[\033[34m*\033[0m] Sending all {len(regions)} requests in sequence...")

    command = ["sudo", "-E", os.path.join(STAFF_DIR, "aflnet", "client"),
               seed_path, target_ip, str(port), str(timeout), "50"]

    if check_crashes:
        command.append(f"--work-dir={work_dir}")
        if process_name:
            command.append(f"--process={process_name}")

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    crash_at_request = -1

    if check_crashes and result.returncode == 10:
        crash_detected = True
        crash_pattern = (
            f"sending SIGSEGV to {process_name}"
            if process_name else
            "sending SIGSEGV to"
        )

        for line in result.stdout.splitlines():
            if line.startswith(b"CRASH_REQUEST_ID="):
                crash_at_request = int(line.split(b"=", 1)[1])
                break

        print(f"\n[\033[31m!\033[0m] CRASH DETECTED")
        print(f"[\033[31m!\033[0m] Crashed at request {crash_at_request}")
    else:
        print(f"\n[\033[32m+\033[0m] No crash detected after {len(regions)} request(s)")


    if check_crashes:
        if result.returncode == 10:
            crash_detected = True
            crash_pattern = f"sending SIGSEGV to {process_name}" if process_name else "sending SIGSEGV to"
            print(f"\n[\033[31m!\033[0m] CRASH DETECTED (reported by client)")
            print(f"[\033[31m!\033[0m] Pattern: {crash_pattern}")
        else:
            print(f"\n[\033[32m+\033[0m] No crash detected after {len(regions)} request(s)")

    return {
        "qemu_pid": qemu_pid,
        "work_dir": work_dir,
        "crash_detected": crash_detected,
        "crash_pattern": crash_pattern,
        "crash_at_request": crash_at_request,
        "total_requests": len(regions)
    }

def minimize_crash_seed(container_name, firmware_name, seed_path, port=80, timeout=150, process_name=None):
    global config

    print(f"\n[\033[36m*\033[0m] Starting crash seed minimization...")

    delimiter = config["AFLNET_FUZZING"]["region_delimiter"]
    if isinstance(delimiter, str):
        delimiter = delimiter.encode()

    with open(seed_path, 'rb') as f:
        seed_data = f.read()

    original_requests = [r for r in seed_data.split(delimiter) if r]
    original_size = len(seed_data)
    original_count = len(original_requests)

    if original_count <= 1:
        print(f"[\033[33m!\033[0m] Seed has only {original_count} request(s), cannot minimize further")
        return {
            "original_count": original_count,
            "minimized_count": original_count,
            "original_size": original_size,
            "minimized_size": original_size,
            "iterations": 0,
            "removed_requests": []
        }

    print(f"[\033[90m→\033[0m] Original seed: {original_count} requests, {original_size} bytes")

    current_requests = list(original_requests)
    removed_indices = []
    iterations = 0

    i = len(current_requests) - 1
    while i >= 0:
        iterations += 1

        test_requests = current_requests[:i] + current_requests[i+1:]

        if len(test_requests) == 0:
            print(f"[\033[90m→\033[0m] Cannot remove request {i+1}/{len(current_requests)} (would leave empty seed)")
            i -= 1
            continue

        print(f"[\033[90m→\033[0m] Testing without request {i+1}/{len(current_requests)}...", end="\n")

        temp_seed_path = seed_path + ".minimize_test"
        with open(temp_seed_path, 'wb') as f:
            f.write(delimiter.join(test_requests))

        # try:
        result = send_and_monitor_seed(
            container_name,
            firmware_name,
            temp_seed_path,
            port=port,
            timeout=timeout,
            check_crashes=True,
            output_minimized=None,
            process_name=process_name
        )

        send_signal_recursive(result["qemu_pid"], signal.SIGINT)
        try:
            os.waitpid(result["qemu_pid"], 0)
        except:
            pass

        if result['crash_detected']:
            print(f"[\033[32m✓\033[0m] Still crashes, removing request {i+1}")
            current_requests = test_requests
            removed_indices.append(i)
            i -= 1
        else:
            print(f"[\033[31m✗\033[0m] No crash, keeping request {i+1}")
            i -= 1

        # except Exception as e:
        #     print(f"[\033[31m!\033[0m] Error during test: {e}")
        #     i -= 1
        # finally:
        #     if os.path.exists(temp_seed_path):
        #         os.remove(temp_seed_path)

    minimized_data = delimiter.join(current_requests)
    minimized_size = len(minimized_data)
    minimized_count = len(current_requests)

    with open(seed_path, 'wb') as f:
        f.write(minimized_data)

    reduction_pct = ((original_size - minimized_size) / original_size * 100) if original_size > 0 else 0

    print(f"\n[\033[32m+\033[0m] Minimization complete!")
    print(f"[\033[90m→\033[0m] Original: {original_count} requests, {original_size} bytes")
    print(f"[\033[90m→\033[0m] Minimized: {minimized_count} requests, {minimized_size} bytes")
    print(f"[\033[90m→\033[0m] Reduction: {reduction_pct:.1f}% ({original_count - minimized_count} requests removed)")
    print(f"[\033[90m→\033[0m] Test iterations: {iterations}")

    return {
        "original_count": original_count,
        "minimized_count": minimized_count,
        "original_size": original_size,
        "minimized_size": minimized_size,
        "iterations": iterations,
        "removed_requests": sorted(removed_indices, reverse=True)
    }

def _extract_kernel_message(log_path: str) -> str:
    message = ""
    try:
        with open(log_path, 'r', errors='ignore') as log_file:
            lines = log_file.readlines()
            
            crash_start_idx = -1
            for i, line in enumerate(lines):
                low = line.lower()
                if "sending sigsegv" in low or "kernel panic" in low or "unexpected fatal signal" in low:
                    crash_start_idx = i
                    break
            
            if crash_start_idx >= 0:
                crash_lines = []
                for i in range(crash_start_idx, len(lines)):
                    line = lines[i].strip()
                    if not line:
                        continue
                    crash_lines.append(line)
                    if "PrId" in line or len(crash_lines) > 30:
                        break
                
                if crash_lines:
                    message = "\n".join(crash_lines)
                    return message
            
            if lines:
                return lines[-1].strip()
    except Exception:
        pass
    return message


def _read_seed_as_poc(seed_path: str, delimiter: bytes) -> str:
    try:
        with open(seed_path, 'rb') as f:
            data = f.read()
        regions = [r for r in data.split(delimiter) if r]
        decoded = []
        for region in regions:
            try:
                decoded.append(region.decode('latin-1'))
            except Exception:
                decoded.append(str(region))
        return "####".join(decoded)
    except Exception:
        return ""

def update_crash_analysis_prompt() -> None:
    if not os.path.exists(CRASH_REPORTS_DIR):
        os.makedirs(CRASH_REPORTS_DIR, exist_ok=True)
        os.chmod(CRASH_REPORTS_DIR, 0o777)

    report_files = sorted([f for f in os.listdir(CRASH_REPORTS_DIR) if f.endswith('.report')])

    prompt_content = """# CRASH ANALYSIS TASK

## Objective
Analyze all crash reports in this directory and create a comprehensive comparison table.

## Instructions
1. Read and analyze ALL `.report` files in this directory
2. Compare the crashes to identify which ones are caused by the same underlying bug
3. Determine if each crash is a false positive (not a real exploitable vulnerability)
4. Search the MITRE CVE database for known vulnerabilities related to each firmware
5. Classify each crash according to CWE (Common Weakness Enumeration)

## Required Output Format

Create a comprehensive table with the following columns:

| Bug ID | Report File(s) | Firmware | Module | Functions | Crash Type | False Positive | Related CVE | CWE | Root Cause Summary |
|--------|---------------|----------|--------|-----------|------------|----------------|-------------|-----|-------------------|

### Column Descriptions:
- **Bug ID**: Sequential number (0, 1, 2, ...). Reports with the same Bug ID represent the same underlying vulnerability.
- **Report File(s)**: List all report files that share this Bug ID (comma-separated if multiple)
- **Firmware**: The firmware name(s) affected
- **Module**: The vulnerable binary/module name(s)
- **Functions**: The affected function(s) from the crash
- **Crash Type**: Type of crash (e.g., Buffer Overflow, Use-After-Free, NULL Pointer Dereference)
- **False Positive**: "Yes" or "No" - whether this crash is a false positive
- **Related CVE**: Known CVE identifiers from MITRE database (if any), or "None found"
- **CWE**: Applicable CWE identifier(s) (e.g., CWE-119, CWE-787)
- **Root Cause Summary**: Brief description of the vulnerability

## Analysis Guidelines

### Identifying Same Bug (Same Bug ID):
- Compare crash locations (functions, modules)
- Compare PoC patterns and input structure
- Compare disassembly patterns
- Consider if crashes occur in the same or similar code paths
- Look for similar memory corruption patterns

### Determining False Positives:
A crash is a **FALSE POSITIVE** if the binary crash is unrelated to the PoC seed sent.

Mark a crash as "Yes" (false positive) if:
- The crash appears to be caused by environmental factors (timing, race conditions, etc.) rather than the input
- The execution trace shows no correlation between the PoC content and the crash location
- The crash occurs in code paths that don't process the input data
- The disassembly shows the crash happens in unrelated functionality (e.g., background tasks, timers, unrelated services)
- The kernel message indicates a crash source independent of the HTTP/network input
- Multiple different inputs (including empty/minimal inputs) produce identical crashes
- The crash is in initialization or cleanup code that runs regardless of input

Mark as "No" (true positive - real input-triggered crash) if:
- The execution trace clearly shows input data being processed before the crash
- The crash location is in parsing, validation, or processing functions for the received data
- The disassembly shows operations on buffers containing the PoC data
- The crash is reproducible specifically with this PoC but not with normal inputs
- The affected functions are directly involved in handling the HTTP request/data from the PoC
- Memory corruption patterns match the structure/content of the PoC seed

### CVE Search Strategy:
For each firmware, search MITRE CVE database using:
- Firmware manufacturer/brand name
- Product name/model
- Keywords from the vulnerability type

### CWE Classification:
Common CWEs to consider:
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
- CWE-787: Out-of-bounds Write
- CWE-788: Access of Memory Location After End of Buffer
- CWE-125: Out-of-bounds Read
- CWE-416: Use After Free
- CWE-476: NULL Pointer Dereference
- CWE-20: Improper Input Validation
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow

## Report Files to Analyze

"""

    prompt_content += f"Total reports: {len(report_files)}\n\n"

    for report_file in report_files:
        prompt_content += f"- `{report_file}`\n"

    prompt_content += """

## Next Steps
1. Use web search to look up CVEs for each firmware in the MITRE CVE database
2. Read each report file carefully
3. Group crashes by root cause
4. Generate the comparison table as specified above

## Additional Analysis (Optional)
After creating the main table, consider providing:
- Statistics on most common vulnerability types
- Recommendations for firmware vendors
- Patterns observed across multiple firmwares
- Severity assessment for each Bug ID
"""

    try:
        with open(CRASH_ANALYSIS_PROMPT_FILE, 'w', encoding='utf-8') as f:
            f.write(prompt_content)
        os.chmod(CRASH_ANALYSIS_PROMPT_FILE, 0o666)
        print(f"[INFO] Updated crash analysis prompt: {CRASH_ANALYSIS_PROMPT_FILE}")
    except Exception as e:
        print(f"[WARN] Could not write crash analysis prompt: {e}")

def generate_unique_crash_reports(container_name: Optional[str] = None) -> None:
    global config

    if os.path.exists(CRASH_REPORTS_DIR):
        print(f"[\033[31mERROR\033[0m] Output directory already exists: {CRASH_REPORTS_DIR}")
        print(f"Please remove or rename it before running --unique-crash-report mode.")
        print(f"To remove: rm -rf {CRASH_REPORTS_DIR}")
        sys.exit(1)

    def read_arch_from_workdir(work_dir: str) -> Optional[str]:
        p = os.path.join(work_dir, "architecture")
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip().lower()
        except Exception:
            return None

    def pick_capstone_arch_mode(arch: Optional[str]) -> Tuple[int, int]:
        if not arch:
            return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN)
        
        arch = arch.replace(" ", "").strip().lower()
        
        if arch in ("mipsel", "mipsle", "little", "le"):
            return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN)
        
        if arch in ("mipseb", "mipsbe", "mips", "big", "be"):
            return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN)
        
        return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN)

    def run_extractor(fw_path: str, extract_dir: str) -> None:
        env = os.environ.copy()
        env["NO_PSQL"] = "1"
        subprocess.run(
            [
                "./sources/extractor/extractor.py",
                "-t", "run",
                "-b", "unknown",
                "-sql", "0.0.0.0",
                "-np",
                "-nk",
                fw_path,
                extract_dir
            ],
            env=env,
            check=True
        )

    def is_angr_loadable(binary_path: str) -> bool:
        try:
            angr.Project(binary_path, auto_load_libs=False)
            return True
        except Exception:
            return False

    def find_module_path(extract_dir: str, module_name: str) -> Optional[str]:
        for d, _, files in os.walk(extract_dir):
            if module_name in files:
                candidate = os.path.join(d, module_name)
                if is_angr_loadable(candidate):
                    return candidate
        return None

    def load_symbols_angr(binary_path: str) -> Tuple[Dict[str, Tuple[int, int, int]], angr.Project]:
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
            mobj = proj.loader.main_object

            base = getattr(mobj, "rebased_addr", None) \
                 or getattr(mobj, "mapped_base", None) \
                 or getattr(mobj, "linked_base", 0)

            funcs = {}
            for sym in mobj.symbols:
                if sym.is_function:
                    start_va = sym.rebased_addr
                    size = sym.size if sym.size and sym.size > 0 else 1
                    end_va = start_va + size

                    try:
                        file_offset = mobj.addr_to_offset(start_va)
                        funcs[sym.name] = (start_va, end_va, file_offset)
                    except Exception:
                        pass

            return funcs, proj
        except Exception as e:
            print(f"[WARN] Could not load symbols with angr: {e}")
            return {}, None

    def disassemble_with_capstone(binary_path: str, binary_name: str, function_names: List[str],
                                  work_dir: str) -> Tuple[str, List[str]]:
        try:
            arch = read_arch_from_workdir(work_dir)
            cs_arch, cs_mode = pick_capstone_arch_mode(arch)
            
            proj = None
            funcs_dict = {}
            try:
                funcs_dict, proj = load_symbols_angr(binary_path)
            except Exception as e:
                print(f"[WARN] angr symbol loading failed: {e}, using capstone only")
            
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            cs = capstone.Cs(cs_arch, cs_mode)
            cs.detail = True

            def normalize_function_name(fname: str) -> List[str]:
                variants = []
                base_name = fname

                if '@@' in base_name:
                    base_name = base_name.split('@@')[0]
                variants.append(base_name)

                if '@' in base_name and '@@' not in fname:
                    base_name = base_name.split('@')[0]
                    variants.append(base_name)

                if base_name.startswith('_'):
                    variants.append(base_name[1:])

                if not base_name.startswith('_'):
                    variants.append('_' + base_name)

                if '.' in base_name:
                    base_name_no_version = base_name.rsplit('.', 1)[0]
                    variants.append(base_name_no_version)

                return list(set(variants))

            disasm_output = []
            func_set = set()
            func_map = {}
            func_variants_map = {}

            for fname in function_names:
                variants = normalize_function_name(fname)
                for variant in variants:
                    func_set.add(variant)
                    func_map[variant] = fname
                    if fname not in func_variants_map:
                        func_variants_map[fname] = []
                    func_variants_map[fname].append(variant)

            found_funcs = set()
            found_original_names = set()

            for sym_name, (start_va, end_va, file_offset) in funcs_dict.items():
                sym_variants = normalize_function_name(sym_name)

                matched_func = None
                for variant in sym_variants:
                    if variant in func_set:
                        matched_func = func_map[variant]
                        break

                if matched_func and matched_func not in found_original_names:
                    found_original_names.add(matched_func)

                    disasm_output.append(f"\n{'='*60}\n")
                    disasm_output.append(f"({binary_name}, {matched_func}):\n")
                    disasm_output.append(f"[Matched symbol: {sym_name}]\n")
                    disasm_output.append(f"[VA: 0x{start_va:08x}, File offset: 0x{file_offset:08x}]\n")
                    disasm_output.append(f"{'='*60}\n")

                    func_size = end_va - start_va
                    func_data = binary_data[file_offset:file_offset + func_size]

                    if len(func_data) < func_size:
                        disasm_output.append(f"[WARN] Function size mismatch: expected {func_size}, got {len(func_data)} bytes\n")
                        func_size = len(func_data)

                    instr_count = 0
                    for instr in cs.disasm(func_data, start_va):
                        addr_rebased = instr.address - start_va
                        disasm_output.append(f"{addr_rebased:8x}:  {instr.mnemonic:12} {instr.op_str}\n")
                        instr_count += 1

                    if instr_count == 0:
                        disasm_output.append(f"[WARN] No instructions disassembled for this function\n")

                    found_funcs.add(sym_name)
            
            if not found_funcs:
                print(f"[WARN] No matching functions found in {binary_name}")
                print(f"[INFO] Requested functions: {function_names[:5]}")
                print(f"[INFO] Symbols available: {list(funcs_dict.keys())[:20]}")
            else:
                print(f"[INFO] Found {len(found_funcs)} matching functions in {binary_name}")
                print(f"[INFO] Matched: {', '.join(list(found_original_names)[:5])}")

            not_found = set(function_names) - found_original_names
            not_found_list = sorted(list(not_found))

            disasm_text = "".join(disasm_output) if disasm_output else "No functions found for disassembly.\n"
            return disasm_text, not_found_list

        except Exception as e:
            return f"Error during disassembly: {e}\n", []

    def _format_bytes_as_hex(data: bytes) -> str:
        result = []
        for byte in data:
            if 32 <= byte < 127 and chr(byte) not in '\\':
                result.append(chr(byte))
            else:
                result.append(f"\\x{byte:02x}")
        return "".join(result)

    def _read_seed_as_poc_hex(seed_path: str, delimiter: bytes) -> str:
        try:
            with open(seed_path, 'rb') as f:
                data = f.read()
            regions = [r for r in data.split(delimiter) if r]
            
            delimiter_str = _format_bytes_as_hex(delimiter)
            
            formatted_regions = []
            for region in regions:
                formatted_regions.append(_format_bytes_as_hex(region))
            
            return f"{delimiter_str}".join(formatted_regions)
        except Exception:
            return ""

    root_dir = os.path.join(STAFF_DIR, "unique_crashes")
    if not os.path.isdir(root_dir):
        print(f"[!] unique_crashes directory not found: {root_dir}")
        return

    delimiter = config["AFLNET_FUZZING"]["region_delimiter"]

    for brand_name in sorted(os.listdir(root_dir)):
        brand_path = os.path.join(root_dir, brand_name)
        for firmware_name in sorted(os.listdir(brand_path)):
            firmware_path = os.path.join(brand_path, firmware_name)
            if not os.path.isdir(firmware_path):
                continue
            for module_name in sorted(os.listdir(firmware_path)):
                module_path = os.path.join(firmware_path, module_name)
                if not os.path.isdir(module_path):
                    continue
                for fname in sorted(os.listdir(module_path)):
                    if not fname.endswith(".succ"):
                        continue
                    seed_base = fname[:-5]
                    seed_path = os.path.join(module_path, fname)
                    trace_path = os.path.join(module_path, seed_base)
                    report_path = os.path.join(module_path, f"{seed_base}.report")
                    log_path = os.path.join(module_path, f"{seed_base}.log")
                    code_path = os.path.join(module_path, f"{seed_base}.code")

                    print("Processing seed:", seed_path)
                    # input("Press Enter to continue...")

                    if os.path.isfile(report_path) and os.path.isfile(log_path):
                        print(f"[SKIP] Already processed {firmware_name}/{module_name}/{seed_base}")
                        continue

                    if not os.path.isfile(trace_path):
                        print(f"[WARN] Trace file missing for seed {seed_base}, skipping")
                        continue
                    print(f"[+] Processing {firmware_name}/{module_name}/{seed_base}")

                    PROCESS_RE = re.compile(r".*Process:\s*(\S+)")
                    MODULE_RE = re.compile(r".*module:\s*(\S+)")
                    SYMBOL_RE = re.compile(r", symbol:\s*(\S+)")

                    target_process = None
                    trace_module_name = None
                    unique_functions = []
                    module_functions_map = {}
                    current_module = None

                    try:
                        with open(trace_path, 'r', errors='ignore') as tf:
                            for line in tf:
                                m = PROCESS_RE.match(line)
                                if m:
                                    target_process = m.group(1)

                                m_mod = MODULE_RE.match(line)
                                if m_mod:
                                    current_module = m_mod.group(1).rstrip('.,;:')
                                    if current_module not in module_functions_map:
                                        module_functions_map[current_module] = []
                                    if not trace_module_name:
                                        trace_module_name = current_module

                                m_sym = SYMBOL_RE.search(line)
                                if m_sym:
                                    func_name = m_sym.group(1)
                                    if func_name not in unique_functions:
                                        unique_functions.append(func_name)

                                    if current_module and func_name not in module_functions_map[current_module]:
                                        module_functions_map[current_module].append(func_name)
                    except Exception as e:
                        print(f"[WARN] Could not read trace file {trace_path}: {e}")
                        target_process = None
                        trace_module_name = None

                    process_list_for_monitoring = []
                    if target_process:
                        process_list_for_monitoring.append(target_process)
                    if trace_module_name and trace_module_name != target_process:
                        process_list_for_monitoring.append(trace_module_name)

                    process_names_csv = ",".join(process_list_for_monitoring) if process_list_for_monitoring else None
                    if not process_names_csv:
                        print(f"[WARN] Could not extract process names from trace, using module_name: {module_name}")
                        process_names_csv = module_name

                    print(f"[INFO] Found {len(module_functions_map)} modules in trace file")
                    for mod, funcs in module_functions_map.items():
                        print(f"  - {mod}: {len(funcs)} functions")

                    saved_firmware = config["GENERAL"]["firmware"]

                    config["GENERAL"]["firmware"] = brand_name+"/"+firmware_name
                    if "TEST" not in config:
                        config["TEST"] = {}
                    config["TEST"]["seed_input"] = seed_path
                    config["TEST"]["port"] = 80
                    config["TEST"]["timeout"] = config["GENERAL_FUZZING"]["timeout"]
                    config["TEST"]["process_name"] = module_name

                    firmware = config["GENERAL"]["firmware"]
                    seed_input = config["TEST"]["seed_input"]
                    port = config["TEST"]["port"]
                    timeout = config["TEST"]["timeout"]
                    process_name = config["TEST"]["process_name"] if config["TEST"]["process_name"] else None

                    if not seed_input or not os.path.exists(seed_input):
                        print(f"[ERROR] Seed input path not found: {seed_input}")
                        return

                    os.environ["EXEC_MODE"] = "RUN"
                    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
                    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

                    if os.path.isdir(seed_input):
                        print(f"[ERROR] seed_input is a directory but firmware is not 'all'")
                        return

                    firmware_with_brand = find_firmware_with_brand(firmware)
                    if not firmware_with_brand:
                        print(f"\n[\033[31mERROR\033[0m] Could not find firmware {firmware} in any brand subdirectory")
                        print(f"Please specify firmware as 'brand/firmware.zip' or ensure it exists in firmwares directory")
                        return

                    print(f"\n[\033[32m+\033[0m] Test mode with crash detection")
                    print(f"Firmware: {firmware}")
                    if firmware != firmware_with_brand:
                        print(f"Full path: {firmware_with_brand}")
                    print(f"Seed: {seed_input}")
                    print(f"Port: {port}")
                    print(f"Timeout: {timeout}sec")
                    if process_name:
                        print(f"Process name: {process_name}")

                    original_firmware = config["GENERAL"]["firmware"]
                    config["GENERAL"]["firmware"] = firmware_with_brand

                    result = None
                    try:
                        result = send_and_monitor_seed(
                            container_name,
                            firmware_with_brand,
                            seed_input,
                            port=port,
                            timeout=timeout,
                            check_crashes=True,
                            output_minimized=seed_input,
                            process_name=process_names_csv
                        )
                    except Exception as e:
                        config["GENERAL"]["firmware"] = original_firmware
                        print(f"\n[\033[31mERROR\033[0m] Failed to test seed: {e}")
                        return
                    finally:
                        config["GENERAL"]["firmware"] = original_firmware
                    try:
                        send_signal_recursive(result["qemu_pid"], 2)
                        try:
                            os.waitpid(result["qemu_pid"], 0)
                        except Exception:
                            pass
                    except Exception:
                        pass

                    if not result.get("crash_detected"):
                        print(f"[SKIP] No crash reproduced for {seed_base}")
                        continue

                    work_dir = result.get("work_dir")
                    if not work_dir or not os.path.isdir(work_dir):
                        print(f"[WARN] work_dir not found for {seed_base}, skipping log copy")
                        continue

                    qemu_log = os.path.join(work_dir, "qemu.final.serial.log")
                    if os.path.isfile(qemu_log):
                        dest_log = os.path.join(module_path, f"{seed_base}.log")
                        shutil.copy2(qemu_log, dest_log)
                        print(f"[INFO] Copied QEMU log to {dest_log}")
                    else:
                        print(f"[WARN] qemu.final.serial.log missing in {work_dir}")

                    poc = _read_seed_as_poc_hex(seed_path, delimiter)
                    kernel_message = _extract_kernel_message(qemu_log)
                    try:
                        with open(trace_path, 'r', errors='ignore') as f:
                            trace_content = f.read()
                    except Exception:
                        trace_content = ""

                    disasm_content = ""
                    all_unmatched_functions = []
                    if module_functions_map:
                        try:
                            fw_file = os.path.join(FIRMWARE_DIR, brand_name, firmware_name)
                            if os.path.isfile(fw_file):
                                extract_dir = tempfile.mkdtemp(prefix="disasm_")
                                try:
                                    run_extractor(fw_file, extract_dir)
                                    set_permissions_recursive(extract_dir)

                                    tars = glob.glob(os.path.join(extract_dir, "*.tar.gz"))
                                    if tars:
                                        latest = max(tars, key=os.path.getmtime)
                                        with tarfile.open(latest, "r:gz") as tar:
                                            tar.extractall(path=extract_dir)

                                    for module_name_item, module_functions in module_functions_map.items():
                                        module_name_item = module_name_item.strip()

                                        if not module_functions:
                                            print(f"[SKIP] No functions for module {module_name_item}")
                                            continue

                                        module_path_extracted = find_module_path(extract_dir, module_name_item)
                                        if not module_path_extracted:
                                            print(f"[WARN] Could not find module {module_name_item} for disassembly")
                                            for func in module_functions:
                                                if func not in all_unmatched_functions:
                                                    all_unmatched_functions.append(func)
                                            continue

                                        if os.path.islink(module_path_extracted):
                                            print(f"[SKIP] {module_name_item} is a symlink, skipping")
                                            continue

                                        print(f"[INFO] Disassembling {module_name_item} with {len(module_functions)} functions")
                                        binary_disasm, unmatched = disassemble_with_capstone(
                                            module_path_extracted,
                                            module_name_item,
                                            module_functions,
                                            work_dir
                                        )
                                        disasm_content += binary_disasm + "\n"
                                        all_unmatched_functions.extend(unmatched)
                                finally:
                                    shutil.rmtree(extract_dir, ignore_errors=True)
                        except Exception as e:
                            print(f"[WARN] Could not generate disassembly: {e}")

                    try:
                        delimiter_str = _format_bytes_as_hex(delimiter)
                        with open(report_path, 'w', encoding='utf-8') as rep:
                            rep.write("=" * 80 + "\n")
                            rep.write("FIRMWARE CRASH ANALYSIS REPORT\n")
                            rep.write("=" * 80 + "\n\n")
                            
                            rep.write("## EXECUTIVE SUMMARY\n")
                            rep.write("-" * 80 + "\n")
                            rep.write(f"Firmware: {firmware_name}\n")
                            rep.write(f"Vulnerable Binary: {module_name}\n")
                            rep.write(f"Target Process: {target_process if target_process else 'Unknown'}\n")
                            rep.write(f"Trace Module: {trace_module_name if trace_module_name else 'Unknown'}\n")
                            rep.write(f"Crash Type: Segmentation Fault (SIGSEGV)\n")
                            rep.write(f"Affected Functions: {', '.join(unique_functions) if unique_functions else 'Unknown'}\n\n")
                            
                            rep.write("## PROOF OF CONCEPT (PoC)\n")
                            rep.write("-" * 80 + "\n")
                            rep.write("The following HTTP requests trigger the crash when sent in sequence.\n")
                            rep.write(f"Note: Multiple requests are separated by the delimiter: {delimiter_str}\n\n")
                            rep.write(poc + "\n\n")
                            
                            rep.write("## AFFECTED CODE - DISASSEMBLY\n")
                            rep.write("-" * 80 + "\n")
                            if disasm_content:
                                rep.write(disasm_content + "\n\n")
                            else:
                                rep.write("No disassembly available for the affected functions.\n\n")

                            if all_unmatched_functions:
                                rep.write("## FUNCTIONS NOT FOUND IN BINARY\n")
                                rep.write("-" * 80 + "\n")
                                rep.write("The following functions from the trace could not be matched in the binary.\n")
                                rep.write("This may indicate dynamic loading, stripped symbols, or inlined functions.\n\n")
                                for func_name in all_unmatched_functions:
                                    rep.write(f"  - {func_name}\n")
                                rep.write("\n")

                            rep.write("## EXECUTION TRACE AT CRASH\n")
                            rep.write("-" * 80 + "\n")
                            rep.write("Call stack and instruction sequence leading to the crash:\n\n")
                            rep.write(trace_content + "\n\n")
                            
                            rep.write("## KERNEL/SYSTEM MESSAGE\n")
                            rep.write("-" * 80 + "\n")
                            rep.write("Crash details captured from system logs:\n\n")
                            rep.write(kernel_message if kernel_message else "No crash message available\n")
                            rep.write("\n\n")
                            
                            rep.write("## ANALYSIS REQUEST FOR SECURITY RESEARCHER\n")
                            rep.write("-" * 80 + "\n")
                            rep.write("Please analyze the above crash information and provide:\n\n")
                            rep.write("1. ROOT CAUSE ANALYSIS:\n")
                            rep.write("   - What is the vulnerability (buffer overflow, use-after-free, etc.)?\n")
                            rep.write("   - Where in the code does it occur?\n")
                            rep.write("   - What conditions trigger it?\n\n")
                            
                            rep.write("2. ATTACK VECTOR:\n")
                            rep.write("   - How can this vulnerability be exploited?\n")
                            rep.write("   - What is the severity (remote code execution, DoS, etc.)?\n")
                            rep.write("   - What privileges are required to exploit it?\n\n")
                            
                            rep.write("3. IMPACT ASSESSMENT:\n")
                            rep.write("   - What are the security implications?\n")
                            rep.write("   - Can it lead to privilege escalation?\n")
                            rep.write("   - Is arbitrary code execution possible?\n\n")
                            
                            rep.write("4. REMEDIATION RECOMMENDATIONS:\n")
                            rep.write("   - What code changes would fix this issue?\n")
                            rep.write("   - Are there input validation improvements needed?\n")
                            rep.write("   - What defensive programming practices apply?\n\n")
                            
                            rep.write("5. SIMILAR VULNERABILITIES:\n")
                            rep.write("   - Are there similar patterns elsewhere in the codebase?\n")
                            rep.write("   - What preventive measures should be implemented?\n\n")
                            
                            rep.write("=" * 80 + "\n")
                            rep.write("END OF REPORT\n")
                            rep.write("=" * 80 + "\n")
                        
                        os.chmod(report_path, 0o666)
                        print(f"[✓] Report generated: {report_path}")

                        os.makedirs(CRASH_REPORTS_DIR, exist_ok=True)
                        os.chmod(CRASH_REPORTS_DIR, 0o777)

                        first_func = unique_functions[0] if unique_functions else "unknown"
                        first_func = re.sub(r'[^\w\-]', '_', first_func)

                        firmware_name_clean = re.sub(r'[^\w\-]', '_', firmware_name)
                        brand_name_clean = re.sub(r'[^\w\-]', '_', brand_name)
                        module_name_clean = re.sub(r'[^\w\-]', '_', module_name)

                        centralized_report_name = f"{brand_name_clean}_{firmware_name_clean}_{module_name_clean}_{first_func}.report"
                        centralized_report_path = os.path.join(CRASH_REPORTS_DIR, centralized_report_name)

                        try:
                            shutil.copy2(report_path, centralized_report_path)
                            os.chmod(centralized_report_path, 0o666)
                            print(f"[✓] Copied report to centralized directory: {centralized_report_name}")
                        except Exception as e:
                            print(f"[WARN] Could not copy report to centralized directory: {e}")

                        try:
                            update_crash_analysis_prompt()
                        except Exception as e:
                            print(f"[WARN] Could not update crash analysis prompt: {e}")

                    except Exception as e:
                        print(f"[ERROR] Could not write report for {seed_base}: {e}")

def test_mode(container_name):
    global config

    firmware = config["GENERAL"]["firmware"]
    seed_input = config["TEST"]["seed_input"]
    port = config["TEST"]["port"]
    timeout = config["TEST"]["timeout"]
    process_name = config["TEST"]["process_name"] if config["TEST"]["process_name"] else None

    if not seed_input or not os.path.exists(seed_input):
        print(f"[ERROR] Seed input path not found: {seed_input}")
        return

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    if firmware == "all" and os.path.isdir(seed_input):
        print(f"\n[\033[32m+\033[0m] Test mode with crash detection (BATCH MODE)")
        print(f"Directory: {seed_input}")
        print(f"Port: {port}")
        print(f"Timeout: {timeout}sec")
        print(f"Process name: {process_name}")
        print("="*60)

        test_batch_mode(container_name, seed_input, port, timeout, process_name)
    else:
        if os.path.isdir(seed_input):
            print(f"[ERROR] seed_input is a directory but firmware is not 'all'")
            return

        test_single_seed(container_name, firmware, seed_input, port, timeout, process_name)

def test_single_seed(container_name, firmware, seed_input, port, timeout, process_name):
    global config

    firmware_with_brand = find_firmware_with_brand(firmware)
    if not firmware_with_brand:
        print(f"\n[\033[31mERROR\033[0m] Could not find firmware {firmware} in any brand subdirectory")
        print(f"Please specify firmware as 'brand/firmware.zip' or ensure it exists in firmwares directory")
        return

    print(f"\n[\033[32m+\033[0m] Test mode with crash detection")
    print(f"Firmware: {firmware}")
    if firmware != firmware_with_brand:
        print(f"Full path: {firmware_with_brand}")
    print(f"Seed: {seed_input}")
    print(f"Port: {port}")
    print(f"Timeout: {timeout}sec")
    if process_name:
        print(f"Process name: {process_name}")

    original_firmware = config["GENERAL"]["firmware"]
    config["GENERAL"]["firmware"] = firmware_with_brand

    result = None
    try:
        result = send_and_monitor_seed(
            container_name,
            firmware_with_brand,
            seed_input,
            port=port,
            timeout=timeout,
            check_crashes=True,
            output_minimized=seed_input,
            process_name=process_name
        )
    except Exception as e:
        config["GENERAL"]["firmware"] = original_firmware
        print(f"\n[\033[31mERROR\033[0m] Failed to test seed: {e}")
        return
    finally:
        config["GENERAL"]["firmware"] = original_firmware

    print("WAIT ANOTHER 60 SECS")
    time.sleep(60)
    
    if result:
        send_signal_recursive(result["qemu_pid"], signal.SIGINT)
        try:
            os.waitpid(result["qemu_pid"], 0)
        except:
            pass

        print("\n" + "="*60)
        print("[\033[32m+\033[0m] Test Summary")
        print("="*60)
        print(f"Total requests in seed: {result['total_requests']}")
        print(f"Crash detected: {'Yes' if result['crash_detected'] else 'No'}")
        if result['crash_detected']:
            print(f"Crash pattern: {result['crash_pattern']}")
            print(f"Crash at request: {result['crash_at_request'] + 1}")
        print("="*60)

def test_batch_mode(base_dir, port, timeout, process_name):
    sys.path.insert(0, os.path.join(STAFF_DIR, "analysis"))
    try:
        from extract_crashes import SKIP_MODULES
    except ImportError:
        SKIP_MODULES = set()
        print("[WARN] Could not import SKIP_MODULES, proceeding without filtering")

    def extract_process_from_crash_pattern(pattern):
        if not pattern:
            return None
        parts = pattern.split("sending SIGSEGV to")
        if len(parts) > 1:
            return parts[1].strip()
        return None

    def should_skip_crash(firmware, crashed_process):
        return (firmware, "any", crashed_process) in SKIP_MODULES

    total_tested = 0
    total_crashes_detected = 0
    total_crashes_valid = 0
    total_crashes_skipped = 0
    total_renamed = 0

    results = []

    for firmware_name in sorted(os.listdir(base_dir)):
        firmware_path = os.path.join(base_dir, firmware_name)
        if not os.path.isdir(firmware_path):
            continue

        firmware_with_brand = find_firmware_with_brand(firmware_name)
        if not firmware_with_brand:
            print(f"\n[\033[31m!\033[0m] Could not find firmware {firmware_name} in any brand subdirectory")
            continue

        print(f"\n{'='*60}")
        print(f"[\033[33m*\033[0m] Processing firmware: {firmware_name}")
        print(f"[\033[90m→\033[0m] Full path: {firmware_with_brand}")
        print(f"{'='*60}")

        for module_name in sorted(os.listdir(firmware_path)):
            module_path = os.path.join(firmware_path, module_name)
            if not os.path.isdir(module_path):
                continue

            crashes_dir = os.path.join(module_path, "crashes")
            if not os.path.isdir(crashes_dir):
                continue

            print(f"\n[\033[34m*\033[0m] Module: {module_name}")

            for seed_file in sorted(os.listdir(crashes_dir)):
                seed_path = os.path.join(crashes_dir, seed_file)

                if not os.path.isfile(seed_path):
                    continue
                if ".minimized" in seed_file or seed_file.endswith(".txt"):
                    continue

                print(f"\n  [\033[36m→\033[0m] Testing seed: {seed_file}")
                total_tested += 1

                original_firmware = config["GENERAL"]["firmware"]
                config["GENERAL"]["firmware"] = firmware_with_brand

                try:
                    result = send_and_monitor_seed(
                        container_name,
                        firmware_with_brand,
                        seed_path,
                        port=port,
                        timeout=timeout,
                        check_crashes=True,
                        output_minimized=None,
                        process_name=process_name
                    )

                    config["GENERAL"]["firmware"] = original_firmware

                    send_signal_recursive(result["qemu_pid"], signal.SIGINT)
                    try:
                        os.waitpid(result["qemu_pid"], 0)
                    except:
                        pass
                except Exception as e:
                    config["GENERAL"]["firmware"] = original_firmware
                    print(f"  [\033[31m✗\033[0m] Error testing seed: {e}")
                    results.append({
                        "firmware": firmware_name,
                        "module": module_name,
                        "seed": seed_file,
                        "crash": False,
                        "error": str(e),
                        "total": 0
                    })
                    continue

                if result['crash_detected']:
                    total_crashes_detected += 1

                    crashed_process = extract_process_from_crash_pattern(result['crash_pattern'])

                    if crashed_process and should_skip_crash(firmware_name, crashed_process):
                        total_crashes_skipped += 1
                        results.append({
                            "firmware": firmware_name,
                            "module": module_name,
                            "seed": seed_file,
                            "crash": True,
                            "skipped": True,
                            "pattern": result['crash_pattern'],
                            "crashed_process": crashed_process,
                            "request": result['crash_at_request'] + 1,
                            "total": result['total_requests']
                        })
                        print(f"  [\033[90m⊗\033[0m] Crash detected but SKIPPED (process '{crashed_process}' in SKIP_MODULES)")
                    else:
                        total_crashes_valid += 1

                        results.append({
                            "firmware": firmware_name,
                            "module": module_name,
                            "seed": seed_file,
                            "crash": True,
                            "skipped": False,
                            "pattern": result['crash_pattern'],
                            "crashed_process": crashed_process,
                            "request": result['crash_at_request'] + 1,
                            "total": result['total_requests']
                        })
                        print(f"  [\033[32m✓\033[0m] Crash detected (process: {crashed_process})")

                        if crashed_process and crashed_process != module_name:
                            new_module_path = os.path.join(firmware_path, crashed_process)
                            if not os.path.exists(new_module_path):
                                print(f"  [\033[36m↻\033[0m] Renaming module: {module_name} → {crashed_process}")
                                os.rename(module_path, new_module_path)
                                module_path = new_module_path
                                crashes_dir = os.path.join(module_path, "crashes")
                                module_name = crashed_process
                                total_renamed += 1
                else:
                    results.append({
                        "firmware": firmware_name,
                        "module": module_name,
                        "seed": seed_file,
                        "crash": False,
                        "total": result['total_requests']
                    })
                    print(f"  [\033[33m○\033[0m] No crash detected")

    total_errors = sum(1 for r in results if r.get('error'))

    log_file_path = os.path.join(base_dir, "test_mode_results.log")
    with open(log_file_path, 'w') as log_file:
        log_file.write("="*60 + "\n")
        log_file.write("BATCH TEST MODE RESULTS\n")
        log_file.write("="*60 + "\n\n")
        log_file.write(f"Total seeds evaluated: {total_tested}\n\n")

        results_sorted = sorted(results, key=lambda x: (x['firmware'], x['module'], x['seed']))

        for firmware_name, firmware_results in groupby(results_sorted, key=lambda x: x['firmware']):
            log_file.write(f"\nFirmware: {firmware_name}\n")
            firmware_results_list = list(firmware_results)

            for module_name, module_results in groupby(firmware_results_list, key=lambda x: x['module']):
                log_file.write(f"  Module: {module_name}\n")

                for result in module_results:
                    log_file.write(f"    Seed: {result['seed']}\n")

                    if result.get('error'):
                        log_file.write(f"      → Error: {result['error']}\n")
                    elif result.get('crash'):
                        if result.get('skipped'):
                            log_file.write(f"      → Crash detected but SKIPPED (process '{result.get('crashed_process')}' in SKIP_MODULES)\n")
                        else:
                            log_file.write(f"      → Crash detected at request {result.get('request', 'unknown')}/{result.get('total', 'unknown')} (process: {result.get('crashed_process', 'unknown')})\n")
                    else:
                        log_file.write(f"      → No crash detected\n")

    csv_file_path = os.path.join(base_dir, "test_mode_results.csv")
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = ['firmware', 'module', 'seed', 'crashed_process', 'total_requests',
                     'crash_at_request', 'status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            if result.get('crash'):
                total_requests = result.get('total', 0)
                crash_at_request = result.get('request', 0)
                status = 'skipped' if result.get('skipped') else 'valid'

                writer.writerow({
                    'firmware': result['firmware'],
                    'module': result['module'],
                    'seed': result['seed'],
                    'crashed_process': result.get('crashed_process', 'unknown'),
                    'total_requests': total_requests,
                    'crash_at_request': crash_at_request,
                    'status': status
                })

    print(f"\n\n{'='*60}")
    print(f"[\033[32m+\033[0m] BATCH TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total seeds tested: {total_tested}")
    print(f"Crashes detected: {total_crashes_detected}")
    print(f"  - Valid crashes: {total_crashes_valid}")
    print(f"  - Skipped crashes (SKIP_MODULES): {total_crashes_skipped}")
    print(f"No crash detected: {total_tested - total_crashes_detected - total_errors}")
    print(f"Errors encountered: {total_errors}")
    print(f"Directories renamed: {total_renamed}")
    print(f"Results written to: {log_file_path}")
    print(f"Results CSV written to: {csv_file_path}")
    print(f"{'='*60}")

    if total_crashes_valid > 0:
        print(f"\n[\033[32m+\033[0m] Valid Crash Details:")
        for r in results:
            if r.get('crash') and not r.get('skipped'):
                print(f"  • {r['firmware']}/{r['module']}/{r['seed']}")
                print(f"    Process: {r.get('crashed_process', 'unknown')}")
                print(f"    Pattern: {r['pattern']}")
                print(f"    Crash at request {r['request']}/{r['total']}")

    if total_crashes_skipped > 0:
        print(f"\n[\033[90m+\033[0m] Skipped Crash Details (SKIP_MODULES):")
        for r in results:
            if r.get('crash') and r.get('skipped'):
                print(f"  • {r['firmware']}/{r['module']}/{r['seed']}")
                print(f"    Process: {r.get('crashed_process', 'unknown')}")
                print(f"    Pattern: {r['pattern']}")
                print(f"    Reason: ({r['firmware']}, 'any', '{r.get('crashed_process')}') in SKIP_MODULES")

    if total_errors > 0:
        print(f"\n[\033[31m+\033[0m] Error Details:")
        for r in results:
            if r.get('error'):
                print(f"  • {r['firmware']}/{r['module']}/{r['seed']}")
                print(f"    Error: {r['error']}")

    print(f"\n{'='*60}\n")

def run(capture, crash_analysis, crash_dir=None):
    global config
    global captured_pcap_path

    iid = str(check("run"))
    work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)

    if "true" not in open(os.path.join(work_dir, "web_check")).read():
        return

    if os.path.exists(os.path.join(work_dir, "debug")):
        shutil.rmtree(os.path.join(work_dir, "debug"), ignore_errors=True)

    os.environ["EXEC_MODE"] = "RUN"
    # os.environ["CALLSTACK_TRACE"] = "1"
    # os.environ["INCLUDE_LIBRARIES"] = "1"
    # os.environ["DEBUG"] = "1"
    # os.environ["TAINT"] = "1"
    
    signal.signal(signal.SIGINT, run_capture_signal_handler)

    if os.path.exists(os.path.join(work_dir, "webserver_ready")):
        os.remove(os.path.join(work_dir, "webserver_ready"))

    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()
    sleep=int(float(sleep))

    process = subprocess.Popen(
        ["sudo", "-E", "./run.sh", "-r", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), "run", PSQL_IP],

    )
    qemu_pid = process.pid

    print(f"Sleeping for {sleep} seconds...")
    time.sleep(sleep)
    
    print("[\033[32m+\033[0m] Web service READY!\n")

    if capture:
        blacklist_keywords = config["CAPTURE"]["blacklist_keywords"].split('/')
        whitelist_keywords = config["CAPTURE"]["whitelist_keywords"].split('/')

        pcap_dir = os.path.join(
            work_dir,
            PCAP_DIR,
            os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])),
            os.path.basename(config["GENERAL"]["firmware"])
        )

        os.makedirs(pcap_dir, exist_ok=True)

        captured_pcap_path = os.path.join(pcap_dir, "user_interaction.pcap")

        interface = f"tap_run_{iid}_0"
        target_ip = open(os.path.join(work_dir, "ip")).read().strip()

        subprocess.run([
            "sudo", "-E", "python3", os.path.join(ANALYSIS_DIR, "capture_packets.py"),
            interface,
            target_ip,
            captured_pcap_path,
            " ".join(blacklist_keywords),
            " ".join(whitelist_keywords)
        ])

        os.kill(qemu_pid, signal.SIGINT)

    os.waitpid(qemu_pid, 0)


def fuzz(out_dir, container_name, replay_exp):
    global config

    mode = container_name if container_name else config["GENERAL"]["mode"]
    taint_dir = get_taint_dir(config["PRE-ANALYSIS"]["pre_analysis_id"], TAINT_DIR)
    print(f"PRE-ANALYSIS dir: {taint_dir}")

    if "staff" in mode:
        tmp_iid = str(check("run"))
        tmp_work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", tmp_iid)
        if "true" not in open(os.path.join(tmp_work_dir, "web_check")).read():
            return
        if os.path.exists(os.path.join(tmp_work_dir, "mem_file")):
            os.remove(os.path.join(tmp_work_dir, "mem_file"))
        with open(os.path.join(tmp_work_dir, "time_web"), 'r') as file:
            sleep = file.read().strip()
        sleep=int(float(sleep))
        taint(FIRMAE_DIR, taint_dir, tmp_work_dir, mode, config["GENERAL"]["firmware"], sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])

    iid = str(check(mode))
    work_dir = os.path.join(FIRMAE_DIR, "scratch", mode, iid)

    if "true" not in open(os.path.join(work_dir, "web_check")).read():
        return
    if os.path.exists(os.path.join(work_dir, "mem_file")):
        os.remove(os.path.join(work_dir, "mem_file"))
    with open(os.path.join(work_dir, "time_web"), 'r') as file:
        sleep = file.read().strip()

    os.environ["TAINT"] = "0"
    os.environ["FD_DEPENDENCIES_TRACK"] = "0"
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])
    os.environ["COVERAGE_TRACING"] = str(config["EXTRA_FUZZING"]["coverage_tracing"])
    os.environ["STAGE_MAX"] = str(config["EXTRA_FUZZING"]["stage_max"])
    os.environ["AFL_NO_ARITH"] = str(config["GENERAL_FUZZING"]["afl_no_arith"])
    os.environ["AFL_NO_BITFLIP"] = str(config["GENERAL_FUZZING"]["afl_no_bitflip"])
    os.environ["AFL_NO_INTEREST"] = str(config["GENERAL_FUZZING"]["afl_no_interest"])
    os.environ["AFL_NO_USER_EXTRAS"] = str(config["GENERAL_FUZZING"]["afl_no_user_extras"])
    os.environ["AFL_NO_EXTRAS"] = str(config["GENERAL_FUZZING"]["afl_no_extras"])
    os.environ["AFL_CALIBRATION"] = str(config["GENERAL_FUZZING"]["afl_calibration"])
    os.environ["AFL_SHUFFLE_QUEUE"] = str(config["GENERAL_FUZZING"]["afl_shuffle_queue"])
    # os.environ["DEBUG_FUZZ"] = "1"
    # os.environ["DEBUG"] = "1"

    if "aflnet" in mode or "staff" in mode or replay_exp:
        os.environ["EXEC_MODE"] = "AFLNET"
        os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')   
    elif "triforce" in mode:
        os.environ["EXEC_MODE"] = "TRIFORCE"
    else:
        assert(0)

    with open("/proc/self/status") as file:
        status_content = file.read()

    cpu_to_bind = re.search(r"Cpus_allowed_list:\s*([0-9]+)", status_content)

    if cpu_to_bind:
        cpu_to_bind_value = cpu_to_bind.group(1)
        print("CPU_TO_BIND:", cpu_to_bind_value)
    else:
        print("CPU_TO_BIND not found in /proc/self/status")

    if os.path.exists(os.path.join(work_dir, "outputs")):
        shutil.rmtree(os.path.join(work_dir, "outputs"), ignore_errors=True)
    
    os.makedirs(os.path.join(work_dir, "outputs"))

    if "staff" in mode:
        if out_dir:
            os.makedirs(os.path.join(out_dir, "outputs", "taint_metadata"))
        else:
            os.makedirs(os.path.join(work_dir, "outputs", "taint_metadata"))

    if os.path.exists(os.path.join(work_dir, "inputs")):
        shutil.rmtree(os.path.join(work_dir, "inputs"), ignore_errors=True)
    
    os.makedirs(os.path.join(work_dir, "inputs"))

    filename = os.path.join(work_dir, "ip")
    ip = ""
    try:
        with open(filename, 'r') as file:
            ip = file.read().strip()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    proto = config["AFLNET_FUZZING"]["proto"]
    port = None
    try:
        port = socket.getservbyname(proto)
        print(f"The port for {proto.upper()} is {port}.")
    except OSError:
        print(f"Protocol {proto.upper()} not found.")
        exit(1)

    if "staff" in mode:
        os.environ["SEQUENCE_MINIMIZATION"] = str(config["STAFF_FUZZING"]["sequence_minimization"])

        inputs = os.path.join(work_dir, "inputs")
        pcap_dir = os.path.join(taint_dir, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            pcap_file = os.path.join(pcap_path, "%s.seed"%(pcap_file))
            taint_metadata_file = os.path.join(pcap_path, "%s_metadata.json"%(pcap_file))
            shutil.copy(pcap_file, inputs)

            if out_dir:
                shutil.copy(taint_metadata_file, os.path.join(out_dir, "outputs", "taint_metadata"))
            else:
                shutil.copy(taint_metadata_file, os.path.join(work_dir, "outputs", "taint_metadata"))

    elif "aflnet" in mode:
        inputs = os.path.join(work_dir, "inputs")
        pcap_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            seed_path = os.path.join(inputs, "%s.seed"%(pcap_file))
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            convert_pcap_into_single_seed_file(pcap_path, seed_path, config["AFLNET_FUZZING"]["region_delimiter"])        
    elif "triforce" in mode:
        inputs = os.path.join(work_dir, "inputs")
        os.makedirs(inputs, exist_ok=True)
        seed_path = os.path.join(work_dir, "seed")

        pcap_dir = os.path.join(PCAP_DIR, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]))
        sub_dirs = [d for d in os.listdir(pcap_dir) if os.path.isdir(os.path.join(pcap_dir, d))]

        first_seed_written = False
        for pcap_file in os.listdir(os.path.join(pcap_dir, proto)):
            pcap_path = os.path.join(pcap_dir, proto, pcap_file)
            generated = convert_pcap_into_multiple_seed_files(
                pcap_path,
                inputs,
                pcap_file,
                config["AFLNET_FUZZING"]["region_delimiter"]
            )

            if not first_seed_written and generated:
                seed_files = sorted(
                    [f for f in os.listdir(inputs) if f.startswith(pcap_file)],
                    key=lambda name: int(name.split("_")[-1].split(".")[0])
                )
                if seed_files:
                    src = os.path.join(inputs, seed_files[0])
                    dst = os.path.join(seed_path)
                    shutil.copy(src, dst)
                    first_seed_written = True
    else:
        assert(0)

    subprocess.run(["sudo", "-E", "./run.sh", "-f", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), mode, PSQL_IP])

    filename = os.path.join(work_dir, "afl-qemu-system-trace_cmd")
    afl_qemu_system_trace_cmd = ""
    try:
        with open(filename, 'r') as file:
            afl_qemu_system_trace_cmd = file.read()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    filename = os.path.join(work_dir, "afl-qemu-system-trace_cmd_append")
    afl_qemu_system_trace_cmd_append = ""
    try:
        with open(filename, 'r') as file:
            afl_qemu_system_trace_cmd_append = file.read()
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        exit(1)

    subprocess.run(["sudo", "-E", "tee", "/proc/sys/kernel/core_pattern"], input=b"core\n", check=True)

    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"

    prev_dir = os.getcwd()
    os.chdir(work_dir)

    env["MAP_SIZE_POW2"] = str(config["GENERAL_FUZZING"]["map_size_pow2"])

    command = ["sudo", "-E"]
    # command += ["gdb", "--args"]
    command += ["./afl-fuzz"]
    command += ["-t", "8000000+"]
    command += ["-w", str(config["GENERAL_FUZZING"]["timeout"])]
    command += ["-b", cpu_to_bind_value]
    command += ["-y", str(config["GENERAL_FUZZING"]["fuzz_tmout"])]
    command += ["-m", "none"]
    command += ["-i", inputs]
    if out_dir:
        command += ["-o", os.path.join(out_dir, "outputs")]
    else:
        command += ["-o", "outputs"]
    command += ["-x", "keywords"]
    command += ["-D", str(sleep)]
    if "staff" in mode or "aflnet" in mode:
        command += ["-N", f"tcp://{ip}/{port}"]
        command += ["-P", proto.upper()]
        if config["AFLNET_FUZZING"]["region_level_mutation"]:
            command += ["-R"]
        if config["STAFF_FUZZING"]["checkpoint_strategy"]:
            command += ["-X"]
    if "staff" in mode:
        command += ["-H"]
        with open(os.path.join(work_dir, "taint_metrics"), 'w') as file:
            file.write(config["STAFF_FUZZING"]["taint_metrics"])
        with open(os.path.join(taint_dir, os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.basename(config["GENERAL"]["firmware"]), "global_elapsed_time"), "r") as f:
            global_elapsed_time_ms = f.read().strip()
        command += ["-A", global_elapsed_time_ms]
        if config["STAFF_FUZZING"]["taint_hints_all_at_once"]:
            command += ["-O"]
    if "state_aware" in mode:
        command += ["-E"]

    replay_cmd = list(command)
    replay_cmd += ["-N", f"tcp://{ip}/{port}"]
    replay_cmd += ["-P", proto.upper()]
    if config["AFLNET_FUZZING"]["region_level_mutation"]:
        replay_cmd += ["-R"]
    if config["STAFF_FUZZING"]["checkpoint_strategy"]:
        replay_cmd += ["-X"]

    command += ["-QQ"]
    command += ["--"]

    for arg in afl_qemu_system_trace_cmd.split(" "):
        if arg != '':
            command.append(arg.strip())

    command.append("-append")

    command.append(afl_qemu_system_trace_cmd_append.strip())

    command.append("--aflFile")
    command.append("@@")

    if not replay_exp:
        ret = 1
        try:
            print(" ".join(command))
            subprocess.run(
                command,
                env=env,
                check=True
            )
            ret = 0
        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            ret = 1

    if "triforce" in mode or replay_exp:
        os.chdir(prev_dir)
        cleanup(FIRMAE_DIR, work_dir)
        subprocess.run(["sudo", "-E", "./run.sh", "-f", os.path.basename(os.path.dirname(config["GENERAL"]["firmware"])), os.path.join(FIRMWARE_DIR, config["GENERAL"]["firmware"]), mode, PSQL_IP])
        os.chdir(work_dir)

        if out_dir:
            os.rename(os.path.join(out_dir, "outputs", "plot_data"), os.path.join(out_dir, "outputs", "old_plot_data"))
            os.rename(os.path.join(out_dir, "outputs", "fuzzer_stats"), os.path.join(out_dir, "outputs", "old_fuzzer_stats"))
        else:
            os.rename(os.path.join("outputs", "plot_data"), os.path.join("outputs", "old_plot_data"))
            os.rename(os.path.join("outputs", "fuzzer_stats"), os.path.join("outputs", "old_fuzzer_stats"))

        os.environ["EXEC_MODE"] = "AFLNET"
        os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
        os.environ["AFL_SKIP_CPUFREQ"] = "1"
        env = os.environ.copy()

        command = ["sudo", "-E"]
        command += ["./afl-fuzz-net" if x == "./afl-fuzz" else x for x in replay_cmd[2:]]
        command += ["-Y"]
        command += ["-QQ"]
        command += ["--"]

        for arg in afl_qemu_system_trace_cmd.split(" "):
            if arg != '':
                command.append(arg.strip())

        command.append("-append")

        command.append(afl_qemu_system_trace_cmd_append.strip())

        command.append("--aflFile")
        command.append("@@")

        try:
            print(" ".join(command))
            subprocess.run(
                command,
                env=env,
                check=True
            )
            ret = 0
        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            ret = 1

    os.chdir(prev_dir)

    if out_dir:
        if ret:
            update_schedule_status(SCHEDULE_CSV_PATH_0, "failed", os.path.basename(out_dir))
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
        else:
            update_schedule_status(SCHEDULE_CSV_PATH_0, "succeeded", os.path.basename(out_dir))

            # if os.path.isdir(out_dir):
            #     os.makedirs(EXP_DONE_PATH, exist_ok=True)

            #     def get_next_available_exp_name(out_dir):
            #         used = set()
            #         pattern = re.compile(r'^exp_(\d+)$')
            #         for entry in os.listdir(out_dir):
            #             match = pattern.match(entry)
            #             if match:
            #                 used.add(int(match.group(1)))
            #         n = 1
            #         while True:
            #             if n not in used:
            #                 return f"exp_{n}"
            #             n += 1

            #     new_exp_name = get_next_available_exp_name(EXP_DONE_PATH)
            #     dst_path = os.path.join(EXP_DONE_PATH, new_exp_name)
            #     print(f"Moving succeeded experiment {os.path.basename(out_dir)} -> {new_exp_name}")
            #     shutil.move(out_dir, dst_path)

    return ret

def pre_analysis(container_name):
    global config

    mode = container_name if container_name else config["GENERAL"]["mode"]
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    if (config["GENERAL"]["firmware"] != "all"):
        iid = str(check(mode))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", mode, iid)

        if "true" in open(os.path.join(work_dir, "web_check")).read():
            with open(os.path.join(work_dir, "time_web"), 'r') as file:
                sleep = file.read().strip()
            sleep=int(float(sleep))

            taint_dir = get_taint_dir(config["PRE-ANALYSIS"]["pre_analysis_id"], TAINT_DIR)
            print(f"PRE-ANALYSIS dir: {taint_dir}")
            taint(FIRMAE_DIR, taint_dir, work_dir, mode, config["GENERAL"]["firmware"], sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])
    else:
        firmware_brands = {}
        
        for brand in os.listdir(PCAP_DIR):
            brand_path = os.path.join(PCAP_DIR, brand)
            if os.path.isdir(brand_path):
                firmware_brands[brand] = {}
                for device in os.listdir(brand_path):
                    device_path = os.path.join(brand_path, device)
                    if os.path.isdir(device_path):
                        firmware_brands[brand][device] = [
                            os.path.join(root, f)
                            for root, _, files in os.walk(device_path)
                            for f in files
                        ]

        if not firmware_brands:
            return

        for brand, devices in firmware_brands.items():
            for device, files in devices.items():
                print(f"Pre-analyzing {os.path.basename(brand)}/{os.path.basename(device)}")
                iid = str(check_firmware(os.path.join(os.path.basename(brand), os.path.basename(device)), mode))
                work_dir = os.path.join(FIRMAE_DIR, "scratch", mode, iid)

                if "true" in open(os.path.join(work_dir, "web_check")).read():
                    with open(os.path.join(work_dir, "time_web"), 'r') as file:
                        sleep = file.read().strip()
                    sleep=int(float(sleep))

                    taint_dir = get_taint_dir(config["PRE-ANALYSIS"]["pre_analysis_id"], TAINT_DIR)
                    print(f"PRE-ANALYSIS dir: {taint_dir}")
                    taint(FIRMAE_DIR, taint_dir, work_dir, mode, os.path.join(os.path.basename(brand), os.path.basename(device)), sleep, config["GENERAL_FUZZING"]["timeout"], config["PRE-ANALYSIS"]["subregion_divisor"], config["PRE-ANALYSIS"]["min_subregion_len"], config["PRE-ANALYSIS"]["delta_threshold"], config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"])

def crash_analysis(container_name):
    global config
    global removed_wait_for_container_init

    os.environ["EXEC_MODE"] = "RUN"
    os.environ["REGION_DELIMITER"] = config["AFLNET_FUZZING"]["region_delimiter"].decode('latin-1')
    os.environ["INCLUDE_LIBRARIES"] = str(config["EMULATION_TRACING"]["include_libraries"])

    PROCESS_RE = re.compile(r".*Process:\s*(\S+)")
    MODULE_RE  = re.compile(r".*module:\s*(\S+)")
    PC_RE      = re.compile(r"pc:\s*(0x[0-9A-Fa-f]+)")
    SYMBOL_TAG = ", symbol:"

    module_cache: Dict[str, tuple[angr.Project, list[tuple[int, int, str]]]] = {}

    def set_permissions_recursive(path: str, mode: int = 0o777) -> None:
        for root, dirs, files in os.walk(path):
            os.chmod(root, mode)
            for f in files:
                os.chmod(os.path.join(root, f), mode)

    def run_extractor(fw_path: str, extract_dir: str) -> None:
        env = os.environ.copy()
        env["NO_PSQL"] = "1"
        subprocess.run(
            [
                "./sources/extractor/extractor.py",
                "-t", "run",
                "-b", "unknown",
                "-sql", "0.0.0.0",
                "-np",
                "-nk",
                fw_path,
                extract_dir
            ],
            env=env,
            check=True
        )

    def build_fw_index(root: str) -> Dict[str, str]:
        idx: Dict[str, str] = {}
        for d, _, files in os.walk(root):
            for fn in files:
                idx[os.path.basename(fn)] = os.path.join(d, fn)
        return idx

    def is_angr_loadable(binary_path: str) -> bool:
        try:
            angr.Project(binary_path, auto_load_libs=False)
            return True
        except Exception:
            return False

    def find_module_path(extract_dir: str, module_name: str) -> Optional[str]:
        for d, _, files in os.walk(extract_dir):
            if module_name in files:
                candidate = os.path.join(d, module_name)
                if is_angr_loadable(candidate):
                    return candidate
        return None

    def load_symbols_once(module_path: str) -> Tuple[angr.Project, List[Tuple[int, int, str]]]:

        proj = angr.Project(module_path, auto_load_libs=False)
        mobj = proj.loader.main_object
        base = getattr(mobj, "rebased_addr", None) \
             or getattr(mobj, "mapped_base", None) \
             or getattr(mobj, "linked_base", 0)

        symbol_ranges = []
        for sym in mobj.symbols:
            if sym.is_function:
                start = sym.rebased_addr - base
                end   = start + (sym.size or 1)
                symbol_ranges.append((start, end, sym.name))

        symbol_ranges.sort(key=lambda x: x[0])
        return proj, symbol_ranges

    def fast_symbol_lookup(symbol_ranges: List[Tuple[int, int, str]], addr: int) -> Optional[str]:
        starts = [s[0] for s in symbol_ranges]
        idx = bisect.bisect_right(starts, addr) - 1
        if idx >= 0:
            start, end, name = symbol_ranges[idx]
            if start <= addr < end:
                return name
        return None

    def lookup_symbol(module_path: str, addr: int) -> Optional[str]:
        cached = module_cache.get(module_path)
        if cached is None:
            try:
                proj, ranges = load_symbols_once(module_path)
            except Exception:
                return None
            module_cache[module_path] = (proj, ranges)
            cached = (proj, ranges)

        proj, symbol_ranges = cached

        sym = proj.loader.find_symbol(addr)
        if sym and sym.name:
            return sym.name

        return fast_symbol_lookup(symbol_ranges, addr)

    def annotate_log_file(path: str, extract_dir: str) -> None:
        with open(path, "r") as f:
            lines = f.readlines()

        out: list[str] = []
        for line in lines:
            if SYMBOL_TAG in line:
                out.append(line)
                continue

            m_mod = MODULE_RE.match(line)
            m_pc  = PC_RE.search(line)
            if not (m_mod and m_pc):
                out.append(line)
                continue

            module_name = m_mod.group(1).rstrip('.,;:')
            addr        = int(m_pc.group(1), 16)
            module_path = find_module_path(extract_dir, module_name)
            if not module_path:
                out.append(line)
                continue

            sym = lookup_symbol(module_path, addr)
            if sym:
                out.append(line.rstrip("\n") + f"{SYMBOL_TAG} {sym}\n")
            else:
                out.append(line)

        with open(path, "w") as f:
            f.writelines(out)
        os.chmod(path, 0o777)
        print(f"[INFO] Annotated symbols in {path}")

    def get_source_seed_info(crash_file: str, experiments_dir: str, firmware: str, method: str, exp: str) -> int:
        if "id&1" not in crash_file:
            return None

        src_match = re.search(r'src:(\d+)', crash_file)
        if not src_match:
            print(f"[WARN] Could not extract source seed ID from: {crash_file}")
            return None

        src_id = src_match.group(1)

        queue_dir = os.path.join(experiments_dir, exp, "outputs", "queue")
        print(f"[DEBUG] Looking for source seed in: {queue_dir}")

        if not os.path.isdir(queue_dir):
            print(f"[WARN] Queue directory not found: {queue_dir}")
            return None

        source_seed_path = None
        for filename in os.listdir(queue_dir):
            if filename.startswith(f"id:{src_id},") or filename.startswith(f"id:{src_id}$"):
                source_seed_path = os.path.join(queue_dir, filename)
                print(f"[DEBUG] Found source seed: {filename}")
                break

        if not source_seed_path:
            print(f"[WARN] Source seed id:{src_id} not found in {queue_dir}")
            files = os.listdir(queue_dir)[:5]
            print(f"[DEBUG] First 5 files in queue: {files}")
            return None

        try:
            delimiter = config["AFLNET_FUZZING"]["region_delimiter"]
            with open(source_seed_path, 'rb') as f:
                seed_data = f.read()

            regions = [r for r in seed_data.split(delimiter) if r]
            src_req_count = len(regions)

            print(f"[INFO] Source seed id:{src_id} has {src_req_count} requests")
            return src_req_count

        except Exception as e:
            print(f"[WARN] Failed to read source seed {source_seed_path}: {e}")
            return None

    def extract_tte_from_filename(filename: str) -> int:
        match = re.search(r'\$(\d+)', filename)
        return int(match.group(1)) if match else -1

    def extract_func_from_trace(trace_file_path: str, firmware_name: str = None) -> str:
        if not trace_file_path or not os.path.isfile(trace_file_path):
            return "unknown"

        try:
            pc_ranges = {}
            crashes_csv_path = os.path.join(ANALYSIS_DIR, "crashes.csv")
            if os.path.isfile(crashes_csv_path):
                sys.path.insert(0, ANALYSIS_DIR)
                try:
                    from extract_crashes import load_pc_ranges_from_csv
                    pc_ranges = load_pc_ranges_from_csv(crashes_csv_path, output_py="/tmp/pc_ranges_temp.py", verbose=False)
                except Exception as e:
                    print(f"[WARN] Could not load PC_RANGES from crashes.csv: {e}")

            pc_str = None
            module_name = None
            in_trace = False

            with open(trace_file_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    if line.startswith("=== Trace"):
                        in_trace = True
                        continue

                    if in_trace:
                        if line.startswith("Process:"):
                            continue

                        m_pc = re.search(r"pc:\s*(0x[0-9A-Fa-f]+)", line)
                        m_mod = re.search(r"module:\s*([^\s,]+)", line)

                        if m_pc:
                            pc_str = m_pc.group(1)
                        if m_mod:
                            module_name = m_mod.group(1).rstrip('.,;:')

                        if line.startswith("["):
                            break

            if pc_ranges and firmware_name and module_name and pc_str:
                try:
                    pc_int = int(pc_str, 16)
                    fw_basename = os.path.basename(firmware_name)

                    for fw_key, modmap in pc_ranges.items():
                        if fw_key.lower() != fw_basename.lower() and fw_key not in fw_basename and fw_basename not in fw_key:
                            continue

                        ranges = modmap.get(module_name) or modmap.get(module_name.lower())
                        if not ranges:
                            continue

                        for func_name, tpl in ranges.items():
                            if len(tpl) == 3:
                                start, end, category = tpl
                            else:
                                start, end = tpl
                                category = None

                            try:
                                s = int(start)
                                e = int(end)
                            except:
                                continue

                            if s <= pc_int <= e:
                                print(f"[INFO] Mapped PC {pc_str} in {module_name} to function: {func_name}")
                                return func_name
                except Exception as e:
                    print(f"[WARN] Error mapping PC to function: {e}")

            if pc_str:
                print(f"[INFO] Function not found in crashes.csv, using PC value: {pc_str}")
                return pc_str

            with open(trace_file_path, 'r') as f:
                for line in f:
                    if SYMBOL_TAG in line:
                        parts = line.split(SYMBOL_TAG)
                        if len(parts) > 1:
                            func_name = parts[1].strip()
                            return func_name if func_name else "unknown"
            return "unknown"
        except Exception as e:
            print(f"[WARN] Failed to extract function from trace: {e}")
            return "unknown"

    def log_processed_crash(status: str, firmware_name: str, method_name: str, exp_name: str,
                           module_name: str, func_name: str, seed_path: str,
                           tte: int = -1, src_requests: int = -1,
                           original_requests: int = -1, minimized_requests: int = -1) -> None:
        lock_file_path = CRASH_PROCESSING_LOG + ".lock"
        lock_fd = None

        try:
            log_entry = f"{status}#{method_name}#{exp_name}#{firmware_name}#{module_name}#{func_name}#{seed_path}#{tte}#{src_requests}#{original_requests}#{minimized_requests}\n"

            lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_RDWR, 0o666)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            try:
                with open(CRASH_PROCESSING_LOG, "a") as log_file:
                    log_file.write(log_entry)
                    log_file.flush()

                print(f"[LOG] {status}: {firmware_name}/{method_name}/{exp_name}/{module_name}/{func_name}")
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

        except Exception as e:
            print(f"[WARN] Failed to log crash: {e}")
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
                except:
                    pass

    def move_dir_contents(src_dir: str, dest_dir: str) -> None:
        if not os.path.isdir(src_dir):
            raise ValueError(f"Source {src_dir!r} is not a directory")

        if not os.listdir(src_dir):
            return False

        if os.path.exists(dest_dir) and not os.path.isdir(dest_dir):
            shutil.move(dest_dir, dest_dir.replace(os.path.basename(dest_dir), "seed"))
            os.makedirs(dest_dir, exist_ok=True)
            shutil.move(dest_dir.replace(os.path.basename(dest_dir), "seed"), dest_dir)

        for name in os.listdir(src_dir):
            s = os.path.join(src_dir, name)
            d = os.path.join(dest_dir, name)
            if os.path.exists(d):
                if os.path.isdir(d):
                    shutil.rmtree(d)
                else:
                    os.remove(d)
            shutil.move(s, d)

        return True

    def rename_crash_files(base_dir):
        if not os.path.isdir(base_dir):
            print(f"Error: Directory '{base_dir}' does not exist.")
            sys.exit(1)

        for root, dirs, files in os.walk(base_dir):
            if os.path.basename(root) == "crash_traces":
                crashes_dir = os.path.join(os.path.dirname(root), "crashes")
                if not os.path.isdir(crashes_dir):
                    continue

                trace_files = {f.split(":", 1)[1]: f for f in files if ":" in f}

                for crash_file in os.listdir(crashes_dir):
                    if ":" not in crash_file:
                        continue
                    crash_id = crash_file.split(":", 1)[1]
                    if crash_id in trace_files:
                        old_path = os.path.join(crashes_dir, crash_file)
                        new_path = os.path.join(crashes_dir, trace_files[crash_id])
                        if old_path != new_path:
                            print(f"Renaming:\n  {old_path}\n  -> {new_path}")
                            shutil.move(old_path, new_path)

    if not os.path.exists(CRASH_DIR):
        print(f"[\033[33m!\033[0m] CRASH_DIR not found: {CRASH_DIR}")
        print(f"[\033[36m*\033[0m] Running extract_crashes.py to create crash directory...")

        extract_crashes_script = os.path.join(ANALYSIS_DIR, "extract_crashes.py")
        crashes_csv = os.path.join(ANALYSIS_DIR, "crashes.csv")

        try:
            subprocess.run(
                [
                    "python3", extract_crashes_script,
                    EXPERIMENTS_DIR_0,
                    "--extracted_root", CRASH_DIR,
                    "--update",
                    "--annotate",
                    "--crashes-csv", crashes_csv,
                    "--show-exp-count",
                    "--include-zero-crashes"
                ],
                check=True,
                cwd=STAFF_DIR
            )
            print(f"[\033[32m+\033[0m] extract_crashes.py completed successfully")
        except subprocess.CalledProcessError as e:
            print(f"[\033[31m!\033[0m] extract_crashes.py failed: {e}")
            raise RuntimeError(f"Failed to create CRASH_DIR with extract_crashes.py")

    firmware_path = config["GENERAL"]["firmware"]
    base_fw = os.path.basename(firmware_path)

    if os.path.dirname(firmware_path):
        firmware_with_brand = firmware_path
    else:
        firmware_with_brand = base_fw

    crash_root = os.path.join(CRASH_DIR, firmware_with_brand)
    if not os.path.exists(crash_root):
        removed_wait_for_container_init = True
        print(f"[\033[33m!\033[0m] Crash directory not found: {crash_root}, skipping!")
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        return

    print(f"[\033[36m*\033[0m] Processing crashes from: {crash_root}")

    fw_index   = build_fw_index(FIRMWARE_DIR)

    for root, dirs, files in os.walk(crash_root):
        if os.path.basename(root) != "crashes":
            continue

        extract_dir = tempfile.mkdtemp(prefix="extracted_")
        try:
            fw_file = fw_index.get(base_fw)
            if not fw_file:
                print(f"[WARN] Firmware '{firmware_with_brand}' not found under {FIRMWARE_DIR}")
                continue

            run_extractor(fw_file, extract_dir)
            set_permissions_recursive(extract_dir)

            tars = glob.glob(os.path.join(extract_dir, "*.tar.gz"))
            if not tars:
                raise FileNotFoundError("No .tar.gz in extracted/")
            latest = max(tars, key=os.path.getmtime)
            with tarfile.open(latest, "r:gz") as tar:
                tar.extractall(path=extract_dir)

            for crash_file in files:

                crash_file_path = os.path.join(root, crash_file)

                if "README" in crash_file:
                    continue

                if crash_file.endswith(".lock"):
                    continue

                if crash_file.endswith(".succ") or crash_file.endswith(".fail"):
                    continue

                lock_file_path = crash_file_path + ".lock"
                try:
                    lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                except FileExistsError:
                    print(f"[SKIP] Seed {crash_file} is locked by another container")
                    continue
                except OSError as e:
                    print(f"[ERROR] Failed to create lock for {crash_file}: {e}")
                    continue

                try:
                    try:
                        print(f"lock_file_path: {lock_file_path}")
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (OSError, IOError) as e:
                        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                            print(f"[SKIP] Seed {crash_file} is being processed by another container")
                            continue
                        else:
                            raise

                    print(f"[LOCK ACQUIRED] Processing seed: {crash_file}")

                    if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
                        os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))

                    succ_seed_path = crash_file_path + ".succ"
                    fail_seed_path = crash_file_path + ".fail"
                    if os.path.exists(succ_seed_path) or os.path.exists(fail_seed_path):
                        print(f"[SKIP] Already processed: {crash_file}")
                        continue

                    crash_trace = crash_file_path.replace("/crashes", "/crash_traces")
                    if not os.path.isfile(crash_trace):
                        print(f"[WARN] No trace file found for {crash_file}, skipping")
                        continue

                    crash_trace_dir = os.path.dirname(crash_trace)

                    path_parts = root.rstrip('/').split('/')
                    try:
                        crashes_idx = path_parts.index('crashes')
                        exp_name = path_parts[crashes_idx - 1]
                        method_name = path_parts[crashes_idx - 2]
                    except (ValueError, IndexError):
                        print(f"[WARN] Could not extract method/exp from path: {root}")
                        method_name = "unknown"
                        exp_name = "unknown"

                    target_process = None
                    module_name = None
                    with open(crash_trace) as tf:
                        for line in tf:
                            m = PROCESS_RE.match(line)
                            if m:
                                target_process = m.group(1)
                            m_mod = MODULE_RE.match(line)
                            if m_mod:
                                module_name = m_mod.group(1).rstrip('.,;:')
                            if target_process and module_name:
                                break

                    process_list_for_monitoring = []
                    if target_process:
                        process_list_for_monitoring.append(target_process)
                    if module_name and module_name != target_process:
                        process_list_for_monitoring.append(module_name)
                        if module_name == "atp" and "xgi" not in process_list_for_monitoring:
                            process_list_for_monitoring.append("xgi")

                    process_names_csv = ",".join(process_list_for_monitoring) if process_list_for_monitoring else target_process

                    if module_name:
                        from analysis.extract_crashes import SKIP_MODULES
                        fw_name_only = base_fw
                        if (fw_name_only, method_name, module_name) in SKIP_MODULES or \
                           (fw_name_only, "any", module_name) in SKIP_MODULES:
                            print(f"[\033[33m!\033[0m] Seed filtered by SKIP_MODULES: {fw_name_only}/{method_name}/{module_name}")

                            tte = extract_tte_from_filename(crash_file)
                            log_processed_crash(
                                status="FAILED_4",
                                firmware_name=firmware_with_brand,
                                method_name=method_name,
                                exp_name=exp_name,
                                module_name=module_name or "unknown",
                                func_name="unknown",
                                seed_path=crash_file_path,
                                tte=tte,
                                src_requests=-1,
                                original_requests=-1,
                                minimized_requests=-1
                            )

                            lock_file = crash_file_path + ".lock"
                            if os.path.isfile(lock_file):
                                os.remove(lock_file)
                                print(f"[CLEANUP] Removed lock file: {lock_file}")

                            minimize_test_file = crash_file_path + ".minimize_test"
                            if os.path.isfile(minimize_test_file):
                                os.remove(minimize_test_file)
                                print(f"[CLEANUP] Removed minimize test file: {minimize_test_file}")

                            fail_seed_path = crash_file_path + ".fail"
                            if os.path.isfile(crash_file_path):
                                os.rename(crash_file_path, fail_seed_path)
                                print(f"[✗] Marked as failed (renamed): {crash_file} -> {os.path.basename(fail_seed_path)}")

                            # print(f"[\033[33m!\033[0m] Removing crash seed and trace...")
                            # for path in [crash_file_path, crash_trace]:
                            #     if os.path.isfile(path):
                            #         os.remove(path)
                            #         print(f"[REMOVED] {path}")
                            continue

                    if not target_process:
                        print(f"[WARN] No target process found in trace file, skipping")
                        continue

                    original_req_count = None
                    try:
                        delimiter = config["AFLNET_FUZZING"]["region_delimiter"]
                        with open(crash_file_path, 'rb') as f:
                            seed_data = f.read()
                        original_requests = [r for r in seed_data.split(delimiter) if r]
                        original_req_count = len(original_requests)
                        print(f"[INFO] Original request count: {original_req_count}")
                    except Exception as e:
                        print(f"[WARN] Could not count original requests: {e}")

                    print(f"[\033[36m*\033[0m] Verifying crash reproducibility for {crash_file}...")
                    print(f"[DEBUG] Monitoring processes: {process_names_csv}")
                    # try:
                    verify_result = send_and_monitor_seed(
                        container_name,
                        firmware_path,
                        crash_file_path,
                        port=80,
                        timeout=config["GENERAL_FUZZING"]["timeout"],
                        check_crashes=True,
                        process_name=process_names_csv
                    )

                    if verify_result["crash_detected"]:
                        test_requests = original_requests[:verify_result["crash_at_request"]+1]
                        len_test_requests = len(test_requests)
                        minimized_data = delimiter.join(test_requests)
                        print(f"Write minimized seed ({len_test_requests}): {crash_file_path}")
                        with open(crash_file_path, 'wb') as f:
                            f.write(minimized_data)

                    send_signal_recursive(verify_result["qemu_pid"], signal.SIGINT)
                    try:
                        os.waitpid(verify_result["qemu_pid"], 0)
                    except:
                        pass

                    if not verify_result['crash_detected']:
                        print(f"[\033[31m!\033[0m] Crash NOT reproducible, removing seed and trace...")

                        tte = extract_tte_from_filename(crash_file)
                        log_processed_crash(
                            status="FAILED_3",
                            firmware_name=firmware_with_brand,
                            method_name=method_name,
                            exp_name=exp_name,
                            module_name=module_name or "unknown",
                            func_name="unknown",
                            seed_path=crash_file_path,
                            tte=tte,
                            src_requests=-1,
                            original_requests=original_req_count if original_req_count else -1,
                            minimized_requests=-1
                        )

                        lock_file = crash_file_path + ".lock"
                        if os.path.isfile(lock_file):
                            os.remove(lock_file)
                            print(f"[CLEANUP] Removed lock file: {lock_file}")

                        minimize_test_file = crash_file_path + ".minimize_test"
                        if os.path.isfile(minimize_test_file):
                            os.remove(minimize_test_file)
                            print(f"[CLEANUP] Removed minimize test file: {minimize_test_file}")

                        fail_seed_path = crash_file_path + ".fail"
                        if os.path.isfile(crash_file_path):
                            os.rename(crash_file_path, fail_seed_path)
                            print(f"[✗] Marked as failed (renamed): {crash_file} -> {os.path.basename(fail_seed_path)}")

                        # for path in [crash_file_path, crash_trace]:
                        #     if os.path.isfile(path):
                        #         os.remove(path)
                        #         print(f"[REMOVED] {path}")
                        continue
                    else:
                        print(f"[\033[32m✓\033[0m] Crash verified as reproducible")
                    # except Exception as e:
                    #     print(f"[\033[31m!\033[0m] Verification failed: {e}, skipping this seed")
                    #     continue

                    src_req_count = None
                    if "id&1" in crash_file:
                        print(f"[DEBUG] Detected id&1 seed, extracting source info...")
                        src_req_count = get_source_seed_info(
                            crash_file,
                            EXPERIMENTS_DIR_0,
                            firmware_with_brand,
                            method_name,
                            exp_name
                        )
                        print(f"[DEBUG] Source request count: {src_req_count}")

                    minimized_req_count = None

                    if target_process:
                        print(f"[\033[36m*\033[0m] Starting automatic minimization for {crash_file}...")
                        # try:
                        minimization_result = minimize_crash_seed(
                            container_name,
                            firmware_path,
                            crash_file_path,
                            port=80,
                            timeout=config["GENERAL_FUZZING"]["timeout"],
                            process_name=process_names_csv
                        )
                        #original_req_count = minimization_result['original_count']
                        minimized_req_count = minimization_result['minimized_count']
                        print(f"[\033[32m✓\033[0m] Minimization complete: {original_req_count} → {minimized_req_count} requests")
                        # except Exception as e:
                        #     print(f"[\033[33m!\033[0m] Minimization failed: {e}, continuing with original seed")

                    with open(crash_trace) as tf:
                        not_reproducible = False
                        for line in tf:
                            m = PROCESS_RE.match(line)
                            if not m:
                                continue
                            iid = str(check_firmware(
                                firmware_path,
                                "run"
                            ))
                            work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)
                            if "true" in open(os.path.join(work_dir, "web_check")).read():
                                if "/seed" not in crash_trace:
                                    crash_detected = replay_firmware(
                                        firmware_path,
                                        work_dir, True,
                                        crash_file_path,
                                        process_names_csv
                                    )

                                    if not crash_detected:
                                        print(f"[\033[31m!\033[0m] Crash NOT reproducible during replay, removing seed...")

                                        tte = extract_tte_from_filename(crash_file)
                                        log_processed_crash(
                                            status="FAILED_2",
                                            firmware_name=firmware_with_brand,
                                            method_name=method_name,
                                            exp_name=exp_name,
                                            module_name=module_name or "unknown",
                                            func_name="unknown",
                                            seed_path=crash_file_path,
                                            tte=tte,
                                            src_requests=src_req_count if src_req_count else -1,
                                            original_requests=original_req_count if original_req_count else -1,
                                            minimized_requests=-1
                                        )

                                        lock_file = crash_file_path + ".lock"
                                        if os.path.isfile(lock_file):
                                            os.remove(lock_file)
                                            print(f"[CLEANUP] Removed lock file: {lock_file}")

                                        minimize_test_file = crash_file_path + ".minimize_test"
                                        if os.path.isfile(minimize_test_file):
                                            os.remove(minimize_test_file)
                                            print(f"[CLEANUP] Removed minimize test file: {minimize_test_file}")

                                        fail_seed_path = crash_file_path + ".fail"
                                        if os.path.isfile(crash_file_path):
                                            os.rename(crash_file_path, fail_seed_path)
                                            print(f"[✗] Marked as failed (renamed): {crash_file} -> {os.path.basename(fail_seed_path)}")

                                        # for path in [crash_file_path, crash_trace]:
                                        #     if os.path.isfile(path):
                                        #         os.remove(path)
                                        #         print(f"[REMOVED] {path}")
                                        # not_reproducible = True
                                        break

                                dest_trace_file = crash_file_path.replace("/crashes/", "/crash_traces/")
                                dest_trace_dir = dest_trace_file + "_traces"

                                old_module_name = None
                                if os.path.isfile(dest_trace_file):
                                    try:
                                        with open(dest_trace_file, 'r') as f:
                                            process_found = False
                                            for line in f:
                                                if "Process:" in line:
                                                    process_found = True
                                                    continue
                                                if process_found and "module:" in line:
                                                    m_mod = MODULE_RE.search(line)
                                                    if m_mod:
                                                        old_module_name = m_mod.group(1).rstrip('.,;:')
                                                        break
                                        print(f"[DEBUG] Old trace module: {old_module_name}")
                                    except Exception as e:
                                        print(f"[WARN] Could not read old trace file: {e}")

                                os.makedirs(dest_trace_dir, exist_ok=True)

                                if "/seed" not in crash_trace:
                                    ret = move_dir_contents(os.path.join(work_dir, "crash_analysis"), dest_trace_dir)
                                    if ret is False:
                                        not_reproducible = True
                                        break
                                    shutil.copy(os.path.join(work_dir, "qemu.final.serial.log"), dest_trace_dir)

                                annotated_trace = None
                                matching_log = None
                                module_mismatch = False

                                for fn in os.listdir(dest_trace_dir):
                                    if "qemu" not in fn and "/seed" not in fn:
                                        trace_path = os.path.join(dest_trace_dir, fn)

                                        if old_module_name and matching_log is None:
                                            try:
                                                new_module_name = None
                                                with open(trace_path, 'r') as f:
                                                    process_found = False
                                                    for line in f:
                                                        if "Process:" in line:
                                                            process_found = True
                                                            continue
                                                        if process_found and "module:" in line:
                                                            m_mod = MODULE_RE.search(line)
                                                            if m_mod:
                                                                new_module_name = m_mod.group(1).rstrip('.,;:')
                                                                break

                                                print(f"[DEBUG] New trace {fn} module: {new_module_name}")

                                                if new_module_name == old_module_name:
                                                    matching_log = trace_path
                                                    print(f"[INFO] Found matching trace (module: {new_module_name}): {fn}")
                                                elif new_module_name and new_module_name != old_module_name:
                                                    print(f"[WARN] Module mismatch: old={old_module_name}, new={new_module_name}")
                                                    module_mismatch = True
                                            except Exception as e:
                                                print(f"[WARN] Could not read {fn}: {e}")

                                        print(os.path.join(dest_trace_dir, fn))
                                        annotate_log_file(trace_path, extract_dir)
                                        if annotated_trace is None:
                                            annotated_trace = trace_path

                                if module_mismatch and not matching_log:
                                    print(f"[\033[31m!\033[0m] Module mismatch detected, crash trace inconsistent")

                                    tte = extract_tte_from_filename(crash_file)
                                    log_processed_crash(
                                        status="FAILED_1",
                                        firmware_name=firmware_with_brand,
                                        method_name=method_name,
                                        exp_name=exp_name,
                                        module_name=module_name or "unknown",
                                        func_name="unknown",
                                        seed_path=crash_file_path,
                                        tte=tte,
                                        src_requests=src_req_count if src_req_count else -1,
                                        original_requests=original_req_count if original_req_count else -1,
                                        minimized_requests=-1
                                    )
                                    not_reproducible = True

                                    lock_file = crash_file_path + ".lock"
                                    if os.path.isfile(lock_file):
                                        os.remove(lock_file)
                                        print(f"[CLEANUP] Removed lock file: {lock_file}")

                                    minimize_test_file = crash_file_path + ".minimize_test"
                                    if os.path.isfile(minimize_test_file):
                                        os.remove(minimize_test_file)
                                        print(f"[CLEANUP] Removed minimize test file: {minimize_test_file}")

                                    fail_seed_path = crash_file_path + ".fail"
                                    if os.path.isfile(crash_file_path):
                                        os.rename(crash_file_path, fail_seed_path)
                                        print(f"[✗] Marked as failed (renamed): {crash_file} -> {os.path.basename(fail_seed_path)}")

                                    break

                                if matching_log:
                                    if os.path.isfile(dest_trace_file):
                                        os.remove(dest_trace_file)
                                    shutil.copy2(matching_log, dest_trace_file)
                                    print(f"[INFO] Replaced crash trace with matching log: {os.path.basename(matching_log)}")
                                    annotated_trace = dest_trace_file
                                elif annotated_trace:
                                    if os.path.isfile(dest_trace_file):
                                        os.remove(dest_trace_file)
                                    shutil.copy2(annotated_trace, dest_trace_file)
                                    print(f"[WARN] No matching trace found, using first trace: {os.path.basename(annotated_trace)}")
                                    annotated_trace = dest_trace_file

                                func_name = extract_func_from_trace(annotated_trace, firmware_name=firmware_with_brand)
                                tte = extract_tte_from_filename(crash_file)

                                log_processed_crash(
                                    status="SUCCEEDED",
                                    firmware_name=firmware_with_brand,
                                    method_name=method_name,
                                    exp_name=exp_name,
                                    module_name=module_name or "unknown",
                                    func_name=func_name,
                                    seed_path=crash_file_path,
                                    tte=tte,
                                    src_requests=src_req_count if src_req_count else -1,
                                    original_requests=original_req_count if original_req_count else -1,
                                    minimized_requests=minimized_req_count if minimized_req_count else -1
                                )

                                if os.path.isdir(dest_trace_dir):
                                    shutil.rmtree(dest_trace_dir, ignore_errors=True)
                                    print(f"[CLEANUP] Removed trace directory: {dest_trace_dir}")

                                lock_file = crash_file_path + ".lock"
                                if os.path.isfile(lock_file):
                                    os.remove(lock_file)
                                    print(f"[CLEANUP] Removed lock file: {lock_file}")

                                minimize_test_file = crash_file_path + ".minimize_test"
                                if os.path.isfile(minimize_test_file):
                                    os.remove(minimize_test_file)
                                    print(f"[CLEANUP] Removed minimize test file: {minimize_test_file}")

                                succ_seed_path = crash_file_path + ".succ"
                                if os.path.isfile(crash_file_path):
                                    os.rename(crash_file_path, succ_seed_path)
                                    print(f"[✓] Marked as processed (renamed): {crash_file} -> {os.path.basename(succ_seed_path)}")

                        if not_reproducible:
                            print("NOT REPRODUCIBLE!", crash_file_path, crash_file_path.replace("crashes", "crash_traces"))

                            for path in [crash_file_path, crash_file_path.replace("crashes", "crash_traces")]:
                                if os.path.isdir(path):
                                    shutil.rmtree(path, ignore_errors=True)
                                    with open(CRASH_ANALYSIS_LOG, "a+") as log_file:
                                        log_file.write(f"Removed directory: {path}\n")
                                elif os.path.isfile(path):
                                    os.remove(path)
                                    with open(CRASH_ANALYSIS_LOG, "a+") as log_file:
                                        log_file.write(f"Removed file: {path}\n")

                finally:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                        os.close(lock_fd)
                    except:
                        pass
                    try:
                        os.remove(lock_file_path)
                    except:
                        pass
                    print(f"[LOCK RELEASED] Finished processing seed: {crash_file}")
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

def start(keep_config, reset_firmware_images, replay_exp, out_dir, container_name, crash_dir=None, config_dict=None):
    global PSQL_IP, config
    global removed_wait_for_container_init

    PSQL_IP = "0.0.0.0"
    os.environ["NO_PSQL"] = "1"

    if reset_firmware_images:
        for pattern in patterns:
            for path in glob.glob(pattern):
                if os.path.isdir(path):
                    print(f"Removing directory: {path}")
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    print(f"Removing file: {path}")
                    os.remove(path)
        # if os.path.exists(CRASH_PROCESSING_LOG):
        #     os.remove(CRASH_PROCESSING_LOG)
        # if os.path.exists(CRASH_ANALYSIS_LOG):
        #     os.remove(CRASH_ANALYSIS_LOG)
        # if os.path.exists(CRASH_PROCESSING_LOG+".lock"):
        #     os.remove(CRASH_PROCESSING_LOG+".lock")
        # if os.path.exists(CRASH_SEED_COUNT_LOG):
        #     os.remove(CRASH_SEED_COUNT_LOG)


    if config_dict is not None:
        config = config_dict
    else:
        config = load_config(CONFIG_INI_PATH)

    if not keep_config:
        if any(x in config["GENERAL"]["mode"] for x in ["aflnet_base", "aflnet_state_aware", "triforce", "staff_base", "staff_state_aware"]):
            if out_dir:
                copy_file(CONFIG_INI_PATH, os.path.join(out_dir, "outputs"))
            else:
                os.remove(CONFIG_INI_PATH)
        else:
            os.remove(CONFIG_INI_PATH)

    prev_dir = os.getcwd()
    os.chdir(FIRMAE_DIR)

    mode = config["GENERAL"]["mode"]
    if mode == "run":
        run(False, False)
    elif mode == "run_capture":
        run(True, False)
    elif mode == "replay":
        replay()
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif mode == "test":
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        test_mode(container_name)
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif mode == "unique_crash_report":
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        generate_unique_crash_reports(container_name)
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif mode == "replay_mem_count":
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        firmware_filter = config["GENERAL"]["firmware"]
        replay_with_mem_counting(firmware_filter=firmware_filter)
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif mode == "crash_analysis":
        crash_analysis(container_name)
        if not removed_wait_for_container_init:
            removed_wait_for_container_init = True
            if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
                os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif mode == "check":
        wait_file = os.path.join(STAFF_DIR, "wait_for_container_init")
        pid = os.fork()
        if pid == 0:
            try:
                time.sleep(10)
                if os.path.exists(wait_file):
                    os.remove(wait_file)
                    print(f"[\033[32m✓\033[0m] Removed {wait_file} after 5 seconds")
            except Exception as e:
                print(f"[\033[31m!\033[0m] Failed to remove {wait_file}: {e}")
            finally:
                os._exit(0)
        else:
            check("run", enable_csv_logging=True)
            if out_dir:
                update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif "pre_analysis" in mode:
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        pre_analysis(container_name)
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif "pre_exp" in mode:
        if os.path.exists(os.path.join(STAFF_DIR, "wait_for_container_init")):
            os.remove(os.path.join(STAFF_DIR, "wait_for_container_init"))
        iid = str(check(container_name if container_name else config["GENERAL"]["mode"]))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", container_name if container_name else config["GENERAL"]["mode"], iid)

        if "true" in open(os.path.join(work_dir, "web_check")).read():
            with open(os.path.join(work_dir, "time_web"), 'r') as file:
                sleep = file.read().strip()
            sleep=int(float(sleep))

            with open(os.path.join(work_dir, "taint_metrics"), 'w') as file:
                file.write(config["STAFF_FUZZING"]["taint_metrics"])

            taint_dir = get_taint_dir(config["PRE-ANALYSIS"]["pre_analysis_id"], TAINT_DIR)
            print(f"PRE-ANALYSIS dir: {taint_dir}")

            pre_analysis_exp(os.path.join(PRE_ANALYSIS_EXP_DIR, "pre_analysis_"+str(config["PRE-ANALYSIS"]["pre_analysis_id"])), FIRMAE_DIR, work_dir, container_name if container_name else config["GENERAL"]["mode"], config["GENERAL"]["firmware"], os.path.basename(config["AFLNET_FUZZING"]["proto"]), config["EMULATION_TRACING"]["include_libraries"], config["AFLNET_FUZZING"]["region_delimiter"], sleep, config["GENERAL_FUZZING"]["timeout"], taint_dir, config["PRE-ANALYSIS"]["pre_analysis_id"])
        
        if out_dir:
            update_schedule_status(SCHEDULE_CSV_PATH_1, "succeeded", os.path.basename(out_dir))
    elif any(x in mode for x in ["aflnet_base", "aflnet_state_aware", "triforce", "staff_base", "staff_state_aware"]) or replay_exp:
        fuzz(out_dir, container_name, replay_exp)
    else:
        assert False, f"Unknown mode: {mode}"

    os.chdir(prev_dir)

if __name__ == "__main__":
    os.umask(0o000)
    parser = argparse.ArgumentParser(description="Process some arguments.")
    parser.add_argument("--keep_config", type=int, help="Keep config file", default=1)
    parser.add_argument("--reset_firmware_images", type=int, help="Reset firmware images", default=0)
    parser.add_argument("--replay_exp", type=int, help="Replay an experiment (triforce)", default=0)
    parser.add_argument("--output", type=str, help="Output dir", default=None)
    parser.add_argument("--container_name", type=str, help="Container name", default=None)
    parser.add_argument("--crash_dir", type=str, help="Directory of crash outputs for crash_analysis mode", default=None)

    parser.add_argument("--test", action="store_true", help="Enable test mode: send seed to firmware")
    parser.add_argument("--firmware", type=str, help="Firmware path for test mode (e.g., dlink/dap2310_v1.00_o772.bin)", default=None)
    parser.add_argument("--seed_input", type=str, help="Seed input file path for test mode", default=None)
    parser.add_argument("--port", type=int, help="Target port for test mode (default: 80)", default=80)
    parser.add_argument("--timeout", type=int, help="Request timeout in sec for test mode (default: 150 sec)", default=150)
    parser.add_argument("--process_name", type=str, help="Process name to monitor for crashes (e.g., mini_httpd) - REQUIRED for test mode", default=None)

    parser.add_argument("--replay-mem-count", action="store_true", help="Enable replay mode with memory operations counting")
    parser.add_argument("--mem-count-log", type=str, help="Output CSV file for memory operations counting results (stored in STAFF main directory, default: mem_ops_replay_results.csv)", default="mem_ops_replay_results.csv")
    parser.add_argument("--unique-crash-report", action="store_true", help="Replay all seeds in unique_crashes and generate detailed reports")

    args = parser.parse_args()

    config_memory = None
    if args.test or args.unique_crash_report:
        if args.test and (not args.firmware or not args.seed_input):
            print("[ERROR] Test mode requires --firmware, --seed_input, and --process_name arguments")
            exit(1)

        if args.unique_crash_report:
            config_memory = {
                "GENERAL": {
                    "mode": "unique_crash_report",
                    "firmware": args.firmware if args.firmware else ""
                },
                "AFLNET_FUZZING": {
                    "region_delimiter": b'\x1A\x1A\x1A\x1A',
                    "proto": "http",
                    "region_level_mutation": 1
                },
                "EMULATION_TRACING": {
                    "include_libraries": 1
                },
                "GENERAL_FUZZING": {
                    "timeout": args.timeout,
                    "map_size_pow2": 25,
                    "fuzz_tmout": 86400,
                    "afl_no_arith": 1,
                    "afl_no_bitflip": 0,
                    "afl_no_interest": 1,
                    "afl_no_user_extras": 1,
                    "afl_no_extras": 1,
                    "afl_calibration": 1,
                    "afl_shuffle_queue": 1
                },
                "TEST": {
                    "seed_input": "",
                    "port": 80,
                    "timeout": args.timeout,
                    "process_name": ""
                }
            }
            print(f"[INFO] Unique crash report mode configuration created (in memory, no config.ini)")
        else:
            import configparser
            config_tmp = configparser.ConfigParser()
            config_tmp["GENERAL"] = {
                "mode": "test",
                "firmware": args.firmware if args.firmware else ""
            }
            config_tmp["AFLNET_FUZZING"] = {
                "region_delimiter": "\\x1A\\x1A\\x1A\\x1A",
                "proto": "http",
                "region_level_mutation": "1"
            }
            config_tmp["EMULATION_TRACING"] = {
                "include_libraries": "1"
            }
            config_tmp["GENERAL_FUZZING"] = {
                "timeout": str(args.timeout)
            }

            if args.test:
                config_tmp["TEST"] = {
                    "seed_input": os.path.abspath(args.seed_input),
                    "port": str(args.port),
                    "timeout": str(args.timeout),
                    "process_name": args.process_name if args.process_name else ""
                }

            with open(CONFIG_INI_PATH, "w") as f:
                config_tmp.write(f)

            print(f"[INFO] Test mode configuration created")
            print(f"  Firmware: {args.firmware}")
            print(f"  Seed: {os.path.abspath(args.seed_input)}")
            print(f"  Port: {args.port}")
            print(f"  Timeout: {args.timeout}sec")
            if args.process_name:
                print(f"  Process name: {args.process_name}")

    if args.replay_mem_count:
        config_tmp = configparser.ConfigParser()
        config_tmp["GENERAL"] = {
            "mode": "replay_mem_count",
            "firmware": args.firmware if args.firmware else "all"
        }
        config_tmp["AFLNET_FUZZING"] = {
            "region_delimiter": "\\x1A\\x1A\\x1A\\x1A",
            "proto": "http",
            "region_level_mutation": "1"
        }
        config_tmp["EMULATION_TRACING"] = {
            "include_libraries": "1"
        }
        config_tmp["GENERAL_FUZZING"] = {
            "timeout": "150"
        }

        mem_count_csv_path = args.mem_count_log
        if not os.path.isabs(mem_count_csv_path):
            mem_count_csv_path = os.path.join(STAFF_DIR, mem_count_csv_path)
        else:
            mem_count_csv_path = os.path.abspath(mem_count_csv_path)

        config_tmp["MEM_COUNT"] = {
            "output_csv": mem_count_csv_path
        }

        with open(CONFIG_INI_PATH, "w") as f:
            config_tmp.write(f)

        print(f"[INFO] Replay with memory counting mode configuration created")
        print(f"  Firmware: {args.firmware if args.firmware else 'all'}")
        print(f"  Output CSV: {mem_count_csv_path}")

    start(
        args.keep_config if not (args.test or args.replay_mem_count or args.unique_crash_report) else 1,
        args.reset_firmware_images,
        args.replay_exp,
        os.path.abspath(args.output) if args.output else None,
        args.container_name if args.container_name else None,
        args.crash_dir,
        config_dict=config_memory
    )