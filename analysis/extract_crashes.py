#!/usr/bin/env python3
import os
import configparser
import shutil
import re
import argparse
from typing import List, Tuple
import pandas as pd
import csv
import textwrap
from collections import defaultdict
from typing import Dict, Tuple
import subprocess

STAFF_DIR = os.getcwd()
FIRMAE_DIR = os.path.join(STAFF_DIR, "FirmAE")

SKIP_MODULES = {}
SKIP_MODULES = {("any", "aflnet_base", "any")}
SKIP_MODULES = {("any", "aflnet_base", "any"), ("dap2310_v1.00_o772.bin", "any", "neaps_array"), ("dap2310_v1.00_o772.bin", "any", "neapc"),
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

CAUSALITY_CATEGORY_ORDER = ["OIB", "OID", "OII", "MIB", "MID", "MII"]

# DEFAULT_METHODS = ["triforce", "aflnet_state_aware", "aflnet_base", "staff_state_aware"]
# COMPETITORS = ["triforce", "aflnet_state_aware", "aflnet_base"]
DEFAULT_METHODS = ["triforce", "aflnet_state_aware", "staff_state_aware"]
COMPETITORS = ["triforce", "aflnet_state_aware"]

METHOD_ABBR = {
    "aflnet_base": "AB",
    "aflnet_state_aware": "ASA",
    "triforce": "TRI",
    "staff_state_aware": "STAFF"
}

TOOL_FILTER = "staff_state_aware"
ALLOWED_TOOLS = set(DEFAULT_METHODS) | {"all"}

FILTER_METRIC_CHOICE = "recall"
DEDUP_METRIC_CHOICE = "recall"

OUTPUT_DIR = "analysis_results"

MAX_EXP_NUM = None

def ordered_categories(keys):
    ordered = [c for c in CAUSALITY_CATEGORY_ORDER if c in keys]
    extras = sorted([c for c in keys if c not in CAUSALITY_CATEGORY_ORDER])
    return ordered + extras

def should_include_experiment(exp_name: str) -> bool:
    if MAX_EXP_NUM is None:
        return True

    match = re.match(r'exp[_-]?(\d+)', exp_name, re.IGNORECASE)
    if match:
        exp_num = int(match.group(1))
        return exp_num <= MAX_EXP_NUM

    return True

PC_RANGES = {
    # "DGN3500-V1.1.00.30_NA.zip": {
    #     "setup.cgi": {
    #         "FUN_A": (0x000115d0, 0x00018f34),
    #     },
    # },
    # # other firmwares...
}

GROUPS = []

def check(mode, firmware):
    PSQL_IP = "0.0.0.0"
    iid = ""
    os.environ["NO_PSQL"] = "1"
    subprocess.run(["sudo", "-E", "./flush_interface.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    prev_dir = os.getcwd()
    os.chdir(FIRMAE_DIR)

    if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
        if not subprocess.run(["sudo", "-E", "./scripts/util.py", "check_connection", "_", PSQL_IP, mode], stdout=subprocess.PIPE).returncode == 0:
            print("[\033[31m-\033[0m] docker container failed to connect to the hosts' postgresql!")
            exit(1)

    iid = subprocess.check_output(["sudo", "-E", "./scripts/util.py", "get_iid", os.path.join("..", "firmwares", firmware), PSQL_IP, mode]).decode('utf-8').strip()
    if iid == "":
        assert(0)
    
    os.chdir(prev_dir)

    return iid

def _parse_num_token(tok: str):
    if tok is None:
        raise ValueError("Empty token")
    s = str(tok).strip().lower()
    if not s:
        raise ValueError("Empty token")

    try:
        return int(s, 0)
    except Exception:
        pass
    m = re.search(r'([0-9a-fA-F]+)', s)
    if m:
        try:
            return int(m.group(1), 16)
        except Exception:
            pass
    raise ValueError(f"Cannot parse numeric token: {tok!r}")

def load_pc_ranges_from_csv(csv_path: str = "crashes.csv",
                            output_py: str = "pc_ranges_generated.py",
                            verbose: bool = True) -> Dict[str, Dict[str, Dict[str, Tuple[int,int,str,str]]]]:
    pc_ranges = defaultdict(lambda: defaultdict(dict))

    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    if verbose:
        print(f"[INFO] reading PC ranges from: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        row_no = 0
        for raw in reader:
            row_no += 1
            if not raw:
                continue

            firmware = raw.get("firmware", "").strip()
            module = raw.get("module", "").strip()
            start_tok = raw.get("start_pc", "").strip()
            end_tok = raw.get("end_pc", "").strip()
            func_tok = raw.get("function_name", "").strip()
            category = raw.get("analysis_result", "").strip()
            cve_id = raw.get("cve", "").strip()
            bug_id = raw.get("bug_id", "").strip()

            if not firmware or not module or not start_tok or not end_tok:
                if verbose:
                    print(f"[WARN] row {row_no}: missing required fields")
                continue

            if not category:
                category = None
            if not cve_id or cve_id == "???":
                cve_id = None
            if not bug_id:
                bug_id = None

            func_name = None
            if func_tok:
                fn = str(func_tok).strip()
                fn = fn.strip().lstrip(",").strip()
                if fn.startswith("(") and fn.endswith(")"):
                    fn = fn[1:-1].strip()
                fn = fn.strip("'\" ")
                if fn:
                    func_name = fn

            if func_name is None:
                func_name = f"range_{start_tok}_{end_tok}"

            try:
                s_int = _parse_num_token(start_tok)
                e_int = _parse_num_token(end_tok)
            except Exception as ex:
                if verbose:
                    print(f"[ERROR] row {row_no}: cannot parse ({start_tok},{end_tok}) -> {ex}; skipping")
                continue

            if s_int > e_int:
                if verbose:
                    print(f"[WARN] row {row_no}: start > end, swapping: {hex(s_int)} > {hex(e_int)}")
                s_int, e_int = e_int, s_int

            if func_name in pc_ranges[firmware][module]:
                if verbose:
                    old = pc_ranges[firmware][module][func_name]
                    print(f"[WARN] row {row_no}: duplicate function '{func_name}' for {firmware}/{module}; "
                          f"old={old} -> new={(s_int,e_int,category,cve_id,bug_id)} (overwriting)")

            pc_ranges[firmware][module][func_name] = (s_int, e_int, category, cve_id, bug_id)
            if verbose:
                print(f"[ROW {row_no}] {firmware} / {module} -> {func_name}: "
                      f"0x{s_int:08x}-0x{e_int:08x} [{category}]")

    pc_ranges = {fw: {mod: dict(funcs) for mod, funcs in mods.items()} for fw, mods in pc_ranges.items()}

    lines = []
    lines.append("# Auto-generated PC_RANGES from " + os.path.basename(csv_path))
    lines.append("PC_RANGES = {")
    for fw, mods in sorted(pc_ranges.items()):
        lines.append(f"    {fw!r}: {{")
        for mod, funcs in sorted(mods.items()):
            lines.append(f"        {mod!r}: {{")
            for fname, (s, e, cat, cve_id, bug_id) in sorted(funcs.items()):
                cat_repr = repr(cat) if cat is not None else "None"
                cve_repr = repr(cve_id) if cve_id is not None else "None"
                bug_repr = repr(bug_id) if bug_id is not None else "None"
                lines.append(f"            {fname!r}: (0x{s:08x}, 0x{e:08x}, {cat_repr}, {cve_repr}, {bug_repr}),")
            lines.append("        },")
        lines.append("    },")
    lines.append("}")
    content = "\n".join(lines) + "\n"

    try:
        with open(output_py, "w", encoding="utf-8") as ofh:
            ofh.write(content)
        if verbose:
            print(f"[WRITE] PC_RANGES python literal -> {output_py}")
    except Exception as ex:
        if verbose:
            print(f"[ERROR] cannot write {output_py}: {ex}")

    return pc_ranges


def get_firmware_order_from_csv(csv_path: str = "crashes.csv") -> list:
    """
    Extract firmware names from crashes.csv in the order they appear.
    Returns a list of unique firmware names preserving order.
    """
    firmware_order = []
    seen = set()

    if not os.path.isfile(csv_path):
        return []

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            firmware = row.get("firmware", "").strip()
            if firmware and firmware not in seen:
                firmware_order.append(firmware)
                seen.add(firmware)

    return firmware_order


def chmod_recursive(path, mode):
    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
        for f in files:
            os.chmod(os.path.join(root, f), mode)

    os.chmod(path, mode)

def extract_crash_id(filename: str):
    try:
        after_colon = filename.split(":", 1)[1]
        crash_id = after_colon.split(",", 1)[0]
        return crash_id
    except IndexError:
        return None

def read_start_time(fuzzer_stats_path: str):
    if not os.path.isfile(fuzzer_stats_path):
        return None
    with open(fuzzer_stats_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if ln.startswith("start_time"):
                parts = ln.split(":", 1)
                if len(parts) == 2:
                    try:
                        return int(parts[1].strip())
                    except ValueError:
                        return None
    return None

def parse_plot_changes(plot_path: str) -> List[Tuple[int,int,int]]:
    events = []
    if not os.path.isfile(plot_path):
        return events
    prev = None
    with open(plot_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.split(",")]
            if len(parts) < 9:
                continue
            try:
                unix_time = int(parts[0])
                unique_crashes = int(parts[8])
            except ValueError:
                continue
            if prev is None:
                prev = unique_crashes
                continue
            if unique_crashes != prev:
                events.append((unix_time, prev, unique_crashes))
                prev = unique_crashes
            else:
                prev = unique_crashes
    return events

def safe_rename(src: str, dst: str, overwrite: bool=True):
    if os.path.abspath(src) == os.path.abspath(dst):
        return
    if os.path.exists(dst):
        if overwrite:
            os.remove(dst)
        else:
            raise FileExistsError(dst)
    os.rename(src, dst)

def make_tte_suffix(filename: str, tte: int) -> str:
    if re.search(r'\$\d+', filename):
        return re.sub(r'\$\d+', f'${tte}', filename)

    if "." in filename:
        base, ext = filename.rsplit(".", 1)
        return f"{base}${tte}.{ext}"
    else:
        return f"{filename}${tte}"


def unify_crash_and_trace_filenames(extracted_root="extracted_crashes", verbose=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[ERROR] extracted_root does not exist: {extracted_root}")
        return

    for entry in sorted(os.listdir(extracted_root)):
        entry_path = os.path.join(extracted_root, entry)
        if not os.path.isdir(entry_path):
            continue

        has_methods = any(method in DEFAULT_METHODS for method in os.listdir(entry_path) if os.path.isdir(os.path.join(entry_path, method)))

        firmware_paths = []
        if has_methods:
            firmware_paths.append(entry_path)
        else:
            for fw in sorted(os.listdir(entry_path)):
                fw_path = os.path.join(entry_path, fw)
                if os.path.isdir(fw_path):
                    firmware_paths.append(fw_path)

        for firmware_path in firmware_paths:
            for mode in sorted(os.listdir(firmware_path)):
                mode_path = os.path.join(firmware_path, mode)
                if not os.path.isdir(mode_path):
                    continue

                for sub_exp in sorted(os.listdir(mode_path)):
                    exp_path = os.path.join(mode_path, sub_exp)
                    if not os.path.isdir(exp_path):
                        continue

                    # Filter by MAX_EXP_NUM if set
                    if not should_include_experiment(sub_exp):
                        continue

                    crashes_dir = os.path.join(exp_path, "crashes")
                    traces_dir = os.path.join(exp_path, "crash_traces")
                    if not (os.path.isdir(crashes_dir) and os.path.isdir(traces_dir)):
                        continue

                crash_map = {}

                for f in os.listdir(crashes_dir):
                    fpath = os.path.join(crashes_dir, f)

                    if os.path.isfile(fpath):
                        cid = extract_crash_id(f)
                        if cid:
                            crash_map[cid] = fpath

                    elif os.path.isdir(fpath):
                        for subf in os.listdir(fpath):
                            subpath = os.path.join(fpath, subf)
                            if os.path.isfile(subpath):
                                cid = extract_crash_id(subf)
                                if cid:
                                    crash_map[cid] = subpath


                trace_map = {}

                for f in os.listdir(traces_dir):
                    fpath = os.path.join(traces_dir, f)

                    if os.path.isfile(fpath):
                        cid = extract_crash_id(f)
                        if cid:
                            trace_map[cid] = fpath

                    elif os.path.isdir(fpath):
                        for subf in os.listdir(fpath):
                            subpath = os.path.join(fpath, subf)
                            if os.path.isfile(subpath):
                                cid = extract_crash_id(subf)
                                if cid:
                                    trace_map[cid] = subpath

                for cid in sorted(set(crash_map.keys()) | set(trace_map.keys())):
                    cfile = crash_map.get(cid)
                    tfile = trace_map.get(cid)

                    if not (cfile and tfile):
                        continue

                    cbase = os.path.basename(cfile)
                    tbase = os.path.basename(tfile)

                    if len(cbase) > len(tbase):
                        suffix = tbase.split("$")[-1] if "$" in tbase else ""
                        new_name = f"{cbase.split('$')[0]}${suffix}" if suffix else cbase.split('$')[0]
                        new_path = os.path.join(traces_dir, new_name)

                        if new_path != tfile and not os.path.exists(new_path):
                            if verbose:
                                print(f"[RENAME] crash_trace: {tfile} -> {new_path}")
                            os.rename(tfile, new_path)

                    elif len(tbase) > len(cbase):
                        suffix = cbase.split("$")[-1] if "$" in cbase else ""
                        new_name = f"{tbase.split('$')[0]}${suffix}" if suffix else tbase.split('$')[0]
                        new_path = os.path.join(crashes_dir, new_name)

                        if new_path != cfile and not os.path.exists(new_path):
                            if verbose:
                                print(f"[RENAME] crash: {cfile} -> {new_path}")
                            os.rename(cfile, new_path)

def update_extracted_root_from_experiments(experiments_dir, extracted_root="extracted_crashes", verbose=True):
    def extract_ts_from_name(filename):
        if "$" not in filename:
            return None
        try:
            ts_str = filename.split("$")[-1]
            ts = int(ts_str)
            return ts // 1000
        except Exception:
            return None

    if not os.path.isdir(experiments_dir):
        if verbose:
            print(f"[ERROR] experiments_dir does not exist: {experiments_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_dir)):
        sub_path = os.path.join(experiments_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        if not should_include_experiment(sub_exp):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            if verbose:
                print(f"[INFO] skipping {sub_path}: no config.ini")
            continue

        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            mode = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
        except Exception as e:
            if verbose:
                print(f"[WARN] couldn't read mode/firmware in {config_path}: {e}")
            continue

        if os.path.dirname(firmware_path):
            firmware_with_brand = firmware_path
        else:
            firmware_with_brand = os.path.basename(firmware_path)

        if (os.path.isdir(os.path.join(sub_path, "outputs", "crash_traces")) and not os.listdir(os.path.join(sub_path, "outputs", "crash_traces"))
            and os.path.isdir(os.path.join(sub_path, "outputs", "crashes")) and not os.listdir(os.path.join(sub_path, "outputs", "crashes"))):
            continue

        target_exp_dir = os.path.join(extracted_root, firmware_with_brand, mode, sub_exp)

        for ftype in ("crashes", "crash_traces"):
            os.makedirs(os.path.join(target_exp_dir, ftype), exist_ok=True)

        copied_counts = {"crashes": 0, "crash_traces": 0}

        for ftype in ("crashes", "crash_traces"):
            src_folder = os.path.join(sub_path, "outputs", ftype)
            dst_folder = os.path.join(target_exp_dir, ftype)

            if not os.path.isdir(src_folder):
                if verbose:
                    print(f"[INFO] no {ftype} in {sub_path}, skipping {ftype}")
                continue

            for file in sorted(os.listdir(src_folder)):
                src_file = os.path.join(src_folder, file)
                if not os.path.isfile(src_file):
                    continue

                crash_id = extract_crash_id(file)
                if crash_id is None:
                    if verbose:
                        print(f"[WARN] cannot extract crash id from '{file}', skipping")
                    continue

                already_exists = False
                is_done_file = False
                for existing_file in os.listdir(dst_folder):
                    existing_path = os.path.join(dst_folder, existing_file)
                    if not os.path.isfile(existing_path):
                        continue
                    if extract_crash_id(existing_file) == crash_id:
                        if existing_file.endswith(".succ"):
                            is_done_file = True
                            if verbose:
                                print(f"[SKIP] .succ file exists, will not overwrite: {existing_file}")
                        already_exists = True
                        break

                if already_exists:
                    if verbose:
                        print(f"[SKIP] {ftype}: crash_id {crash_id} already exists in extracted_root")
                    continue

                dst_file = os.path.join(dst_folder, file)

                if mode == "triforce":
                    ts = extract_ts_from_name(file)
                    if ts is not None:
                        if "$" in file:
                            prefix, _ = file.rsplit("$", 1)
                            dst_file = os.path.join(dst_folder, f"{prefix}${ts}")

                shutil.copy2(src_file, dst_file)
                if verbose:
                    print(f"Copied NEW to extracted_root: {src_file} -> {dst_file}")
                copied_counts[ftype] += 1

        if verbose:
            print(f"[RESULT] {sub_exp} -> firmware='{firmware_with_brand}', mode='{mode}': "
                  f"crashes_copied={copied_counts['crashes']}, "
                  f"traces_copied={copied_counts['crash_traces']}")

def count_and_log_crash_seeds(extracted_root="extracted_crashes", log_file="crash_seed_count.log", verbose=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[INFO] extracted_root does not exist yet: {extracted_root}")
        return 0

    count = 0
    filtered_files = []

    for root, dirs, files in os.walk(extracted_root):
        if not root.endswith("/crashes") and "/crashes/" not in root and not root.endswith("crashes"):
            continue

        if "/aflnet_base/" in root or root.endswith("/aflnet_base"):
            continue

        for file in files:
            if file.endswith(".lock") or file.endswith(".succ") or file.endswith(".fail") or file.endswith(".minimize_test"):
                continue

            full_path = os.path.join(root, file)
            if os.path.isfile(full_path):
                count += 1
                filtered_files.append(full_path)

    log_path = os.path.join(STAFF_DIR, log_file)
    try:
        with open(log_path, "w") as f:
            f.write(f"Crash seed count (filtered): {count}\n")
            f.write(f"Timestamp: {pd.Timestamp.now()}\n")
            f.write(f"\nFilter criteria:\n")
            f.write(f"  - Path contains: */extracted_crashes/*/crashes/*\n")
            f.write(f"  - Path excludes: */aflnet_base/*\n")
            f.write(f"  - File excludes: *.lock, *.succ, *.fail, *.minimize_test\n")
            f.write(f"\n")

            if verbose and len(filtered_files) <= 100:
                f.write(f"Files counted ({len(filtered_files)}):\n")
                for fpath in sorted(filtered_files):
                    relative_path = os.path.relpath(fpath, STAFF_DIR)
                    f.write(f"  {relative_path}\n")
            elif len(filtered_files) > 100:
                f.write(f"Files counted: {len(filtered_files)} (too many to list)\n")

        if verbose:
            print(f"[INFO] Logged crash seed count to: {log_path}")
            print(f"[INFO] Total crash seeds (filtered): {count}")
    except Exception as e:
        print(f"[ERROR] Failed to write crash seed count log: {e}")

    return count

def print_seed_status_statistics(extracted_root="extracted_crashes", verbose=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[INFO] extracted_root does not exist yet: {extracted_root}")
        return

    succ_count = 0
    fail_count = 0
    unprocessed_count = 0

    seen_base_names = set()

    for root, dirs, files in os.walk(extracted_root):
        if not root.endswith("/crashes") and "/crashes/" not in root and not root.endswith("crashes"):
            continue

        if "/aflnet_base/" in root or root.endswith("/aflnet_base"):
            continue

        for file in files:
            if file.endswith(".lock") or file.endswith(".minimize_test"):
                continue

            full_path = os.path.join(root, file)
            if not os.path.isfile(full_path):
                continue

            if file.endswith(".succ"):
                base_name = file[:-5]
                status = "succ"
            elif file.endswith(".fail"):
                base_name = file[:-5]
                status = "fail"
            else:
                base_name = file
                status = "unprocessed"

            unique_key = os.path.join(root, base_name)

            if unique_key in seen_base_names:
                continue

            seen_base_names.add(unique_key)

            if status == "succ":
                succ_count += 1
            elif status == "fail":
                fail_count += 1
            else:
                unprocessed_count += 1

    total = succ_count + fail_count + unprocessed_count

    print("\n" + "="*60)
    print("SEED FILE STATUS STATISTICS")
    print("="*60)
    print(f"  Seeds with .succ (succeeded):    {succ_count:6d}")
    print(f"  Seeds with .fail (failed):       {fail_count:6d}")
    print(f"  Seeds unprocessed (no suffix):   {unprocessed_count:6d}")
    print(f"  {'-'*58}")
    print(f"  Total seeds:                     {total:6d}")
    print("="*60 + "\n")

def print_unprocessed_seed_paths(extracted_root="extracted_crashes"):
    if not os.path.isdir(extracted_root):
        print(f"[INFO] extracted_root does not exist yet: {extracted_root}")
        return

    unprocessed_paths = []

    for root, dirs, files in os.walk(extracted_root):
        if not root.endswith("/crashes") and "/crashes/" not in root and not root.endswith("crashes"):
            continue

        if "/aflnet_base/" in root or root.endswith("/aflnet_base"):
            continue

        for file in files:
            if file.endswith(".lock") or file.endswith(".minimize_test"):
                continue

            if file.endswith(".succ") or file.endswith(".fail"):
                continue

            full_path = os.path.join(root, file)
            if os.path.isfile(full_path):
                succ_path = full_path + ".succ"
                fail_path = full_path + ".fail"

                if not os.path.exists(succ_path) and not os.path.exists(fail_path):
                    unprocessed_paths.append(full_path)

    print("\n" + "="*60)
    print(f"UNPROCESSED SEEDS (no .succ or .fail suffix): {len(unprocessed_paths)}")
    print("="*60)
    for path in sorted(unprocessed_paths):
        print(path)
    print("="*60 + "\n")

def map_key_by_range_and_groups_standalone(fw, module, pc_str, pc_ranges):
    def pc_to_int(pc_str):
        if pc_str is None:
            return None
        s = str(pc_str).strip()
        try:
            return int(s, 0)
        except:
            m = re.search(r"(0x[0-9a-fA-F]+)", s)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"(\d+)", s)
            if m2:
                return int(m2.group(1))
            return None

    raw = (fw, module, pc_str, None, None)
    pc_int = pc_to_int(pc_str)

    for fw_key, modmap in pc_ranges.items():
        if fw_key.lower() != fw.lower() and fw_key not in fw and fw not in fw_key:
            continue
        ranges = modmap.get(module) or modmap.get(module.lower())
        if not ranges:
            continue
        if pc_int is None:
            continue
        for fun_name, tpl in ranges.items():
            if len(tpl) == 5:
                start, end, category, cve_id, bug_id = tpl
            elif len(tpl) == 4:
                start, end, category, cve_id = tpl
                bug_id = None
            elif len(tpl) == 3:
                start, end, category = tpl
                cve_id = None
                bug_id = None
            else:
                start, end = tpl
                category = None
                cve_id = None
                bug_id = None
            try:
                s = int(start)
                e = int(end)
            except:
                continue
            if s <= pc_int <= e:
                return (fw, module, fun_name, category, cve_id)
    return raw

def extract_unique_crashes_per_function(extracted_root="extracted_crashes", output_dir="unique_crashes", verbose=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[ERROR] extracted_root does not exist: {extracted_root}")
        return

    unique_crashes = {}

    print(f"\n[INFO] Scanning {extracted_root} for unique crashes...")

    for root, dirs, files in os.walk(extracted_root):
        if not (root.endswith("/crashes") or "/crashes/" in root or root.endswith("crashes")):
            continue

        if "/aflnet_base/" in root or root.endswith("/aflnet_base"):
            continue

        parts = root.split(os.sep)
        try:
            extracted_idx = parts.index(extracted_root)
            if extracted_idx + 2 < len(parts):
                firmware = parts[extracted_idx + 2]
                brand = parts[extracted_idx + 1]
            else:
                firmware = "unknown"
        except (ValueError, IndexError):
            firmware = "unknown"

        for file in files:
            if file.endswith(".lock") or file.endswith(".minimize_test"):
                continue

            if file.endswith(".succ"):
                base_name = file[:-5]
                status = "succ"
                seed_path = os.path.join(root, file)
            elif file.endswith(".fail"):
                base_name = file[:-5]
                status = "fail"
                seed_path = os.path.join(root, file)
            else:
                base_name = file
                status = "unprocessed"
                seed_path = os.path.join(root, file)

            trace_root = root.replace("/crashes", "/crash_traces")
            trace_path = os.path.join(trace_root, base_name)

            if not os.path.isfile(trace_path):
                if verbose:
                    print(f"[WARN] No trace file found for {base_name}: {trace_path}")
                continue

            try:
                pc_str, module = _parse_first_frame_pc_module(trace_path)

                if not module:
                    module = "unknown"

                if not pc_str:
                    function = "unknown"
                else:
                    mapped = map_key_by_range_and_groups_standalone(firmware, module, pc_str, PC_RANGES)
                    if mapped and len(mapped) >= 3 and mapped[2]:
                        function = mapped[2]
                    else:
                        function = pc_str

            except Exception as e:
                if verbose:
                    print(f"[WARN] Failed to parse trace file {trace_path}: {e}")
                module = "unknown"
                function = "unknown"

            unique_key = (brand, firmware, module, function)

            status_priority = {"succ": 3, "fail": 2, "unprocessed": 1}

            if unique_key not in unique_crashes:
                unique_crashes[unique_key] = {
                    'seed_path': seed_path,
                    'trace_path': trace_path,
                    'status': status,
                    'priority': status_priority[status]
                }
            else:
                if status_priority[status] > unique_crashes[unique_key]['priority']:
                    unique_crashes[unique_key] = {
                        'seed_path': seed_path,
                        'trace_path': trace_path,
                        'status': status,
                        'priority': status_priority[status]
                    }

    if os.path.exists(output_dir):
        if verbose:
            print(f"[INFO] Output directory exists, will add/overwrite files: {output_dir}")
    else:
        os.makedirs(output_dir, exist_ok=True)
        if verbose:
            print(f"[INFO] Created output directory: {output_dir}")

    copied_count = 0
    for (brand, firmware, module, function), info in sorted(unique_crashes.items()):
        fw_dir = os.path.join(output_dir, brand, firmware)
        module_dir = os.path.join(fw_dir, module)
        os.makedirs(module_dir, exist_ok=True)

        safe_function = function.replace('/', '_').replace('\\', '_')

        seed_basename = os.path.basename(info['seed_path'])
        dest_seed = os.path.join(module_dir, f"{safe_function}__{seed_basename}")
        shutil.copy2(info['seed_path'], dest_seed)

        trace_basename = os.path.basename(info['trace_path'])
        dest_trace = os.path.join(module_dir, f"{safe_function}__{trace_basename}")
        shutil.copy2(info['trace_path'], dest_trace)

        copied_count += 1
        if verbose:
            print(f"[COPY] {brand}/{firmware}/{module}/{function} ({info['status']}) -> {dest_seed}")

    print(f"\n[SUCCESS] Extracted {copied_count} unique crashes to: {output_dir}")
    print(f"           Organized by: firmware/module/function\n")

def events_to_crash_times(events: List[Tuple[int, int, int]]) -> Dict[int, int]:
    crash_times = {}
    for unix_time, prev, new in events:
        for k in range(prev + 1, new + 1):
            crash_times[k] = unix_time
    return crash_times

def annotate_extracted_with_tte(experiments_dir, extracted_root="extracted_crashes", verbose=True):
    if not os.path.isdir(experiments_dir):
        if verbose:
            print(f"[ERROR] experiments_dir does not exist: {experiments_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_dir)):
        sub_path = os.path.join(experiments_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        if not should_include_experiment(sub_exp):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            if verbose:
                print(f"[INFO] skipping {sub_path}: no config.ini")
            continue

        config = configparser.ConfigParser()
        config.read(config_path)
        try:
            mode = config.get("GENERAL", "mode")
            firmware_path = config.get("GENERAL", "firmware")
        except Exception as e:
            if verbose:
                print(f"[WARN] couldn't read mode/firmware in {config_path}: {e}")
            continue

        if os.path.dirname(firmware_path):
            firmware_with_brand = firmware_path
        else:
            firmware_with_brand = os.path.basename(firmware_path)
        target_exp_dir = os.path.join(extracted_root, firmware_with_brand, mode, sub_exp)

        if not os.path.isdir(target_exp_dir):
            if verbose:
                print(f"[INFO] no extracted dir for {sub_exp} at {target_exp_dir}, skipping")
            continue

        fuzzer_stats_path = os.path.join(sub_path, "outputs", "fuzzer_stats")
        start_time = read_start_time(fuzzer_stats_path)
        if start_time is None:
            if verbose:
                print(f"[WARN] no start_time found in {fuzzer_stats_path}, skipping {sub_exp}")
            continue

        plot_candidates = [
            os.path.join(sub_path, "plot_data"),
            os.path.join(sub_path, "outputs", "plot_data"),
        ]
        plot_path = None
        for p in plot_candidates:
            if os.path.isfile(p):
                plot_path = p
                break
        if plot_path is None:
            if verbose:
                print(f"[INFO] no plot_data for {sub_exp}, skipping TTE annotation")
            continue

        events = parse_plot_changes(plot_path)
        if not events:
            if verbose:
                print(f"[INFO] no unique_crashes changes detected in {plot_path}")
            continue

        crash_times = events_to_crash_times(events)

        crashes_folder = os.path.join(target_exp_dir, "crashes")
        crash_entries = {}
        crash_real_mtime = {}
        if os.path.isdir(crashes_folder):
            for fname in sorted(os.listdir(crashes_folder)):
                if "sig" not in fname:
                    continue
                fpath = os.path.join(crashes_folder, fname)
                if not os.path.isfile(fpath):
                    continue
                cid = extract_crash_id(fname)
                if cid is None:
                    cid = f"__fname__::{fname}"
                crash_entries.setdefault(cid, []).append(fname)
                try:
                    crash_real_mtime[cid] = int(os.path.getmtime(fpath))
                except Exception:
                    crash_real_mtime.setdefault(cid, None)

        def cid_sort_key(cid):
            if cid.startswith("__fname__::"):
                return (1, cid)
            try:
                return (0, int(cid))
            except Exception:
                return (1, cid)

        ordered_cids = sorted(list(crash_entries.keys()), key=cid_sort_key)

        cid_to_mtime = {}
        for idx, cid in enumerate(ordered_cids, start=1):
            vmtime = crash_times.get(idx)
            if vmtime is None:
                vmtime = crash_real_mtime.get(cid)
            cid_to_mtime[cid] = vmtime

        iid = str(check("run", firmware_path))
        work_dir = os.path.join(FIRMAE_DIR, "scratch", "run", iid)
        with open(os.path.join(work_dir, "time_web"), 'r') as file:
            sleep = file.read().strip()
        sleep=int(float(sleep))

        files_map = []
        for cid, fnames in crash_entries.items():
            for fname in fnames:
                fpath = os.path.join(crashes_folder, fname)
                if not os.path.isfile(fpath):
                    continue
                mtime = cid_to_mtime.get(cid)
                if mtime is None:
                    continue
                files_map.append((fpath, "crashes", mtime - start_time + sleep))

        traces_folder = os.path.join(target_exp_dir, "crash_traces")
        if os.path.isdir(traces_folder):
            for tname in sorted(os.listdir(traces_folder)):
                if "sig" not in tname:
                    continue
                tpath = os.path.join(traces_folder, tname)
                if not os.path.isfile(tpath):
                    continue
                tcid = extract_crash_id(tname)
                if tcid is None:
                    tcid = f"__fname__::{tname}"
                tm = cid_to_mtime.get(tcid)
                if tm is None:
                    try:
                        tm = int(os.path.getmtime(tpath))
                    except Exception:
                        tm = None
                if tm is not None:
                    files_map.append((tpath, "crash_traces", tm - start_time + sleep))

        matched_any = False

        for fpath, ftype, tte in files_map:
            if "triforce" in fpath:
                continue
            dirname = os.path.dirname(fpath)
            fname = os.path.basename(fpath)
            new_fname = make_tte_suffix(fname, tte)
            new_path = os.path.join(dirname, new_fname)
            if verbose:
                print(f"[RENAME] {ftype}: {fpath} -> {new_path}", tte)
            safe_rename(fpath, new_path, overwrite=True)

            matched_any = True

        if not matched_any and verbose:
            print(f"[WARN] no extracted crash file matched events for {sub_exp}")

def _parse_first_frame_pc_module(trace_path):
    pc = None
    module = None
    in_trace = False
    try:
        with open(trace_path, "r", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                if ln.startswith("=== Trace"):
                    in_trace = True
                    continue
                if in_trace:
                    if ln.startswith("Process:"):
                        continue
                    m_pc = re.search(r"pc:\s*(0x[0-9A-Fa-f]+)", ln)
                    m_mod = re.search(r"module:\s*([^\s,]+)", ln)
                    if m_pc:
                        pc = m_pc.group(1)
                    if m_mod:
                        module = m_mod.group(1)
                    if ln.startswith("["):
                        return (pc, module)
    except Exception:
        return (None, None)
    return (None, None)

def format_time_hm(seconds: float) -> str:
    if seconds is None:
        return ""
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h{m}m"

def count_requests_in_seed(seed_path: str) -> int:
    if not os.path.isfile(seed_path):
        return 0

    try:
        with open(seed_path, "rb") as f:
            content = f.read()

        delimiter = b'\x1A\x1A\x1A\x1A'
        delimiter_count = content.count(delimiter)

        if len(content) == 0:
            return 0
        return delimiter_count + 1
    except Exception:
        return 0

def build_agg_from_extracted(extracted_root="extracted_crashes", verbose=False):
    agg = defaultdict(lambda: defaultdict(dict))

    def collect_trace_files(traces_dir):
        files = []
        if not os.path.isdir(traces_dir):
            return files
        for entry in sorted(os.listdir(traces_dir)):
            epath = os.path.join(traces_dir, entry)
            if os.path.isfile(epath):
                files.append(epath)
            elif os.path.isdir(epath):
                for subf in sorted(os.listdir(epath)):
                    subp = os.path.join(epath, subf)
                    if os.path.isfile(subp):
                        files.append(subp)
        return files

    def parse_suffixes(bname):
        tte = None
        taint = None
        if "$" in bname:
            try:
                suf = bname.rsplit("$", 1)[1]
                m = re.match(r"(\d+)", suf)
                if m:
                    tte = int(m.group(1))
            except Exception:
                tte = None
        if "&" in bname:
            try:
                suf = bname.rsplit("&", 1)[1]
                m = re.match(r"([0-9]*\.?[0-9]+)", suf)
                if m:
                    taint = float(m.group(1))
            except Exception:
                taint = None
        return tte, taint

    for entry in sorted(os.listdir(extracted_root)):
        entry_path = os.path.join(extracted_root, entry)
        if not os.path.isdir(entry_path):
            continue

        has_methods = any(method in os.listdir(entry_path) for method in DEFAULT_METHODS if os.path.isdir(os.path.join(entry_path, method)))

        firmware_entries = []
        if has_methods:
            firmware_entries.append((entry, entry_path))
        else:
            for fw in sorted(os.listdir(entry_path)):
                fw_path = os.path.join(entry_path, fw)
                if os.path.isdir(fw_path):
                    firmware_entries.append((os.path.join(entry, fw), fw_path))

        for firmware, fw_path in firmware_entries:
            for method in DEFAULT_METHODS:
                method_path = os.path.join(fw_path, method)
                if not os.path.isdir(method_path):
                    continue

                for exp in sorted(os.listdir(method_path)):
                    exp_path = os.path.join(method_path, exp)
                    if not os.path.isdir(exp_path):
                        continue

                    if not should_include_experiment(exp):
                        continue

                    traces_dir = os.path.join(exp_path, "crash_traces")
                    crashes_dir = os.path.join(exp_path, "crashes")
                    if not os.path.isdir(traces_dir):
                        continue

                    files = collect_trace_files(traces_dir)
                    if not files:
                        continue

                    per_exp_info = {}
                    for tf in files:
                        bname = os.path.basename(tf)
                        seed_name = bname.replace("_traces", "")
                        succ_file_path = os.path.join(crashes_dir, seed_name + ".succ")

                        if REQUIRE_SUCC_FLAG:
                            if not os.path.isfile(succ_file_path):
                                if verbose:
                                    print(f"[SKIP] No .succ file for {bname}, skipping (expected: {succ_file_path})")
                                continue
                            crash_seed_path = succ_file_path
                        else:
                            if os.path.isfile(succ_file_path):
                                crash_seed_path = succ_file_path
                            else:
                                fail_file_path = os.path.join(crashes_dir, seed_name + ".fail")
                                if os.path.isfile(fail_file_path):
                                    crash_seed_path = fail_file_path
                                else:
                                    regular_seed_path = os.path.join(crashes_dir, seed_name)
                                    if os.path.isfile(regular_seed_path):
                                        crash_seed_path = regular_seed_path
                                    else:
                                        crash_seed_path = None
                                        if verbose:
                                            print(f"[INFO] No seed file found for {bname}, including crash without seed path")

                        pc, module = _parse_first_frame_pc_module(tf)

                        if pc is None and module is None:
                            if verbose:
                                print(f"[SKIP] cannot parse first frame from {tf}")
                            continue

                        module_norm = (module or "(unknown_module)")
                        pc_norm = (pc or "(unknown_pc)")
                        raw_key = (firmware, module_norm, pc_norm)
                        tte_val, taint_val = parse_suffixes(bname)

                        prev = per_exp_info.get(raw_key)
                        if prev is None:
                            per_exp_info[raw_key] = {
                                "tte": tte_val,
                                "taints": ([taint_val] if taint_val is not None else []),
                                "crash_seed_path": crash_seed_path
                            }
                        else:
                            prev_tte = prev.get("tte")
                            if prev_tte is None:
                                prev["tte"] = tte_val
                            elif tte_val is not None:
                                prev["tte"] = min(prev_tte, tte_val)
                            if taint_val is not None:
                                prev["taints"].append(taint_val)
                            if "crash_seed_path" not in prev:
                                prev["crash_seed_path"] = crash_seed_path

                    for key, info in per_exp_info.items():
                        taints = info.get("taints", []) or []
                        taint_avg = None
                        if taints:
                            try:
                                taint_avg = int(sum(taints) / len(taints)) if all(float(t).is_integer() for t in taints) else (sum(taints) / len(taints))
                            except Exception:
                                taint_avg = sum(taints) / len(taints)
                        agg[key][method][exp] = {
                            "tte": info.get("tte"),
                            "taint": taint_avg,
                            "crash_seed_path": info.get("crash_seed_path")
                        }

    return agg


def write_csv_and_latex(headers, rows, csv_path, tex_path, caption="", count_tte_table=False, add_category_col=False, add_taint_col=False):
    def latex_escape(s):
        if s is None:
            return ""
        s = str(s)
        s = s.replace("\\", "\\textbackslash{}")
        s = s.replace("&", "\\&")
        s = s.replace("%", "\\%")
        s = s.replace("$", "\\$")
        s = s.replace("#", "\\#")
        s = s.replace("{", "\\{")
        s = s.replace("}", "\\}")
        s = s.replace("_", "\\_")
        return s

    for p in (csv_path, tex_path):
        d = os.path.dirname(p)
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                pass

    if not rows:
        df = pd.DataFrame(columns=headers)
        df.to_csv(csv_path, index=False, encoding="utf-8")
        print(f"[WRITE] CSV -> {csv_path} ; LaTeX -> {tex_path} (no rows)")
        with open(tex_path, "w", encoding="utf-8") as fh:
            fh.write("\\begin{table*}[ht]\n\\centering\n")
            fh.write("\\renewcommand{\\arraystretch}{1.06}\n")
            fh.write("\\setlength{\\tabcolsep}{4pt}\n")
            col_format = "|" + "|".join("l" for _ in headers) + "|"
            fh.write(f"\\begin{{tabular}}{{{col_format}}}\n\\hline\n")
            fh.write(" & ".join("{\sc " + latex_escape(h) + "}" for h in headers) + " \\\\\n\\hline\n")
            fh.write("\\end{tabular}\n")
            if caption:
                fh.write(f"\\caption{{{latex_escape(caption)}}}\n")
            fh.write("\\end{table*}\n")
        return

    df = pd.DataFrame(rows)
    for h in headers:
        if h not in df.columns:
            df[h] = None
    df = df[headers]
    df.to_csv(csv_path, index=False, encoding="utf-8")

    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write("\\begin{table*}[ht]\n\\centering\n")
        fh.write("\\renewcommand{\\arraystretch}{1.06}\n")
        fh.write("\\setlength{\\tabcolsep}{4pt}\n")

        if not count_tte_table:
            ncols = len(headers)
            if ncols <= 1:
                col_format = "|" + "|".join("l" for _ in range(ncols)) + "|"
            else:
                col_format = "|l||" + "|".join("c" for _ in range(ncols - 1)) + "|"
        else:
            left_prefix = "|l||c|c|"
            if add_category_col:
                left_prefix = "|l||c|c|c|"
            method_part = "".join(
                "c|c|c|" if (add_taint_col and ("staff" in m)) else "c|c|" 
                for m in DEFAULT_METHODS
            )
            col_format = left_prefix + method_part
            if not col_format.startswith("|"):
                col_format = "|" + col_format
            if not col_format.endswith("|"):
                col_format += "|"

        if not col_format.endswith("|"):
            col_format += "|"

        fh.write(f"\\begin{{tabular}}{{{col_format}}}\n")
        fh.write("\\hline\n")

        if count_tte_table:
            first_row = ["{\sc Firmware}", "{\sc Binary}", "{\sc Function}"]
            if add_category_col:
                first_row.append("{\sc Category}")
            for m in DEFAULT_METHODS:
                abbr = METHOD_ABBR.get(m, m)
                if add_taint_col and "staff" in m:
                    first_row.append(f"\\multicolumn{{3}}{{c|}}{{\sc {{{latex_escape(m)}}}}}")
                else:
                    first_row.append(f"\\multicolumn{{2}}{{c|}}{{\sc {{{latex_escape(m)}}}}}")
            fh.write(" & ".join(first_row) + " \\\\\n")

            second_row = ["", "", ""]
            if add_category_col:
                second_row.append("")
            for m in DEFAULT_METHODS:
                second_row.append("{\sc cnt}")
                second_row.append("{\sc TTE}")
                if add_taint_col and "staff" in m:
                    second_row.append("{\sc taint}")
            fh.write(" & ".join(second_row) + " \\\\\n")
            fh.write("\\hline\n")

            grouped = defaultdict(lambda: defaultdict(list))
            for row in rows:
                fw = row.get("firmware", "")
                module = row.get("module", "")
                grouped[fw][module].append(row)

            total_cols = 3 + (1 if add_category_col else 0) + 2 * len(DEFAULT_METHODS) + (1 if add_taint_col else 0) 
            cline_rest_start = 2
            cline_rest_start_func = 3
            cline_rest_end = total_cols

            fw_items = list(grouped.items())
            for fw_idx, (fw, modules) in enumerate(fw_items):
                module_items = list(modules.items())
                fw_rows = sum(len(funcs) for _, funcs in module_items)
                first_fw_row = True

                for mod_idx, (module, funcs) in enumerate(module_items):
                    mod_rows = len(funcs)
                    first_mod_row = True

                    for fi, row in enumerate(funcs):
                        cells = []
                        # firmware cell (multirow)
                        if first_fw_row:
                            cells.append(f"\\multirow{{{fw_rows}}}{{*}}{{{latex_escape(fw)}}}")
                            first_fw_row = False
                        else:
                            cells.append("")

                        if first_mod_row:
                            module = "\\texttt{"+latex_escape(module)+"}"
                            cells.append(f"\\multirow{{{mod_rows}}}{{*}}{{{module}}}")
                            first_mod_row = False
                        else:
                            cells.append("")

                        cells.append("\\texttt{"+latex_escape(row.get("function", ""))+"}")
                        if add_category_col:
                            cells.append(latex_escape(row.get("category", "")))

                        for m in DEFAULT_METHODS:
                            abbr = METHOD_ABBR.get(m, m)
                            cnt_val = row.get(f"{abbr}_cnt", "")
                            tte_val = row.get(f"{abbr}_avg_tte", "")
                            cells.append("" if cnt_val is None else str(cnt_val))
                            cells.append("" if tte_val is None else str(tte_val))
                            if add_taint_col and "staff" in m:
                                cells.append(str(row.get(f"{abbr}_avg_taint", "")))

                        fh.write(" & ".join(cells) + " \\\\\n")

                        fh.write(f"\\cline{{{cline_rest_start_func}-{cline_rest_end}}}\n")

                    fh.write(f"\\cline{{{cline_rest_start}-{cline_rest_end}}}\n")

                fh.write("\\cline{1-1}\n")

            fh.write("\\hline\n")

        else:
            fh.write(" & ".join("{\sc " + latex_escape(h) + "}" for h in headers) + " \\\\\n")
            fh.write("\\toprule\n")
            fh.write("\\hline\n")
            for row in rows:
                values = [latex_escape(row.get(h, "")) for h in headers]
                fh.write(" & ".join(values) + " \\\\\n")
                fh.write("\\hline\n")

        fh.write("\\end{tabular}\n")
        if caption:
            fh.write(f"\\caption{{{latex_escape(caption)}}}\n")
        fh.write("\\end{table*}\n")

    print(f"[WRITE] CSV -> {csv_path} ; LaTeX -> {tex_path}")


def build_crash_level_tables(
        extracted_root="extracted_crashes",
        out_count_csv=None, out_count_tex=None,
        out_tte_csv=None, out_tte_tex=None,
        out_causality_csv=None, out_causality_tex=None,
        firmwares_csv="analysis/fw_names.csv",
        verbose=True,
        show_exp_count=False,
        experiments_dir=None,
        include_zero_crashes=False):

    if out_count_csv is None:
        out_count_csv = os.path.join(OUTPUT_DIR, "out_count_crashes.csv")
    if out_count_tex is None:
        out_count_tex = os.path.join(OUTPUT_DIR, "out_count_crashes.tex")
    if out_tte_csv is None:
        out_tte_csv = os.path.join(OUTPUT_DIR, "out_tte_crashes.csv")
    if out_tte_tex is None:
        out_tte_tex = os.path.join(OUTPUT_DIR, "out_tte_crashes.tex")
    if out_causality_csv is None:
        out_causality_csv = os.path.join(OUTPUT_DIR, "out_causality_crashes.csv")
    if out_causality_tex is None:
        out_causality_tex = os.path.join(OUTPUT_DIR, "out_causality_crashes.tex")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    def load_firmware_map_triplet(path):
        mapping = {}
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fw_file = row["firmware"].strip()
                brand = row.get("brand", "").strip()
                name = row.get("name", "").strip()
                version = row.get("version", "").strip()
                mapping[fw_file] = (brand, name, version)
        return mapping

    fw_map = load_firmware_map_triplet(firmwares_csv)

    total_experiments = defaultdict(lambda: defaultdict(int))
    all_firmwares_from_experiments = set()
    if (show_exp_count or include_zero_crashes) and experiments_dir and os.path.isdir(experiments_dir):
        import configparser
        for sub_exp in sorted(os.listdir(experiments_dir)):
            sub_path = os.path.join(experiments_dir, sub_exp)
            if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
                continue

            if not should_include_experiment(sub_exp):
                continue

            config_path = os.path.join(sub_path, "outputs", "config.ini")
            if not os.path.isfile(config_path):
                continue

            config = configparser.ConfigParser()
            try:
                config.read(config_path)
                mode = config.get("GENERAL", "mode")
                firmware_path = config.get("GENERAL", "firmware")
                if os.path.dirname(firmware_path):
                    firmware_with_brand = firmware_path
                else:
                    firmware_with_brand = os.path.basename(firmware_path)
                total_experiments[firmware_with_brand][mode] += 1
                all_firmwares_from_experiments.add(firmware_with_brand)
            except Exception:
                continue

    agg_raw = build_agg_from_extracted(extracted_root=extracted_root, verbose=verbose)

    def pc_to_int(pc_str):
        if pc_str is None:
            return None
        s = str(pc_str).strip()
        try:
            return int(s, 0)
        except:
            m = re.search(r"(0x[0-9a-fA-F]+)", s)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"(\d+)", s)
            if m2:
                return int(m2.group(1), 10)
        return None

    def map_key_by_range_and_groups(fw, module, pc_str):
        raw = (fw, module, pc_str, None, None)
        pc_int = pc_to_int(pc_str)
        for fw_key, modmap in PC_RANGES.items():
            if fw_key.lower() != fw.lower() and fw_key not in fw and fw not in fw_key:
                continue
            ranges = modmap.get(module) or modmap.get(module.lower())
            if not ranges:
                continue
            if pc_int is None:
                pc_int = pc_to_int(pc_str)
                if pc_int is None:
                    continue
            for fun_name, tpl in ranges.items():
                if len(tpl) == 5:
                    start, end, category, cve_id, bug_id = tpl
                elif len(tpl) == 4:
                    start, end, category, cve_id = tpl
                    bug_id = None
                elif len(tpl) == 3:
                    start, end, category = tpl
                    cve_id = None
                    bug_id = None
                else:
                    start, end = tpl
                    category = None
                    cve_id = None
                    bug_id = None
                try:
                    s = int(start)
                    e = int(end)
                except:
                    continue
                if s <= pc_int <= e:
                    return (fw, module, fun_name, category, cve_id)
        return raw

    def should_skip(fw, method, module):
        fw_name_only = os.path.basename(fw)
        return (fw_name_only, method, module) in SKIP_MODULES or (fw_name_only, "any", module) in SKIP_MODULES or ("any", method, "any") in SKIP_MODULES

    agg = defaultdict(lambda: defaultdict(dict))
    for (fw, module, pc_key), method_dict in agg_raw.items():
        mapped_key = map_key_by_range_and_groups(fw, module, pc_key)
        for method_name, exp_map in method_dict.items():
            if should_skip(fw, method_name, module):
                continue
            for exp, d in exp_map.items():
                tte = d["tte"]
                taint = d["taint"]
                crash_seed_path = d.get("crash_seed_path")
                prev = agg[mapped_key][method_name].get(exp)
                if prev is None:
                    agg[mapped_key][method_name][exp] = {"tte": tte, "taint": taint, "crash_seed_path": crash_seed_path}
                elif prev is not None and tte is not None:
                    if (tte < prev["tte"]):
                        agg[mapped_key][method_name][exp] = {"tte": tte, "taint": taint, "crash_seed_path": crash_seed_path}

    # ---------- Table1: Number of crashes ----------
    csv_firmware_order = get_firmware_order_from_csv(firmwares_csv.replace("fw_names.csv", "crashes.csv"))
    firmware_set_unsorted = {k[0] for k in agg.keys()}

    if include_zero_crashes and all_firmwares_from_experiments:
        firmware_set_unsorted = firmware_set_unsorted | all_firmwares_from_experiments

    firmware_set = []
    for fw in csv_firmware_order:
        if fw in firmware_set_unsorted:
            firmware_set.append(fw)
    
    for fw in sorted(firmware_set_unsorted - set(firmware_set)):
        firmware_set.append(fw)

    table1_rows = []

    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        for m in DEFAULT_METHODS:
            per_run_crashes = defaultdict(set)
            for key, method_dict in agg.items():
                if len(key) == 5:
                    f, module, pc, category, cve_id = key
                elif len(key) == 4:
                    f, module, pc, category = key
                else:
                    f, module, pc = key

                if f != fw:
                    continue

                for exp, data in method_dict.get(m, {}).items():
                    if data is not None and data.get("tte") is not None:
                        per_run_crashes[exp].add(key)

            mean_crashes = (
                sum(len(s) for s in per_run_crashes.values()) / len(per_run_crashes)
                if per_run_crashes else 0.0
            )
            col_name = f"{METHOD_ABBR.get(m, m)}_mean_cnt"
            row[col_name] = round(mean_crashes, 3)

            if show_exp_count:
                exp_count_col = f"{METHOD_ABBR.get(m, m)}_exp_cnt"
                if total_experiments:
                    row[exp_count_col] = total_experiments.get(fw, {}).get(m, 0)
                else:
                    row[exp_count_col] = len(per_run_crashes)

        table1_rows.append(row)

    headers1 = ["firmware"]
    for m in DEFAULT_METHODS:
        headers1.append(f"{METHOD_ABBR.get(m, m)}_mean_cnt")
        if show_exp_count:
            headers1.append(f"{METHOD_ABBR.get(m, m)}_exp_cnt")

    write_csv_and_latex(headers1, table1_rows, out_count_csv, out_count_tex, caption="Number of crashes")

    # ---------- Table2 (TTE) ----------
    fw_order_map = {fw: idx for idx, fw in enumerate(csv_firmware_order)}
    def crash_sort_key(item):
        key = item[0]
        fw = key[0]
        fw_idx = fw_order_map.get(fw, 999999)
        return (fw_idx, key[1], str(key[2]))

    table2_rows = []

    for key, method_dict in sorted(agg.items(), key=crash_sort_key):
        if len(key) == 5:
            fw, module, func_or_pc, category, cve_id = key
        elif len(key) == 4:
            fw, module, func_or_pc, category = key
            cve_id = None
        else:
            fw, module, func_or_pc = key
            category = None
            cve_id = None

        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {
            "firmware": name,
            "module": module,
            "function": func_or_pc,
            "category": category or "",
            "cve_id": cve_id or "",
        }

        all_crash_seed_paths = []
        for m in DEFAULT_METHODS:
            entries = method_dict.get(m, {})
            cnt = len(entries)
            row[f"{METHOD_ABBR.get(m, m)}_cnt"] = cnt
            ttes = [v.get("tte") for v in entries.values() if v and v.get("tte") is not None]
            taints = [v.get("taint") for v in entries.values() if v and v.get("taint") is not None]
            crash_paths = [v.get("crash_seed_path") for v in entries.values() if v and v.get("crash_seed_path")]
            all_crash_seed_paths.extend(crash_paths)
            if verbose and crash_paths:
                print(f"[DEBUG] Found {len(crash_paths)} crash paths for {fw}/{module}/{func_or_pc} in method {m}")

            avg_tte = (sum(ttes) / len(ttes)) if ttes else None
            avg_taint = (sum(taints) / len(taints)) if taints else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""
            row[f"{METHOD_ABBR.get(m, m)}_avg_taint"] = (round(avg_taint, 3) if avg_taint is not None else "")

        num_requests = 0
        succ_paths = [p for p in all_crash_seed_paths if p and p.endswith(".succ")]

        if succ_paths:
            num_requests = count_requests_in_seed(succ_paths[0])
        row["num_requests"] = num_requests if num_requests > 0 else ""

        table2_rows.append(row)

    headers2 = ["firmware", "module", "function", "category", "cve_id", "num_requests"]
    for m in DEFAULT_METHODS:
        headers2.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers2.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")

    write_csv_and_latex(headers2, table2_rows, out_tte_csv, out_tte_tex, caption="TTE crashes", count_tte_table=True, add_category_col=True, add_taint_col=True)

    # ---------- CVE/CWE Summary Table ----------
    crashes_csv_path = "analysis/crashes.csv"
    cve_cwe_lookup = {}
    if os.path.isfile(crashes_csv_path):
        try:
            with open(crashes_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    csv_fw = row.get('firmware', '').strip()
                    csv_mod = row.get('module', '').strip()
                    csv_func = row.get('function_name', '').strip()
                    
                    if csv_func.startswith('(') and csv_func.endswith(')'):
                        csv_func = csv_func[1:-1].strip()

                    csv_cve = row.get('cve', '').strip()
                    csv_cwe = row.get('cwe', '').strip()

                    key = (csv_fw.lower(), csv_mod.lower(), csv_func.lower())
                    cve_cwe_lookup[key] = {
                        'cve': csv_cve if csv_cve and csv_cve != '???' else '',
                        'cwe': csv_cwe if csv_cwe and csv_cwe != '???' else ''
                    }
        except Exception as e:
            if verbose:
                print(f"[WARN] Could not read crashes.csv: {e}")

    cve_cwe_rows = []
    for key, method_dict in sorted(agg.items(), key=crash_sort_key):
        if len(key) == 5:
            fw, module, func_or_pc, category, cve_id = key
        elif len(key) == 4:
            fw, module, func_or_pc, category = key
            cve_id = None
        else:
            fw, module, func_or_pc = key
            category = None
            cve_id = None

        fw_display = fw
        fw_name_only = os.path.basename(fw)
        if fw_name_only in fw_map:
            brand, name, version = fw_map[fw_name_only]
            fw_display = name if name else fw

        cve_value = cve_id if cve_id and cve_id != '???' else ''
        cwe_value = ''

        for (lookup_fw, lookup_mod, lookup_func), info in cve_cwe_lookup.items():
            fw_match = (lookup_fw in fw.lower() or fw.lower() in lookup_fw)
            mod_match = (lookup_mod == module.lower())
            func_match = (lookup_func == func_or_pc.lower())

            if fw_match and mod_match and func_match:
                if not cve_value and info['cve']:
                    cve_value = info['cve']
                if info['cwe']:
                    cwe_value = info['cwe']
                break

        row = {
            "firmware": fw_display,
            "module": module,
            "function": func_or_pc,
            "CVE": cve_value,
            "CWE": cwe_value
        }
        cve_cwe_rows.append(row)

    cve_cwe_csv = os.path.join(OUTPUT_DIR, "out_cve_cwe_summary.csv")
    cve_cwe_tex = os.path.join(OUTPUT_DIR, "out_cve_cwe_summary.tex")
    cve_cwe_headers = ["firmware", "module", "function", "CVE", "CWE"]
    write_csv_and_latex(cve_cwe_headers, cve_cwe_rows, cve_cwe_csv, cve_cwe_tex, caption="CVE and CWE Summary")

    # ---------- Table3 (Causality) ----------

    staff_method = "staff_state_aware"

    crash_causality = {}

    for key, method_dict in agg.items():
        if len(key) == 5:
            fw, module, func_or_pc, category, cve_id = key
        elif len(key) == 4:
            fw, module, func_or_pc, category = key
        else:
            fw, module, func_or_pc = key
            category = None

        if not category:
            category = "Unknown"

        if staff_method not in method_dict:
            continue

        entries = method_dict[staff_method]
        if not entries:
            continue

        causality_scores = []
        for exp, data in entries.items():
            taint = data.get("taint")
            if taint is not None and taint > 0:
                causality_scores.append(1.0)
            else:
                causality_scores.append(0.0)

        if causality_scores:
            avg_causality = sum(causality_scores) / len(causality_scores)
            crash_key = (fw, module, func_or_pc, category)
            crash_causality[crash_key] = avg_causality

    category_stats = defaultdict(lambda: {"crashes": [], "causality_scores": [], "full_causality_count": 0})

    for (fw, module, func_or_pc, category), causality in crash_causality.items():
        category_stats[category]["crashes"].append((fw, module, func_or_pc))
        category_stats[category]["causality_scores"].append(causality)

        if causality == 1.0:
            category_stats[category]["full_causality_count"] += 1

    table3_rows = []
    total_crashes = 0
    total_full_causality = 0
    all_causality_scores = []

    for category in ordered_categories(category_stats.keys()):
        stats = category_stats[category]
        num_crashes = len(stats["crashes"])
        avg_causality = sum(stats["causality_scores"]) / len(stats["causality_scores"]) if stats["causality_scores"] else 0.0
        full_causality_count = stats["full_causality_count"]

        table3_rows.append({
            "category": category,
            "num_crashes": num_crashes,
            "full_causality_crashes": full_causality_count,
            "causality_score": round(avg_causality, 2)
        })

        total_crashes += num_crashes
        all_causality_scores.extend(stats["causality_scores"])
        total_full_causality += full_causality_count

    if total_crashes > 0:
        overall_causality = sum(all_causality_scores) / len(all_causality_scores) if all_causality_scores else 0.0
        table3_rows.append({
            "category": "ALL",
            "num_crashes": total_crashes,
            "full_causality_crashes": total_full_causality,
            "causality_score": round(overall_causality, 2)
        })

    headers3 = ["category", "num_crashes", "full_causality_crashes", "causality_score"]
    write_csv_and_latex(headers3, table3_rows, out_causality_csv, out_causality_tex, caption="Causality of crashes")

    # Write detailed crash causality scores
    detailed_causality_rows = []
    for (fw, module, func_or_pc, category), causality in sorted(crash_causality.items()):
        detailed_causality_rows.append({
            "firmware": fw,
            "module": module,
            "function": func_or_pc,
            "category": category,
            "causality_score": round(causality, 3)
        })

    if detailed_causality_rows:
        detailed_csv = out_causality_csv.replace(".csv", "_detailed.csv")
        with open(detailed_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["firmware", "module", "function", "category", "causality_score"])
            writer.writeheader()
            writer.writerows(detailed_causality_rows)
        if verbose:
            print(f"[INFO] Wrote detailed crash causality to: {detailed_csv}")

    return (table1_rows, table2_rows, table3_rows), agg

def build_bug_level_tables(
        extracted_root="extracted_crashes",
        agg_raw=None,
        out_count_csv=None, out_count_tex=None,
        out_tte_csv=None, out_tte_tex=None,
        out_causality_csv=None, out_causality_tex=None,
        firmwares_csv="analysis/fw_names.csv",
        verbose=True,
        show_exp_count=False,
        experiments_dir=None,
        include_zero_bugs=False):

    if out_count_csv is None:
        out_count_csv = os.path.join(OUTPUT_DIR, "out_count_bugs.csv")
    if out_count_tex is None:
        out_count_tex = os.path.join(OUTPUT_DIR, "out_count_bugs.tex")
    if out_tte_csv is None:
        out_tte_csv = os.path.join(OUTPUT_DIR, "out_tte_bugs.csv")
    if out_tte_tex is None:
        out_tte_tex = os.path.join(OUTPUT_DIR, "out_tte_bugs.tex")
    if out_causality_csv is None:
        out_causality_csv = os.path.join(OUTPUT_DIR, "out_causality_bugs.csv")
    if out_causality_tex is None:
        out_causality_tex = os.path.join(OUTPUT_DIR, "out_causality_bugs.tex")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    def load_firmware_map_triplet(path):
        mapping = {}
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fw_file = row["firmware"].strip()
                brand = row.get("brand", "").strip()
                name = row.get("name", "").strip()
                version = row.get("version", "").strip()
                mapping[fw_file] = (brand, name, version)
        return mapping

    fw_map = load_firmware_map_triplet(firmwares_csv)

    total_experiments = defaultdict(lambda: defaultdict(int))
    all_firmwares_from_experiments = set()
    if (show_exp_count or include_zero_bugs) and experiments_dir and os.path.isdir(experiments_dir):
        for sub_exp in sorted(os.listdir(experiments_dir)):
            sub_path = os.path.join(experiments_dir, sub_exp)
            if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
                continue
            if not should_include_experiment(sub_exp):
                continue

            config_path = os.path.join(sub_path, "outputs", "config.ini")
            if not os.path.isfile(config_path):
                continue

            cfg = configparser.ConfigParser()
            try:
                cfg.read(config_path)
                mode = cfg.get("GENERAL", "mode")
                firmware_path = cfg.get("GENERAL", "firmware")
                if os.path.dirname(firmware_path):
                    firmware_with_brand = firmware_path
                else:
                    firmware_with_brand = os.path.basename(firmware_path)
                total_experiments[firmware_with_brand][mode] += 1
                all_firmwares_from_experiments.add(firmware_with_brand)
            except Exception:
                continue

    if agg_raw is None:
        agg_raw = build_agg_from_extracted(extracted_root=extracted_root, verbose=verbose)

    def pc_to_int(pc_str):
        if pc_str is None:
            return None
        s = str(pc_str).strip()
        try:
            return int(s, 0)
        except Exception:
            m = re.search(r"(0x[0-9a-fA-F]+)", s)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"(\d+)", s)
            if m2:
                return int(m2.group(1), 10)
        return None

    def map_key_by_range_and_groups(fw, module, pc_str):
        raw = (fw, module, pc_str, None, None, None)
        pc_int = pc_to_int(pc_str)

        for fw_key, modmap in PC_RANGES.items():
            if fw_key.lower() != fw.lower() and fw_key not in fw and fw not in fw_key:
                continue
            ranges = modmap.get(module) or modmap.get(module.lower())
            if not ranges:
                continue
            if pc_int is None:
                continue
            for fun_name, tpl in ranges.items():
                if len(tpl) == 5:
                    start, end, category, cve_id, bug_id = tpl
                elif len(tpl) == 4:
                    start, end, category, cve_id = tpl
                    bug_id = None
                elif len(tpl) == 3:
                    start, end, category = tpl
                    cve_id = None
                    bug_id = None
                else:
                    start, end = tpl
                    category = None
                    cve_id = None
                    bug_id = None

                try:
                    s = int(start)
                    e = int(end)
                except Exception:
                    continue

                if s <= pc_int <= e:
                    return (fw, module, fun_name, category, cve_id, bug_id)

        return raw

    def should_skip(fw, method, module):
        fw_name_only = os.path.basename(fw)
        return ((fw_name_only, method, module) in SKIP_MODULES or
                (fw_name_only, "any", module) in SKIP_MODULES or
                ("any", method, "any") in SKIP_MODULES)

    agg_mapped = defaultdict(lambda: defaultdict(dict))
    for (fw, module, pc_key), method_dict in agg_raw.items():
        mapped_key = map_key_by_range_and_groups(fw, module, pc_key)  # 6-tuple
        for method_name, exp_map in method_dict.items():
            if should_skip(fw, method_name, module):
                continue
            for exp, d in exp_map.items():
                tte = d.get("tte")
                taint = d.get("taint")
                crash_seed_path = d.get("crash_seed_path")

                prev = agg_mapped[mapped_key][method_name].get(exp)
                if prev is None:
                    agg_mapped[mapped_key][method_name][exp] = {
                        "tte": tte, "taint": taint, "crash_seed_path": crash_seed_path
                    }
                elif tte is not None and (prev.get("tte") is None or tte < prev["tte"]):
                    agg_mapped[mapped_key][method_name][exp] = {
                        "tte": tte, "taint": taint, "crash_seed_path": crash_seed_path
                    }

    bug_agg = defaultdict(lambda: defaultdict(dict))
    bug_sites = defaultdict(set)

    for key, method_dict in agg_mapped.items():
        fw, module, func_or_pc, category, cve_id, bug_id = (key + (None,) * 6)[:6]

        if not bug_id:
            bug_id = f"Unknown-{os.path.basename(fw)}"

        bug_key = (fw, bug_id, category, cve_id)
        bug_sites[bug_key].add((module, func_or_pc))

        for method, exp_map in method_dict.items():
            for exp, data in exp_map.items():
                prev = bug_agg[bug_key][method].get(exp)
                if prev is None:
                    bug_agg[bug_key][method][exp] = {
                        "min_tte": data.get("tte"),
                        "taints": ([data["taint"]] if data.get("taint") is not None else []),
                        "sites": { (module, func_or_pc) },
                    }
                else:
                    tte = data.get("tte")
                    if tte is not None:
                        if prev["min_tte"] is None:
                            prev["min_tte"] = tte
                        else:
                            prev["min_tte"] = min(prev["min_tte"], tte)

                    if data.get("taint") is not None:
                        prev["taints"].append(data["taint"])

                    prev["sites"].add((module, func_or_pc))

    # ---------- Table1-bug: mean #bugs ----------
    csv_firmware_order = get_firmware_order_from_csv(firmwares_csv.replace("fw_names.csv", "crashes.csv"))
    firmware_set_unsorted = {k[0] for k in bug_agg.keys()}

    if include_zero_bugs and all_firmwares_from_experiments:
        firmware_set_unsorted = firmware_set_unsorted | all_firmwares_from_experiments

    firmware_set = []
    for fw in csv_firmware_order:
        if fw in firmware_set_unsorted:
            firmware_set.append(fw)
    for fw in sorted(firmware_set_unsorted - set(firmware_set)):
        firmware_set.append(fw)

    table1_rows = []
    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        for m in DEFAULT_METHODS:
            per_run_bugs = defaultdict(set)
            for (f, bug_id, category, cve_id), method_dict in bug_agg.items():
                if f != fw:
                    continue
                for exp, data in method_dict.get(m, {}).items():
                    if data is not None and (data.get("sites") or data.get("min_tte") is not None):
                        per_run_bugs[exp].add(bug_id)

            mean_bugs = (
                sum(len(s) for s in per_run_bugs.values()) / len(per_run_bugs)
                if per_run_bugs else 0.0
            )
            row[f"{METHOD_ABBR.get(m, m)}_mean_cnt"] = round(mean_bugs, 3)

            if show_exp_count:
                exp_count_col = f"{METHOD_ABBR.get(m, m)}_exp_cnt"
                if total_experiments:
                    row[exp_count_col] = total_experiments.get(fw, {}).get(m, 0)
                else:
                    row[exp_count_col] = len(per_run_bugs)

        table1_rows.append(row)

    headers1 = ["firmware"]
    for m in DEFAULT_METHODS:
        headers1.append(f"{METHOD_ABBR.get(m, m)}_mean_cnt")
        if show_exp_count:
            headers1.append(f"{METHOD_ABBR.get(m, m)}_exp_cnt")

    write_csv_and_latex(headers1, table1_rows, out_count_csv, out_count_tex, caption="Number of bugs")

    # ---------- Table2-bug (TTE): one row per bug ----------
    fw_order_map = {fw: idx for idx, fw in enumerate(csv_firmware_order)}
    def bug_sort_key(item):
        fw = item[0][0]
        bug_id = item[0][1]
        fw_idx = fw_order_map.get(fw, 999999)
        return (fw_idx, str(bug_id))

    table2_rows = []
    for (fw, bug_id, category, cve_id), method_dict in sorted(bug_agg.items(), key=bug_sort_key):
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        out_cve = (cve_id or "").strip()
        if not out_cve:
            out_cve = str(bug_id).strip()

        row = {
            "firmware": name,
            "category": category or "",
            "cve_id": out_cve,
            "num_sites": len(bug_sites[(fw, bug_id, category, cve_id)]),
        }

        for m in DEFAULT_METHODS:
            entries = method_dict.get(m, {})
            row[f"{METHOD_ABBR.get(m, m)}_cnt"] = len(entries)

            ttes = [v.get("min_tte") for v in entries.values() if v and v.get("min_tte") is not None]
            avg_tte = (sum(ttes) / len(ttes)) if ttes else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""

            all_taints = []
            for v in entries.values():
                if v and v.get("taints"):
                    all_taints.extend([t for t in v["taints"] if t is not None])
            avg_taint = (sum(all_taints) / len(all_taints)) if all_taints else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_taint"] = (round(avg_taint, 3) if avg_taint is not None else "")

        table2_rows.append(row)

    headers2 = ["firmware", "category", "cve_id", "num_sites"]
    for m in DEFAULT_METHODS:
        headers2.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers2.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")
        headers2.append(f"{METHOD_ABBR.get(m, m)}_avg_taint")

    write_csv_and_latex(headers2, table2_rows, out_tte_csv, out_tte_tex,
                        caption="TTE bugs", count_tte_table=False)

    staff_method = "staff_state_aware"
    bug_causality = {}

    for (fw, bug_id, category, cve_id), method_dict in bug_agg.items():
        cat = category or "Unknown"
        if staff_method not in method_dict:
            continue
        entries = method_dict[staff_method]
        if not entries:
            continue

        scores = []
        for exp, data in entries.items():
            taints = data.get("taints") or []
            scores.append(1.0 if any((t is not None and t > 0) for t in taints) else 0.0)

        if scores:
            bug_causality[(fw, bug_id, cat)] = sum(scores) / len(scores)

    category_stats = defaultdict(lambda: {"bugs": [], "scores": [], "full": 0})
    for (fw, bug_id, cat), sc in bug_causality.items():
        category_stats[cat]["bugs"].append((fw, bug_id))
        category_stats[cat]["scores"].append(sc)
        if sc == 1.0:
            category_stats[cat]["full"] += 1

    table3_rows = []
    total_bugs = 0
    total_full = 0
    all_bug_scores = []

    for cat in sorted(category_stats.keys()):
        num = len(category_stats[cat]["bugs"])
        avg_sc = (sum(category_stats[cat]["scores"]) / len(category_stats[cat]["scores"])) if category_stats[cat]["scores"] else 0.0
        full = category_stats[cat]["full"]
        table3_rows.append({
            "category": cat,
            "num_bugs": num,
            "full_causality_bugs": full,
            "causality_score": round(avg_sc, 2),
        })
        total_bugs += num
        all_bug_scores.extend(category_stats[cat]["scores"])
        total_full += full

    if total_bugs > 0:
        overall_bug_causality = sum(all_bug_scores) / len(all_bug_scores) if all_bug_scores else 0.0
        table3_rows.append({
            "category": "ALL",
            "num_bugs": total_bugs,
            "full_causality_bugs": total_full,
            "causality_score": round(overall_bug_causality, 2),
        })

    headers3 = ["category", "num_bugs", "full_causality_bugs", "causality_score"]
    write_csv_and_latex(headers3, table3_rows, out_causality_csv, out_causality_tex, caption="Causality of bugs")

    # Write detailed bug causality scores
    detailed_bug_causality_rows = []
    for (fw, bug_id, cat), sc in sorted(bug_causality.items()):
        detailed_bug_causality_rows.append({
            "firmware": fw,
            "bug_id": bug_id,
            "category": cat,
            "causality_score": round(sc, 3)
        })

    if detailed_bug_causality_rows:
        detailed_csv = out_causality_csv.replace(".csv", "_detailed.csv")
        with open(detailed_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["firmware", "bug_id", "category", "causality_score"])
            writer.writeheader()
            writer.writerows(detailed_bug_causality_rows)
        if verbose:
            print(f"[INFO] Wrote detailed bug causality to: {detailed_csv}")

    return (table1_rows, table2_rows, table3_rows), bug_agg



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Copy crashes from experiments_dir to extracted_root, then annotate files with $<tte> based on plot_data/fuzzer_stats."
    )
    parser.add_argument("experiments_dir", help="Path to directory containing exp_* directories.")
    parser.add_argument("--extracted_root", default="extracted_crashes",
                        help="Destination root to update/annotate.")
    parser.add_argument("--update", action="store_true",
                        help="Do not copy crashes into extracted_root; operate only on existing extracted_root.")
    parser.add_argument("--annotate", action="store_true",
                        help="Do not run TTE annotation after copying.")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity.")
    parser.add_argument("--crashes-csv", default="crashes.csv",
                        help="CSV file containing PC ranges / function mapping (default: crashes.csv)")
    parser.add_argument("--pc-ranges-py", default="pc_ranges_generated.py",
                        help="Output Python file to write PC_RANGES literal to (default: pc_ranges_generated.py)")
    parser.add_argument("--show-exp-count", action="store_true",
                        help="Add columns showing the number of experiments per (firmware, tool) pair in Table 1")
    parser.add_argument("--include-zero-crashes", action="store_true",
                        help="Include (firmware, tool) pairs in Table 1 even when no crashes were found")
    parser.add_argument("--max-exp", type=int, default=None,
                        help="Maximum experiment number to consider (e.g., --max-exp 5 only considers exp_1 through exp_5)")
    parser.add_argument("--include-not-succ", action="store_true",
                        help="Include seeds without .succ flag (default: only include .succ seeds)")
    parser.add_argument("--extract-unique", metavar="OUTPUT_DIR",
                        help="Extract one representative crash seed per firmware/module/function to OUTPUT_DIR")

    args = parser.parse_args()
    verbose = not args.quiet

    MAX_EXP_NUM = args.max_exp
    if MAX_EXP_NUM is not None and verbose:
        print(f"[INFO] Filtering experiments: only considering exp_1 through exp_{MAX_EXP_NUM}")

    REQUIRE_SUCC_FLAG = not args.include_not_succ
    if not REQUIRE_SUCC_FLAG and verbose:
        print(f"[INFO] Including seeds without .succ flag")

    try:
        PC_RANGES = load_pc_ranges_from_csv(args.crashes_csv, output_py=args.pc_ranges_py, verbose=verbose)
    except Exception as e:
        print(f"[ERROR] cannot load PC ranges from '{args.crashes_csv}': {e}")
        raise SystemExit(1)

    print("Loaded PC_RANGES (top-level keys):", list(PC_RANGES.keys()))

    if verbose:
        import pprint
        pprint.pprint(PC_RANGES)

    unify_crash_and_trace_filenames()

    if args.update:
        update_extracted_root_from_experiments(args.experiments_dir, extracted_root=args.extracted_root, verbose=verbose)
        count_and_log_crash_seeds(extracted_root=args.extracted_root, verbose=verbose)
    else:
        if verbose:
            print("[INFO] skipping copy step")

    if args.annotate:
        annotate_extracted_with_tte(args.experiments_dir, extracted_root=args.extracted_root, verbose=verbose)
    else:
        if verbose:
            print("[INFO] skipping annotation step")

    tables, agg = build_crash_level_tables(
        extracted_root=args.extracted_root,
        verbose=True,
        show_exp_count=args.show_exp_count,
        experiments_dir=args.experiments_dir,
        include_zero_crashes=args.include_zero_crashes
    )

    bug_tables, bug_agg = build_bug_level_tables(
        extracted_root=args.extracted_root,
        firmwares_csv="analysis/fw_names.csv",
        verbose=True,
        show_exp_count=args.show_exp_count,
        experiments_dir=args.experiments_dir,
        include_zero_bugs=args.include_zero_crashes,
    )

    chmod_recursive(args.extracted_root, 0o777)

    if args.extract_unique:
        extract_unique_crashes_per_function(
            extracted_root=args.extracted_root,
            output_dir=args.extract_unique,
            verbose=verbose
        )

    chmod_recursive(args.extract_unique, 0o777)

    # print_seed_status_statistics(extracted_root=args.extracted_root, verbose=verbose)

    # print_unprocessed_seed_paths(extracted_root=args.extracted_root)

