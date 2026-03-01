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
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

STAFF_DIR = os.getcwd()
FIRMAE_DIR = os.path.join(STAFF_DIR, "FirmAE")

SKIP_MODULES = {}
SKIP_MODULES = {("any", "aflnet_base", "any")}
SKIP_MODULES = {("FW_RT_N10U_B1_30043763754.zip", "any", "rc"),("FW_TV-IP121WN_1.2.2.zip", "any", "setup.cgi"), ("any", "any", "FP"), ("any", "aflnet_base", "any"), ("dap2310_v1.00_o772.bin", "any", "neaps_array"), ("dap2310_v1.00_o772.bin", "any", "neapc"),
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
ABLATION_VARIANTS = ["CkptOnly", "SeqOnly", "NoOpt", "FullOpt"]

METHOD_ABBR = {
    "aflnet_base": "AB",
    "aflnet_state_aware": "ASA",
    "triforce": "TRI",
    "staff_state_aware": "STAFF",
    "FullOpt": "STAFF",
    "CkptOnly": "Ckpt",
    "SeqOnly": "Seq",
    "NoOpt": "NoOpt"
}

TOOL_FILTER = "staff_state_aware"
ALLOWED_TOOLS = set(DEFAULT_METHODS) | {"all"}

FILTER_METRIC_CHOICE = "recall"
DEDUP_METRIC_CHOICE = "recall"

OUTPUT_DIR = "analysis_results"

MAX_EXP_NUM = None
MAX_EXP_ABLATION_NUM = None

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

def should_include_ablation_experiment(exp_name: str) -> bool:
    if MAX_EXP_ABLATION_NUM is None:
        return True

    match = re.match(r'exp[_-]?(\d+)', exp_name, re.IGNORECASE)
    if match:
        exp_num = int(match.group(1))
        return exp_num <= MAX_EXP_ABLATION_NUM

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
            min_reqs_str = raw.get("min_reqs", "0").strip()

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
            try:
                min_reqs = int(min_reqs_str) if min_reqs_str else 0
            except ValueError:
                min_reqs = 0

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
                          f"old={old} -> new={(s_int,e_int,category,cve_id,bug_id,min_reqs)} (overwriting)")

            pc_ranges[firmware][module][func_name] = (s_int, e_int, category, cve_id, bug_id, min_reqs)
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
            for fname, tpl in sorted(funcs.items()):
                if len(tpl) == 6:
                    s, e, cat, cve_id, bug_id, min_reqs = tpl
                elif len(tpl) == 5:
                    s, e, cat, cve_id, bug_id = tpl
                    min_reqs = 0
                else:
                    continue
                cat_repr = repr(cat) if cat is not None else "None"
                cve_repr = repr(cve_id) if cve_id is not None else "None"
                bug_repr = repr(bug_id) if bug_id is not None else "None"
                lines.append(f"            {fname!r}: (0x{s:08x}, 0x{e:08x}, {cat_repr}, {cve_repr}, {bug_repr}, {min_reqs}),")
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

def calculate_avg_execs_per_sec(plot_path: str, execs_col_idx: int = 2) -> float:
    first_row = None
    last_row = None

    with open(plot_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.split(",")]
            if len(parts) <= max(execs_col_idx, 0):
                continue
            try:
                unix_time = int(parts[0])
                execs_done = int(parts[execs_col_idx])
                row = (unix_time, execs_done)
                if first_row is None:
                    first_row = row
                last_row = row
            except (ValueError, IndexError):
                continue

    if first_row is None or last_row is None:
        return None

    first_time, _ = first_row
    last_time, last_execs = last_row

    time_diff = last_time - first_time
    if time_diff <= 0:
        return None

    return (last_execs / time_diff) * 60

def get_total_execs_done(plot_path: str, execs_col_idx: int = 2) -> int:
    if not os.path.isfile(plot_path):
        return None

    last_execs = None

    with open(plot_path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.split(",")]
            if len(parts) <= max(execs_col_idx, 0):
                continue
            try:
                last_execs = int(parts[execs_col_idx])
            except (ValueError, IndexError):
                continue

    return last_execs

def build_execs_per_sec_table(experiments_dir, methods=None, verbose=True):
    if methods is None:
        methods = DEFAULT_METHODS

    if not os.path.isdir(experiments_dir):
        if verbose:
            print(f"[ERROR] experiments_dir does not exist: {experiments_dir}")
        return {}, {}

    data_rate = defaultdict(lambda: defaultdict(list))
    data_total = defaultdict(lambda: defaultdict(list))

    for sub_exp in sorted(os.listdir(experiments_dir)):
        sub_path = os.path.join(experiments_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        if not should_include_experiment(sub_exp):
            continue

        config_path = os.path.join(sub_path, "outputs", "config.ini")
        if not os.path.isfile(config_path):
            if verbose:
                print(f"[INFO] skipping {sub_exp}: no config.ini")
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

        if mode not in methods:
            continue

        if os.path.dirname(firmware_path):
            firmware = firmware_path
        else:
            firmware = os.path.basename(firmware_path)

        # For triforce, use old_plot_data instead of plot_data
        if mode == "triforce":
            plot_candidates = [
                os.path.join(sub_path, "old_plot_data"),
                os.path.join(sub_path, "outputs", "old_plot_data"),
            ]
        else:
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
                print(f"[INFO] no plot_data for {sub_exp}, skipping")
            continue

        avg_execs = calculate_avg_execs_per_sec(plot_path)
        total_execs = get_total_execs_done(plot_path)

        if avg_execs is not None:
            data_rate[firmware][mode].append(avg_execs)
        if total_execs is not None:
            data_total[firmware][mode].append(total_execs)

        if verbose and avg_execs is not None:
            print(f"[INFO] {sub_exp}: {avg_execs:.2f} execs/min, {total_execs} total execs")

    result_rate = {}
    for firmware in data_rate:
        result_rate[firmware] = {}
        for mode in data_rate[firmware]:
            values = data_rate[firmware][mode]
            if values:
                result_rate[firmware][mode] = sum(values) / len(values)

    result_total = {}
    for firmware in data_total:
        result_total[firmware] = {}
        for mode in data_total[firmware]:
            values = data_total[firmware][mode]
            if values:
                result_total[firmware][mode] = sum(values) / len(values)

    return result_rate, result_total

def write_execs_per_sec_tables(execs_data, methods=None, output_dir=OUTPUT_DIR, output_prefix="out_execs_per_min"):
    if methods is None:
        methods = DEFAULT_METHODS

    if not execs_data:
        print("[WARN] No execs/min data to write")
        return

    os.makedirs(output_dir, exist_ok=True)

    headers = ["Firmware"] + [METHOD_ABBR.get(m, m) for m in methods]
    rows = []

    for firmware in sorted(execs_data.keys()):
        row = {"Firmware": firmware}
        for method in methods:
            avg_execs = execs_data[firmware].get(method, None)
            if avg_execs is not None:
                row[METHOD_ABBR.get(method, method)] = f"{avg_execs:.2f}"
            else:
                row[METHOD_ABBR.get(method, method)] = "-"
        rows.append(row)

    csv_path = os.path.join(output_dir, f"{output_prefix}.csv")
    df = pd.DataFrame(rows)
    df.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[INFO] Wrote execs/min CSV to {csv_path}")

    tex_path = os.path.join(output_dir, f"{output_prefix}.tex")
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\\begin{table}[htbp]\n")
        f.write("\\centering\n")
        f.write("\\caption{Average Executions per Minute by Firmware and Method}\n")
        f.write("\\label{tab:execs_per_min}\n")
        f.write("\\begin{tabular}{l" + "r" * len(methods) + "}\n")
        f.write("\\toprule\n")
        f.write(" & ".join(headers) + " \\\\\n")
        f.write("\\midrule\n")

        for row in rows:
            row_values = [row["Firmware"]]
            for method in methods:
                row_values.append(row[METHOD_ABBR.get(method, method)])
            f.write(" & ".join(row_values) + " \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"[INFO] Wrote execs/min LaTeX to {tex_path}")

def write_total_execs_tables(execs_data, methods=None, output_dir=OUTPUT_DIR, output_prefix="out_total_execs"):
    if methods is None:
        methods = DEFAULT_METHODS

    if not execs_data:
        print("[WARN] No total execs data to write")
        return

    os.makedirs(output_dir, exist_ok=True)

    headers = ["Firmware"] + [METHOD_ABBR.get(m, m) for m in methods]
    rows = []

    for firmware in sorted(execs_data.keys()):
        row = {"Firmware": firmware}
        for method in methods:
            avg_execs = execs_data[firmware].get(method, None)
            if avg_execs is not None:
                row[METHOD_ABBR.get(method, method)] = f"{int(avg_execs)}"
            else:
                row[METHOD_ABBR.get(method, method)] = "-"
        rows.append(row)

    csv_path = os.path.join(output_dir, f"{output_prefix}.csv")
    df = pd.DataFrame(rows)
    df.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[INFO] Wrote total execs CSV to {csv_path}")

    tex_path = os.path.join(output_dir, f"{output_prefix}.tex")
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\\begin{table}[htbp]\n")
        f.write("\\centering\n")
        f.write("\\caption{Average Total Executions by Firmware and Method}\n")
        f.write("\\label{tab:total_execs}\n")
        f.write("\\begin{tabular}{l" + "r" * len(methods) + "}\n")
        f.write("\\toprule\n")
        f.write(" & ".join(headers) + " \\\\\n")
        f.write("\\midrule\n")

        for row in rows:
            row_values = [row["Firmware"]]
            for method in methods:
                row_values.append(row[METHOD_ABBR.get(method, method)])
            f.write(" & ".join(row_values) + " \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    print(f"[INFO] Wrote total execs LaTeX to {tex_path}")


def calculate_confidence_interval(data, confidence=0.95, clamp_lower_at_zero=True, clamp_upper_at=None):
    if not data or len(data) == 0:
        return 0.0, 0.0, 0.0, 0.0

    n = len(data)
    mean = np.mean(data)

    if n == 1:
        return mean, mean, mean, 0.0

    std_err = stats.sem(data)

    ci = stats.t.interval(confidence, n - 1, loc=mean, scale=std_err)

    lower_bound = ci[0]
    upper_bound = ci[1]

    if clamp_lower_at_zero and lower_bound < 0:
        lower_bound = 0.0

    if clamp_upper_at is not None and upper_bound > clamp_upper_at:
        upper_bound = float(clamp_upper_at)

    return mean, lower_bound, upper_bound, std_err


def plot_per_category_with_error_bars(category_data_per_method, output_dir=".", output_prefix="crashes_per_category",
                                       methods=None, ylabel="Average Detection Consistency (normalized)",
                                       title="Detection Consistency Per Category with 95% Confidence Intervals",
                                       verbose=True):
    if methods is None:
        methods = DEFAULT_METHODS

    if not category_data_per_method:
        if verbose:
            print("[WARN] No category data to plot")
        return

    all_categories = set()
    for method_data in category_data_per_method.values():
        all_categories.update(method_data.keys())

    categories = ordered_categories(all_categories)

    categories.append("Overall")

    if not categories:
        if verbose:
            print("[WARN] No categories with data to plot")
        return

    plot_data = {}
    csv_rows = []

    for method in methods:
        plot_data[method] = {
            'means': [],
            'ci_lower': [],
            'ci_upper': [],
        }

        for cat in categories:
            if cat == "Overall":
                all_consistency_values = []
                for category_name, consistency_values in category_data_per_method.get(method, {}).items():
                    all_consistency_values.extend(consistency_values)
                counts = all_consistency_values
            else:
                counts = category_data_per_method.get(method, {}).get(cat, [])

            if counts:
                mean, lower, upper, std_err = calculate_confidence_interval(counts, clamp_lower_at_zero=True, clamp_upper_at=1.0)
                plot_data[method]['means'].append(mean)
                plot_data[method]['ci_lower'].append(mean - lower)
                plot_data[method]['ci_upper'].append(upper - mean)

                csv_rows.append({
                    'Method': METHOD_ABBR.get(method, method),
                    'Category': cat,
                    'Mean': f"{mean:.3f}",
                    'CI_Lower': f"{lower:.3f}",
                    'CI_Upper': f"{upper:.3f}",
                    'Std_Error': f"{std_err:.3f}",
                    'N_Crashes': len(counts)
                })
            else:
                plot_data[method]['means'].append(0)
                plot_data[method]['ci_lower'].append(0)
                plot_data[method]['ci_upper'].append(0)

    csv_path = os.path.join(output_dir, f"{output_prefix}_stats.csv")
    df = pd.DataFrame(csv_rows)
    df.to_csv(csv_path, index=False, encoding="utf-8")

    if verbose:
        print(f"[INFO] Saved per-category statistics: {csv_path}")

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(categories))
    width = 0.8 / len(methods)

    for idx, method in enumerate(methods):
        offset = (idx - len(methods)/2 + 0.5) * width
        means = plot_data[method]['means']
        ci_lower = plot_data[method]['ci_lower']
        ci_upper = plot_data[method]['ci_upper']

        ax.bar(x + offset, means, width,
               label=METHOD_ABBR.get(method, method),
               yerr=[ci_lower, ci_upper],
               capsize=3,
               error_kw={'elinewidth': 1, 'capthick': 1})

    ax.set_xlabel('Category', fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.set_xticks(x)

    labels = []
    for cat in categories:
        if cat == "Overall":
            labels.append(r'$\mathbf{Overall}$')
        else:
            labels.append(cat)
    ax.set_xticklabels(labels, rotation=0, ha='center')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()

    eps_path = os.path.join(output_dir, f"{output_prefix}.eps")
    plt.savefig(eps_path, format='eps', dpi=300, bbox_inches='tight')

    png_path = os.path.join(output_dir, f"{output_prefix}.png")
    plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')

    plt.close()

    if verbose:
        print(f"[INFO] Saved per-category plot: {eps_path}")
        print(f"[INFO] Saved per-category plot (PNG): {png_path}")


def plot_per_firmware_with_error_bars(firmware_data_per_method, firmware_total_runs_per_method,
                                       output_dir=".", output_prefix="crashes_per_firmware",
                                       methods=None, firmwares=None, ylabel="Average Detection Consistency (normalized)",
                                       title="Detection Consistency Per Firmware with 95% Confidence Intervals",
                                       verbose=True):
    if methods is None:
        methods = DEFAULT_METHODS

    if not firmware_data_per_method:
        if verbose:
            print("[WARN] No firmware data to plot")
        return

    if firmwares is None:
        firmwares = set()
        for method_data in firmware_data_per_method.values():
            firmwares.update(method_data.keys())
        firmwares = sorted(list(firmwares))

    if not firmwares:
        if verbose:
            print("[WARN] No firmwares with data to plot")
        return

    plot_data = {}
    csv_rows = []

    for method in methods:
        plot_data[method] = {
            'means': [],
            'ci_lower': [],
            'ci_upper': [],
        }

        for fw in firmwares:
            counts = firmware_data_per_method.get(method, {}).get(fw, [])
            total_runs = firmware_total_runs_per_method.get(method, {}).get(fw, 0)

            if counts:
                mean, lower, upper, std_err = calculate_confidence_interval(counts, clamp_lower_at_zero=True, clamp_upper_at=1.0)
                plot_data[method]['means'].append(mean)
                plot_data[method]['ci_lower'].append(mean - lower)
                plot_data[method]['ci_upper'].append(upper - mean)

                csv_rows.append({
                    'Method': METHOD_ABBR.get(method, method),
                    'Firmware': os.path.basename(fw),
                    'Mean': f"{mean:.3f}",
                    'CI_Lower': f"{lower:.3f}",
                    'CI_Upper': f"{upper:.3f}",
                    'Std_Error': f"{std_err:.3f}",
                    'N_Crashes': len(counts),
                    'Total_Runs': total_runs
                })
            else:
                plot_data[method]['means'].append(0)
                plot_data[method]['ci_lower'].append(0)
                plot_data[method]['ci_upper'].append(0)

    csv_path = os.path.join(output_dir, f"{output_prefix}_stats.csv")
    df = pd.DataFrame(csv_rows)
    df.to_csv(csv_path, index=False, encoding="utf-8")

    if verbose:
        print(f"[INFO] Saved per-firmware statistics: {csv_path}")

    fig, ax = plt.subplots(figsize=(14, 6))

    x = np.arange(len(firmwares))
    width = 0.8 / len(methods)

    for idx, method in enumerate(methods):
        offset = (idx - len(methods)/2 + 0.5) * width
        means = plot_data[method]['means']
        ci_lower = plot_data[method]['ci_lower']
        ci_upper = plot_data[method]['ci_upper']

        ax.bar(x + offset, means, width,
               label=METHOD_ABBR.get(method, method),
               yerr=[ci_lower, ci_upper],
               capsize=3,
               error_kw={'elinewidth': 1, 'capthick': 1})

    ax.set_xlabel('Firmware', fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([os.path.basename(fw)[:30] for fw in firmwares], rotation=45, ha='right', fontsize=9)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()

    eps_path = os.path.join(output_dir, f"{output_prefix}.eps")
    plt.savefig(eps_path, format='eps', dpi=300, bbox_inches='tight')

    png_path = os.path.join(output_dir, f"{output_prefix}.png")
    plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')

    plt.close()

    if verbose:
        print(f"[INFO] Saved per-firmware plot: {eps_path}")
        print(f"[INFO] Saved per-firmware plot (PNG): {png_path}")


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


def update_extracted_root_from_ablation_experiments(experiments_ablation_dir, extracted_ablation_root="extracted_crashes_ablation", verbose=True):
    def extract_ts_from_name(filename):
        if "$" not in filename:
            return None
        try:
            ts_str = filename.split("$")[-1]
            ts = int(ts_str)
            return ts // 1000
        except Exception:
            return None

    def classify_variant(config):
        try:
            seq_min = int(config.get("STAFF_FUZZING", "sequence_minimization", fallback="0"))
            ckpt = int(config.get("STAFF_FUZZING", "checkpoint_strategy", fallback="0"))

            if seq_min == 0 and ckpt == 1:
                return "CkptOnly"
            elif seq_min == 1 and ckpt == 0:
                return "SeqOnly"
            elif seq_min == 0 and ckpt == 0:
                return "NoOpt"
            elif seq_min == 1 and ckpt == 1:
                return "FullOpt"
            else:
                return f"seq{seq_min}_ckpt{ckpt}"
        except Exception as e:
            if verbose:
                print(f"[WARN] Error classifying variant: {e}")
            return "Unknown"

    if not os.path.isdir(experiments_ablation_dir):
        if verbose:
            print(f"[ERROR] experiments_ablation_dir does not exist: {experiments_ablation_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_ablation_dir)):
        sub_path = os.path.join(experiments_ablation_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        if not should_include_ablation_experiment(sub_exp):
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

        variant_name = classify_variant(config)

        if os.path.dirname(firmware_path):
            firmware_with_brand = firmware_path
        else:
            firmware_with_brand = os.path.basename(firmware_path)

        if (os.path.isdir(os.path.join(sub_path, "outputs", "crash_traces")) and not os.listdir(os.path.join(sub_path, "outputs", "crash_traces"))
            and os.path.isdir(os.path.join(sub_path, "outputs", "crashes")) and not os.listdir(os.path.join(sub_path, "outputs", "crashes"))):
            continue

        target_exp_dir = os.path.join(extracted_ablation_root, firmware_with_brand, variant_name, sub_exp)

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
                        print(f"[SKIP] {ftype}: crash_id {crash_id} already exists in extracted_ablation_root")
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
                    print(f"Copied NEW to extracted_ablation_root: {src_file} -> {dst_file}")
                copied_counts[ftype] += 1

        if verbose:
            print(f"[RESULT] {sub_exp} -> firmware='{firmware_with_brand}', variant='{variant_name}': "
                  f"crashes_copied={copied_counts['crashes']}, "
                  f"traces_copied={copied_counts['crash_traces']}")

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
            if len(tpl) == 6:
                start, end, category, cve_id, bug_id, min_reqs = tpl
            elif len(tpl) == 5:
                start, end, category, cve_id, bug_id = tpl
                min_reqs = 0
            elif len(tpl) == 4:
                start, end, category, cve_id = tpl
                bug_id = None
                min_reqs = 0
            elif len(tpl) == 3:
                start, end, category = tpl
                cve_id = None
                bug_id = None
                min_reqs = 0
            else:
                start, end = tpl
                category = None
                cve_id = None
                bug_id = None
                min_reqs = 0
            try:
                s = int(start)
                e = int(end)
            except:
                continue
            if s <= pc_int <= e:
                return (fw, module, fun_name, category, cve_id)
    return raw

def extract_unique_crashes_per_function(extracted_root="extracted_crashes", output_dir="unique_crashes", verbose=True, require_succ=True):
    if not os.path.isdir(extracted_root):
        if verbose:
            print(f"[ERROR] extracted_root does not exist: {extracted_root}")
        return

    def parse_tte_from_filename(filename):
        if "$" in filename:
            try:
                suf = filename.rsplit("$", 1)[1]
                suf = suf.split(".")[0]
                m = re.match(r"(\d+)", suf)
                if m:
                    return int(m.group(1))
            except Exception:
                pass
        return None

    unique_crashes = {}

    if require_succ:
        print(f"\n[INFO] Scanning {extracted_root} for unique crashes (all .succ seeds included for fallback)...")
    else:
        print(f"\n[INFO] Scanning {extracted_root} for unique crashes (all seeds included, .succ preferred)...")

    for root, dirs, files in os.walk(extracted_root):
        if not (root.endswith("/crashes") or "/crashes/" in root or root.endswith("crashes")):
            continue

        if "/aflnet_base/" in root or root.endswith("/aflnet_base"):
            continue

        try:
            rel_path = os.path.relpath(root, extracted_root)
            parts = rel_path.split(os.sep)

            if len(parts) >= 3 and parts[0] != "." and not rel_path.startswith(".."):
                brand = parts[0]
                firmware = parts[1]
                method = parts[2]
            else:
                brand = "unknown"
                firmware = "unknown"
                method = "unknown"
        except (ValueError, IndexError):
            brand = "unknown"
            firmware = "unknown"
            method = "unknown"

        for file in files:
            if file.endswith(".lock") or file.endswith(".minimize_test"):
                continue

            if file.endswith(".succ"):
                base_name = file[:-5]
                status = "succ"
                seed_path = os.path.join(root, file)
            elif file.endswith(".fail"):
                continue
            else:
                if require_succ:
                    continue
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

            if module == "unknown" and function == "unknown":
                if verbose:
                    print(f"[SKIP] Filtered unknown/unknown crash: {seed_path}")
                continue

            fw_name_only = os.path.basename(firmware)
            if ((fw_name_only, method, module) in SKIP_MODULES or
                (fw_name_only, "any", module) in SKIP_MODULES or
                ("any", method, "any") in SKIP_MODULES or
                ("any", "any", module) in SKIP_MODULES):
                if verbose:
                    # print(f"[SKIP] Filtered by SKIP_MODULES: {firmware}/{method}/{module}")
                    pass
                continue

            unique_key = (brand, firmware, module, function)

            tte = parse_tte_from_filename(file)

            status_priority = {"succ": 2, "unprocessed": 1}

            if unique_key not in unique_crashes:
                unique_crashes[unique_key] = []

            unique_crashes[unique_key].append({
                'seed_path': seed_path,
                'trace_path': trace_path,
                'tte': tte,
                'status': status,
                'priority': status_priority[status]
            })

    if os.path.exists(output_dir):
        if verbose:
            print(f"[INFO] Output directory exists, will update with new crashes: {output_dir}")
    else:
        os.makedirs(output_dir, exist_ok=True)
        if verbose:
            print(f"[INFO] Created output directory: {output_dir}")

    copied_count = 0
    skipped_count = 0

    for (brand, firmware, module, function), seed_list in sorted(unique_crashes.items()):
        fw_dir = os.path.join(output_dir, brand, firmware)
        module_dir = os.path.join(fw_dir, module)

        safe_function = function.replace('/', '_').replace('\\', '_')
        function_dir = os.path.join(module_dir, safe_function)
        os.makedirs(function_dir, exist_ok=True)

        sorted_seeds = sorted(seed_list, key=lambda x: (-x['priority'], x['tte'] if x['tte'] is not None else float('inf')))

        traces_output_dir = output_dir.replace("unique_crashes", "unique_crashes_traces")
        traces_function_dir = os.path.join(traces_output_dir, brand, firmware, module, safe_function)
        os.makedirs(traces_function_dir, exist_ok=True)

        for seed_idx, info in enumerate(sorted_seeds):
            seed_basename = os.path.basename(info['seed_path'])
            dest_seed = os.path.join(function_dir, f"{seed_basename}")

            trace_basename = os.path.basename(info['trace_path'])
            dest_trace = os.path.join(traces_function_dir, f"{trace_basename}")

            seed_exists = os.path.exists(dest_seed)
            trace_exists_at_source = os.path.exists(info['trace_path'])
            trace_exists_at_dest = os.path.exists(dest_trace)

            if seed_exists:
                skipped_count += 1
                if verbose:
                    tte_str = f"TTE={info['tte']}s" if info['tte'] is not None else "TTE=unknown"
                    status_str = f"[{info['status']}]"
                    seed_label = f"seed {seed_idx+1}/{len(sorted_seeds)}"
                    print(f"[SKIP] {brand}/{firmware}/{module}/{function} ({seed_label}) {status_str} ({tte_str}) -> seed already exists")

                if trace_exists_at_source and not trace_exists_at_dest:
                    try:
                        shutil.copy2(info['trace_path'], dest_trace)
                        if verbose:
                            print(f"       [COPY TRACE] -> {dest_trace}")
                    except Exception as e:
                        if verbose:
                            print(f"       [ERROR] Failed to copy trace: {e}")
                elif not trace_exists_at_source and verbose:
                    print(f"       [WARN] Trace file missing at source: {info['trace_path']}")
            else:
                # Copy seed
                shutil.copy2(info['seed_path'], dest_seed)

                # Copy corresponding trace
                if trace_exists_at_source:
                    try:
                        shutil.copy2(info['trace_path'], dest_trace)
                    except Exception as e:
                        if verbose:
                            print(f"       [ERROR] Failed to copy trace: {e}")
                elif verbose:
                    print(f"       [WARN] No trace file at: {info['trace_path']}")

                copied_count += 1

                tte_str = f"TTE={info['tte']}s" if info['tte'] is not None else "TTE=unknown"
                status_str = f"[{info['status']}]"
                seed_label = f"seed {seed_idx+1}/{len(sorted_seeds)}"
                if verbose:
                    print(f"[COPY] {brand}/{firmware}/{module}/{function} ({seed_label}) {status_str} ({tte_str}) -> {dest_seed}")

    total_processed = copied_count + skipped_count
    total_unique_crashes = len(unique_crashes)
    traces_output_dir = output_dir.replace("unique_crashes", "unique_crashes_traces")

    trace_count = 0
    if os.path.exists(traces_output_dir):
        for root, dirs, files in os.walk(traces_output_dir):
            trace_count += len([f for f in files if not f.startswith('.')])

    if require_succ:
        print(f"\n[SUCCESS] Processed {total_unique_crashes} unique crashes with {total_processed} total seeds (.succ only, sorted by TTE)")
    else:
        print(f"\n[SUCCESS] Processed {total_unique_crashes} unique crashes with {total_processed} total seeds (.succ preferred, sorted by TTE)")
    print(f"           Seeds:  {output_dir}")
    print(f"           Traces: {traces_output_dir} ({trace_count} trace files)")
    print(f"           New: {copied_count}, Skipped (already present): {skipped_count}")
    print(f"           Organized by: firmware/module/function (multiple seeds per crash for fallback)")

    if trace_count == 0 and verbose:
        print(f"\n[WARN] No trace files were copied! Check that {extracted_root}/*/crash_traces/ contains trace files.")
        print(f"       If extracted_crashes is empty, you may need to re-extract from experiments directory.\n")
    else:
        print()

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

        # For triforce, use old_plot_data instead of plot_data
        if mode == "triforce":
            plot_candidates = [
                os.path.join(sub_path, "old_plot_data"),
                os.path.join(sub_path, "outputs", "old_plot_data"),
            ]
        else:
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


def annotate_extracted_ablation_with_tte(experiments_ablation_dir, extracted_ablation_root="extracted_crashes_ablation", verbose=True):
    def classify_variant(config):
        try:
            seq_min = int(config.get("STAFF_FUZZING", "sequence_minimization", fallback="0"))
            ckpt = int(config.get("STAFF_FUZZING", "checkpoint_strategy", fallback="0"))

            if seq_min == 0 and ckpt == 1:
                return "CkptOnly"
            elif seq_min == 1 and ckpt == 0:
                return "SeqOnly"
            elif seq_min == 0 and ckpt == 0:
                return "NoOpt"
            elif seq_min == 1 and ckpt == 1:
                return "FullOpt"
            else:
                return f"seq{seq_min}_ckpt{ckpt}"
        except Exception as e:
            if verbose:
                print(f"[WARN] Error classifying variant: {e}")
            return None

    if not os.path.isdir(experiments_ablation_dir):
        if verbose:
            print(f"[ERROR] experiments_ablation_dir does not exist: {experiments_ablation_dir}")
        return

    for sub_exp in sorted(os.listdir(experiments_ablation_dir)):
        sub_path = os.path.join(experiments_ablation_dir, sub_exp)
        if not os.path.isdir(sub_path) or not sub_exp.startswith("exp_"):
            continue

        if not should_include_ablation_experiment(sub_exp):
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

        variant_name = classify_variant(config)
        if variant_name is None:
            if verbose:
                print(f"[WARN] couldn't classify variant for {sub_exp}, skipping")
            continue

        if os.path.dirname(firmware_path):
            firmware_with_brand = firmware_path
        else:
            firmware_with_brand = os.path.basename(firmware_path)

        target_exp_dir = os.path.join(extracted_ablation_root, firmware_with_brand, variant_name, sub_exp)

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

        if mode == "triforce":
            plot_candidates = [
                os.path.join(sub_path, "old_plot_data"),
                os.path.join(sub_path, "outputs", "old_plot_data"),
            ]
        else:
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
        sleep = int(float(sleep))

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


def build_agg_from_extracted_ablation(extracted_ablation_root=None, verbose=False):
    if extracted_ablation_root is None:
        extracted_ablation_root = extracted_root
    import configparser
    from collections import defaultdict

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

    ABLATION_VARIANTS = ["CkptOnly", "SeqOnly", "NoOpt", "FullOpt"]

    agg_ablation = defaultdict(lambda: defaultdict(dict))
    variant_counts = defaultdict(int)
    experiments_per_fw_variant = defaultdict(lambda: defaultdict(list))  # Track experiments per (firmware, variant)

    if not os.path.isdir(extracted_ablation_root):
        if verbose:
            print(f"[WARN] Ablation extraction directory not found: {extracted_ablation_root}")
        return agg_ablation

    if verbose:
        print(f"[INFO] Processing ablation crashes from: {extracted_ablation_root}")

    for brand_dir in sorted(os.listdir(extracted_ablation_root)):
        brand_path = os.path.join(extracted_ablation_root, brand_dir)
        if not os.path.isdir(brand_path):
            continue

        for fw_dir in sorted(os.listdir(brand_path)):
            fw_path = os.path.join(brand_path, fw_dir)
            if not os.path.isdir(fw_path):
                continue

            fw_name = os.path.join(brand_dir, fw_dir)

            variant_list = ["CkptOnly", "SeqOnly", "NoOpt", "FullOpt"]

            for variant_name in variant_list:
                variant_dir = os.path.join(fw_path, variant_name)
                if not os.path.isdir(variant_dir):
                    continue

                for sub_exp in sorted(os.listdir(variant_dir)):
                    if not sub_exp.startswith("exp_"):
                        continue

                    if not should_include_ablation_experiment(sub_exp):
                        continue

                    if verbose:
                        print(f"[DEBUG] Processing {sub_exp} in {fw_name}/{variant_name}")

                    exp_dir = os.path.join(variant_dir, sub_exp)
                    if not os.path.isdir(exp_dir):
                        continue

                    crashes_dir = os.path.join(exp_dir, "crashes")
                    crash_traces_dir = os.path.join(exp_dir, "crash_traces")

                    if not os.path.isdir(crash_traces_dir):
                        continue

                    trace_files = []
                    for entry in sorted(os.listdir(crash_traces_dir)):
                        epath = os.path.join(crash_traces_dir, entry)
                        if os.path.isfile(epath):
                            trace_files.append(epath)
                        elif os.path.isdir(epath):
                            for subf in sorted(os.listdir(epath)):
                                subp = os.path.join(epath, subf)
                                if os.path.isfile(subp):
                                    trace_files.append(subp)

                    per_exp_info = {}
                    trace_stats = {"total": len(trace_files), "no_succ": 0, "no_pc": 0, "skipped": 0, "added": 0}
                    for tf in trace_files:
                        bname = os.path.basename(tf)
                        seed_name = bname.replace("_traces", "")

                        succ_file_path = os.path.join(crashes_dir, seed_name + ".succ")
                        if REQUIRE_SUCC_FLAG:
                            if not os.path.isfile(succ_file_path):
                                trace_stats["no_succ"] += 1
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

                        pc, module = _parse_first_frame_pc_module(tf)
                        if pc is None and module is None:
                            trace_stats["no_pc"] += 1
                            continue

                        module_norm = (module or "(unknown_module)")
                        pc_norm = (pc or "(unknown_pc)")

                        raw_key = (fw_name, module_norm, pc_norm)

                        tte_val = None
                        taint_val = None
                        if "$" in bname:
                            try:
                                suf = bname.rsplit("$", 1)[1]
                                m = re.match(r"(\d+)", suf)
                                if m:
                                    tte_val = int(m.group(1))
                            except Exception:
                                pass
                        if "&" in bname:
                            try:
                                suf = bname.rsplit("&", 1)[1]
                                m = re.match(r"([0-9]*\.?[0-9]+)", suf)
                                if m:
                                    taint_val = float(m.group(1))
                            except Exception:
                                pass

                        prev = per_exp_info.get(raw_key)
                        if prev is None:
                            per_exp_info[raw_key] = {
                                "tte": tte_val,
                                "taints": ([taint_val] if taint_val is not None else []),
                                "crash_seed_path": crash_seed_path
                            }
                            trace_stats["added"] += 1
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

                        if verbose and (trace_stats["total"] > 0 or len(per_exp_info) > 0):
                            print(f"[TRACE_STATS] {sub_exp} in {fw_name}/{variant_name}: "
                                f"total={trace_stats['total']}, no_succ={trace_stats['no_succ']}, "
                                f"no_pc={trace_stats['no_pc']}, skipped={trace_stats['skipped']}, "
                                f"added={trace_stats['added']}, unique_crashes={len(per_exp_info)}")
                            if len(per_exp_info) > 0:
                                for key in list(per_exp_info.keys())[:3]:  # Show first 3 keys
                                    print(f"    -> {key}")

                        if per_exp_info:
                            experiments_per_fw_variant[fw_name][variant_name].append(sub_exp)

                        for key, info in per_exp_info.items():
                            taints = info.get("taints", []) or []
                            taint_avg = None
                            if taints:
                                try:
                                    taint_avg = int(sum(taints) / len(taints)) if all(float(t).is_integer() for t in taints) else (sum(taints) / len(taints))
                                except Exception:
                                    taint_avg = sum(taints) / len(taints)

                            agg_ablation[key][variant_name][sub_exp] = {
                                "tte": info.get("tte"),
                                "taint": taint_avg,
                                "crash_seed_path": info.get("crash_seed_path")
                            }

                            variant_counts[variant_name] += 1

    return agg_ablation


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
                if len(tpl) == 6:
                    start, end, category, cve_id, bug_id, min_reqs = tpl
                elif len(tpl) == 5:
                    start, end, category, cve_id, bug_id = tpl
                    min_reqs = 0
                elif len(tpl) == 4:
                    start, end, category, cve_id = tpl
                    bug_id = None
                    min_reqs = 0
                elif len(tpl) == 3:
                    start, end, category = tpl
                    cve_id = None
                    bug_id = None
                    min_reqs = 0
                else:
                    start, end = tpl
                    category = None
                    cve_id = None
                    bug_id = None
                    min_reqs = 0
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
        return (fw_name_only, method, module) in SKIP_MODULES or (fw_name_only, "any", module) in SKIP_MODULES or ("any", method, "any") in SKIP_MODULES or ("any", "any", module) in SKIP_MODULES

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

    crash_data_per_method = defaultdict(lambda: defaultdict(list))
    crash_total_runs_per_method = defaultdict(lambda: defaultdict(int))

    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        for m in DEFAULT_METHODS:
            per_run_crashes = defaultdict(set)

            all_crashes_this_fw = set()
            crash_detection_per_run = defaultdict(lambda: defaultdict(bool))

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
                        all_crashes_this_fw.add(key)
                        crash_detection_per_run[key][exp] = True

            run_counts = [len(s) for s in per_run_crashes.values()]

            mean_crashes = (
                sum(len(s) for s in per_run_crashes.values()) / len(per_run_crashes)
                if per_run_crashes else 0.0
            )
            col_name = f"{METHOD_ABBR.get(m, m)}_mean_cnt"
            row[col_name] = round(mean_crashes, 3)

            assert total_experiments, "total_experiments is required for detection consistency calculation. Ensure experiments_dir is provided."
            total_runs = total_experiments.get(fw, {}).get(m, 0)
            if total_runs == 0 and per_run_crashes:
                total_runs = len(per_run_crashes)
            crash_total_runs_per_method[m][fw] = total_runs

            per_crash_detection_consistency = []
            for crash_key in all_crashes_this_fw:
                detection_count = sum(1 for exp in crash_detection_per_run[crash_key] if crash_detection_per_run[crash_key][exp])
                consistency = detection_count / total_runs if total_runs > 0 else 0.0
                per_crash_detection_consistency.append(consistency)

            if per_crash_detection_consistency and len(per_crash_detection_consistency) > 1:
                _, ci_lower, ci_upper, _ = calculate_confidence_interval(per_crash_detection_consistency, clamp_lower_at_zero=True, clamp_upper_at=1.0)
                row[f"{METHOD_ABBR.get(m, m)}_ci_lower"] = round(ci_lower, 3)
                row[f"{METHOD_ABBR.get(m, m)}_ci_upper"] = round(ci_upper, 3)

                crash_data_per_method[m][fw] = per_crash_detection_consistency
            else:
                row[f"{METHOD_ABBR.get(m, m)}_ci_lower"] = round(mean_crashes, 3)
                row[f"{METHOD_ABBR.get(m, m)}_ci_upper"] = round(mean_crashes, 3)

                if per_crash_detection_consistency:
                    crash_data_per_method[m][fw] = per_crash_detection_consistency

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
        headers1.append(f"{METHOD_ABBR.get(m, m)}_ci_lower")
        headers1.append(f"{METHOD_ABBR.get(m, m)}_ci_upper")
        if show_exp_count:
            headers1.append(f"{METHOD_ABBR.get(m, m)}_exp_cnt")

    write_csv_and_latex(headers1, table1_rows, out_count_csv, out_count_tex, caption="Number of crashes")

    category_data_per_method = defaultdict(lambda: defaultdict(list))
    category_total_runs_per_method = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for m in DEFAULT_METHODS:
        all_crashes_per_category = defaultdict(set)
        crash_detection_per_category = defaultdict(lambda: defaultdict(lambda: defaultdict(bool)))
        crash_total_runs_tracker = defaultdict(lambda: defaultdict(int))  # Track total runs per crash

        for key, method_dict in agg.items():
            if len(key) == 5:
                f, module, pc, category, cve_id = key
            elif len(key) == 4:
                f, module, pc, category = key
            else:
                f, module, pc = key
                category = None

            if not category:
                continue

            firmware = key[0]
            total_runs_for_crash = crash_total_runs_per_method[m].get(firmware, 0)
            crash_total_runs_tracker[category][key] = total_runs_for_crash

            for exp, data in method_dict.get(m, {}).items():
                if data is not None and data.get("tte") is not None:
                    all_crashes_per_category[category].add(key)
                    crash_detection_per_category[category][key][exp] = True

        for category in all_crashes_per_category:
            per_crash_detection_consistency = []
            for crash_key in all_crashes_per_category[category]:
                detection_count = sum(1 for exp in crash_detection_per_category[category][crash_key]
                                    if crash_detection_per_category[category][crash_key][exp])
                total_runs = crash_total_runs_tracker[category].get(crash_key, 1)
                if total_runs == 0:
                    total_runs = 1

                consistency = detection_count / total_runs
                per_crash_detection_consistency.append(consistency)

            if per_crash_detection_consistency:
                category_data_per_method[m][category] = per_crash_detection_consistency

    if verbose:
        print("[INFO] Generating statistical analysis plots...")

    plot_per_category_with_error_bars(
        category_data_per_method,
        output_dir=OUTPUT_DIR,
        output_prefix="crashes_per_category",
        methods=DEFAULT_METHODS,
        ylabel="Average Detection Consistency (normalized)",
        title="Crash Detection Consistency Per Category with 95% CI",
        verbose=verbose
    )

    plot_per_firmware_with_error_bars(
        crash_data_per_method,
        crash_total_runs_per_method,
        output_dir=OUTPUT_DIR,
        output_prefix="crashes_per_firmware",
        methods=DEFAULT_METHODS,
        firmwares=firmware_set,
        ylabel="Average Detection Consistency (normalized)",
        title="Crash Detection Consistency Per Firmware with 95% CI",
        verbose=verbose
    )

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

            # Calculate taint causality: fraction of experiments where taint > 0
            taint_causality = None
            if taints:
                causality_scores = [1.0 if t > 0 else 0.0 for t in taints]
                taint_causality = sum(causality_scores) / len(causality_scores)

            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""
            row[f"{METHOD_ABBR.get(m, m)}_avg_taint"] = (round(avg_taint, 3) if avg_taint is not None else "")
            #row[f"{METHOD_ABBR.get(m, m)}_taint_causality"] = (round(taint_causality, 3) if taint_causality is not None else "")

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
        #headers2.append(f"{METHOD_ABBR.get(m, m)}_taint_causality")

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
        raw = (fw, module, pc_str, None, None, None, 0)
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
                if len(tpl) == 6:
                    start, end, category, cve_id, bug_id, min_reqs = tpl
                elif len(tpl) == 5:
                    start, end, category, cve_id, bug_id = tpl
                    min_reqs = 0
                elif len(tpl) == 4:
                    start, end, category, cve_id = tpl
                    bug_id = None
                    min_reqs = 0
                elif len(tpl) == 3:
                    start, end, category = tpl
                    cve_id = None
                    bug_id = None
                    min_reqs = 0
                else:
                    start, end = tpl
                    category = None
                    cve_id = None
                    bug_id = None
                    min_reqs = 0

                try:
                    s = int(start)
                    e = int(end)
                except Exception:
                    continue

                if s <= pc_int <= e:
                    return (fw, module, fun_name, category, cve_id, bug_id, min_reqs)

        return raw

    def should_skip(fw, method, module):
        fw_name_only = os.path.basename(fw)
        return ((fw_name_only, method, module) in SKIP_MODULES or
                (fw_name_only, "any", module) in SKIP_MODULES or
                ("any", method, "any") in SKIP_MODULES) or ("any", "any", module) in SKIP_MODULES

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

    bug_min_reqs = {}

    for key, method_dict in agg_mapped.items():
        fw, module, func_or_pc, category, cve_id, bug_id, min_reqs = (key + (None,) * 7)[:7]
        if min_reqs is None:
            min_reqs = 0

        if not bug_id:
            bug_id = f"Unknown-{os.path.basename(fw)}"

        bug_key = (fw, bug_id, category, cve_id)
        bug_sites[bug_key].add((module, func_or_pc))
        if bug_key not in bug_min_reqs:
            bug_min_reqs[bug_key] = min_reqs
        else:
            bug_min_reqs[bug_key] = max(bug_min_reqs[bug_key], min_reqs)

        for method, exp_map in method_dict.items():
            for exp, data in exp_map.items():
                prev = bug_agg[bug_key][method].get(exp)
                if prev is None:
                    bug_agg[bug_key][method][exp] = {
                        "min_tte": data.get("tte"),
                        "taints": ([data["taint"]] if data.get("taint") is not None else []),
                        "sites": { (module, func_or_pc) },
                        "crash_seed_paths": ([data["crash_seed_path"]] if data.get("crash_seed_path") else []),
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

                    if data.get("crash_seed_path"):
                        prev["crash_seed_paths"].append(data["crash_seed_path"])

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

    bug_data_per_method = defaultdict(lambda: defaultdict(list))

    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        for m in DEFAULT_METHODS:
            per_run_bugs = defaultdict(set)

            all_bugs_this_fw = set()
            bug_detection_per_run = defaultdict(lambda: defaultdict(bool))

            for (f, bug_id, category, cve_id), method_dict in bug_agg.items():
                if f != fw:
                    continue
                for exp, data in method_dict.get(m, {}).items():
                    if data is not None and (data.get("sites") or data.get("min_tte") is not None):
                        per_run_bugs[exp].add(bug_id)
                        all_bugs_this_fw.add(bug_id)
                        bug_detection_per_run[bug_id][exp] = True

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

        bug_key = (fw, bug_id, category, cve_id)
        sites = bug_sites[bug_key]
        first_module = sorted(sites)[0][0] if sites else ""

        min_reqs_val = bug_min_reqs.get(bug_key, 0)

        row = {
            "firmware": name,
            "module": first_module,
            "cve_id": out_cve,
            "category": category or "",
            "min_reqs": min_reqs_val,
        }

        for m in DEFAULT_METHODS:
            entries = method_dict.get(m, {})
            row[f"{METHOD_ABBR.get(m, m)}_cnt"] = len(entries)

            ttes = [v.get("min_tte") for v in entries.values() if v and v.get("min_tte") is not None]
            avg_tte = (sum(ttes) / len(ttes)) if ttes else None
            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""

        table2_rows.append(row)

    headers2 = ["firmware", "module", "cve_id", "category", "min_reqs"]
    for m in DEFAULT_METHODS:
        headers2.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers2.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")

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

    return (table1_rows, table2_rows, table3_rows), bug_agg, bug_sites, bug_min_reqs


def generate_bugs_per_category_by_approach_table(bug_agg, output_dir=".", verbose=False):
    output_csv = os.path.join(output_dir, "out_bugs_per_category_by_approach.csv")
    output_tex = os.path.join(output_dir, "out_bugs_per_category_by_approach.tex")

    bugs_by_category = defaultdict(lambda: defaultdict(set))

    for (fw, bug_id, category, cve_id), method_dict in bug_agg.items():
        cat = category or "Unknown"

        for method_name in DEFAULT_METHODS:
            if method_name in method_dict and method_dict[method_name]:
                bugs_by_category[cat][method_name].add((fw, bug_id))

    rows = []
    total_bugs_per_method = defaultdict(int)

    for cat in CAUSALITY_CATEGORY_ORDER:
        row = {"category": cat}
        row_has_bugs = False
        for method in DEFAULT_METHODS:
            count = len(bugs_by_category[cat][method])
            abbr = METHOD_ABBR.get(method, method)
            row[abbr] = count
            total_bugs_per_method[method] += count
            if count > 0:
                row_has_bugs = True
        if row_has_bugs:
            rows.append(row)

    if "Unknown" in bugs_by_category:
        row = {"category": "Unknown"}
        row_has_bugs = False
        for method in DEFAULT_METHODS:
            count = len(bugs_by_category["Unknown"][method])
            abbr = METHOD_ABBR.get(method, method)
            row[abbr] = count
            total_bugs_per_method[method] += count
            if count > 0:
                row_has_bugs = True
        if row_has_bugs:
            rows.append(row)

    total_row = {"category": "Total"}
    for method in DEFAULT_METHODS:
        abbr = METHOD_ABBR.get(method, method)
        total_row[abbr] = total_bugs_per_method[method]
    rows.append(total_row)

    headers = ["category"] + [METHOD_ABBR.get(m, m) for m in DEFAULT_METHODS]

    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    if verbose:
        print(f"[INFO] Wrote bugs per category by approach CSV to {output_csv}")

    def latex_escape(s):
        s = str(s)
        s = s.replace("\\", "\\textbackslash{}")
        s = s.replace("&", "\\&")
        s = s.replace("%", "\\%")
        s = s.replace("$", "\\$")
        s = s.replace("#", "\\#")
        s = s.replace("_", "\\_")
        s = s.replace("{", "\\{")
        s = s.replace("}", "\\}")
        s = s.replace("~", "\\textasciitilde{}")
        s = s.replace("^", "\\textasciicircum{}")
        return s

    with open(output_tex, 'w', encoding='utf-8') as f:
        f.write("\\begin{table}[ht]\n")
        f.write("\\centering\n")
        f.write("\\renewcommand{\\arraystretch}{1.1}\n")

        col_format = "|l||" + "|".join("c" for _ in DEFAULT_METHODS) + "|"
        f.write(f"\\begin{{tabular}}{{{col_format}}}\n")
        f.write("\\hline\n")

        header_cells = ["{\\sc Category}"] + [
            f"{{\\sc {latex_escape(METHOD_ABBR.get(m, m))}}}"
            for m in DEFAULT_METHODS
        ]
        f.write(" & ".join(header_cells) + " \\\\\n")
        f.write("\\hline\\hline\n")

        for row in rows:
            if row["category"] == "Total":
                f.write("\\hline\n")

            cells = [latex_escape(row["category"])]
            for method in DEFAULT_METHODS:
                abbr = METHOD_ABBR.get(method, method)
                cells.append(str(row[abbr]))

            f.write(" & ".join(cells) + " \\\\\n")

        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\caption{Number of bugs per category found by each approach}\n")
        f.write("\\label{tab:bugs_per_category_by_approach}\n")
        f.write("\\end{table}\n")

    if verbose:
        print(f"[INFO] Wrote bugs per category by approach TEX to {output_tex}")


def generate_detection_consistency_table(bug_agg, experiments_dir=None, total_experiments=None, output_dir=".", verbose=False):
    output_csv = os.path.join(output_dir, "out_detection_consistency.csv")
    output_tex = os.path.join(output_dir, "out_detection_consistency.tex")

    if total_experiments is None:
        total_experiments = defaultdict(lambda: defaultdict(int))
        if experiments_dir and os.path.isdir(experiments_dir):
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
                except Exception:
                    continue

    numerators = defaultdict(lambda: defaultdict(int))
    denominators = defaultdict(lambda: defaultdict(int))

    for (fw, bug_id, category, cve_id), method_dict in bug_agg.items():
        cat = category or "Unknown"
        for method in DEFAULT_METHODS:
            fw_total = total_experiments.get(fw, {}).get(method, 0)
            detections = len(method_dict.get(method, {}))
            numerators[cat][method] += detections
            if detections > 0:
                denominators[cat][method] += fw_total

    rows = []
    for cat in CAUSALITY_CATEGORY_ORDER:
        if not any(denominators[cat][m] > 0 or numerators[cat][m] > 0 for m in DEFAULT_METHODS):
            continue
        row = {"category": cat}
        for method in DEFAULT_METHODS:
            abbr = METHOD_ABBR.get(method, method)
            num = numerators[cat][method]
            den = round(denominators[cat][method], -1)
            row[abbr] = f"{num / den:.2f}" if den > 0 else "-"
        rows.append(row)

    if any(numerators["Unknown"][m] > 0 or denominators["Unknown"][m] > 0 for m in DEFAULT_METHODS):
        row = {"category": "Unknown"}
        for method in DEFAULT_METHODS:
            abbr = METHOD_ABBR.get(method, method)
            num = numerators["Unknown"][method]
            den = round(denominators["Unknown"][method], -1)
            row[abbr] = f"{num / den:.2f}" if den > 0 else "-"
        rows.append(row)

    headers = ["category"] + [METHOD_ABBR.get(m, m) for m in DEFAULT_METHODS]

    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    if verbose:
        print(f"[INFO] Wrote detection consistency CSV to {output_csv}")

    def latex_escape(s):
        s = str(s)
        s = s.replace("\\", "\\textbackslash{}")
        s = s.replace("&", "\\&")
        s = s.replace("%", "\\%")
        s = s.replace("$", "\\$")
        s = s.replace("#", "\\#")
        s = s.replace("_", "\\_")
        s = s.replace("{", "\\{")
        s = s.replace("}", "\\}")
        s = s.replace("~", "\\textasciitilde{}")
        s = s.replace("^", "\\textasciicircum{}")
        return s

    with open(output_tex, 'w', encoding='utf-8') as f:
        f.write("\\begin{table}[ht]\n")
        f.write("\\centering\n")
        f.write("\\renewcommand{\\arraystretch}{1.1}\n")
        col_format = "|l||" + "|".join("c" for _ in DEFAULT_METHODS) + "|"
        f.write(f"\\begin{{tabular}}{{{col_format}}}\n")
        f.write("\\hline\n")
        header_cells = ["{\\sc Category}"] + [
            f"{{\\sc {latex_escape(METHOD_ABBR.get(m, m))}}}"
            for m in DEFAULT_METHODS
        ]
        f.write(" & ".join(header_cells) + " \\\\\n")
        f.write("\\hline\\hline\n")
        for row in rows:
            cells = [latex_escape(row["category"])]
            for method in DEFAULT_METHODS:
                abbr = METHOD_ABBR.get(method, method)
                cells.append(latex_escape(row[abbr]))
            f.write(" & ".join(cells) + " \\\\\n")
        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\caption{Bug Detection Consistency Rate (detections / total experiments) per category by approach}\n")
        f.write("\\label{tab:detection_consistency}\n")
        f.write("\\end{table}\n")

    if verbose:
        print(f"[INFO] Wrote detection consistency TEX to {output_tex}")


def generate_cve_cwe_summary_table(bug_agg, bug_sites, fw_map, crashes_csv_path="analysis/crashes.csv",
                                     output_dir=".", verbose=False):
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

    bug_info = {}
    for (fw, bug_id, category, cve_id), method_dict in bug_agg.items():
        if cve_id and cve_id != '???':
            bug_identifier = cve_id
        else:
            bug_identifier = "likely 0-day"

        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        fw_display = name if name else fw

        sites = bug_sites.get((fw, bug_id, category, cve_id), set())

        methods_found = set()
        for method_name in method_dict:
            if method_dict[method_name]:
                methods_found.add(method_name)

        staff_found = "staff_state_aware" in methods_found
        other_methods_found = bool(methods_found - {"staff_state_aware"})

        if staff_found and not other_methods_found:
            discovery_status = "Only"
        elif staff_found:
            discovery_status = "Yes"
        else:
            discovery_status = "No"

        modules = set()
        functions = set()
        for module, func in sites:
            modules.add(module)
            functions.add(func)

        all_crash_seed_paths = []
        for method_name, exp_map in method_dict.items():
            for exp, data in exp_map.items():
                if data and "crash_seed_paths" in data:
                    all_crash_seed_paths.extend(data["crash_seed_paths"])

        min_requests = None
        succ_paths = [p for p in all_crash_seed_paths if p and p.endswith(".succ")]
        if succ_paths:
            for seed_path in succ_paths:
                num_req = count_requests_in_seed(seed_path)
                if num_req > 0:
                    if min_requests is None:
                        min_requests = num_req
                    else:
                        min_requests = min(min_requests, num_req)

        cwe_value = ''
        for module, func in sites:
            for (lookup_fw, lookup_mod, lookup_func), info in cve_cwe_lookup.items():
                fw_match = (lookup_fw in fw.lower() or fw.lower() in lookup_fw)
                mod_match = (lookup_mod == module.lower())
                func_match = (lookup_func == func.lower())

                if fw_match and mod_match and func_match:
                    if info['cwe']:
                        cwe_value = info['cwe']
                        break
            if cwe_value:
                break

        bug_key = (fw_display, bug_id, category)

        if bug_key not in bug_info:
            bug_info[bug_key] = {
                'firmware': fw_display,
                'firmware_path': fw,
                'module': ', '.join(sorted(modules)),
                'functions': ', '.join(sorted(functions)),
                'bug_id': bug_identifier,
                'category': category if category else '',
                'CVE': bug_identifier if bug_identifier != "likely 0-day" else '',
                'CWE': cwe_value,
                'min_requests': min_requests if min_requests is not None else '',
                'discovery_status': discovery_status
            }
        else:
            existing_funcs = set(bug_info[bug_key]['functions'].split(', '))
            existing_funcs.update(functions)
            bug_info[bug_key]['functions'] = ', '.join(sorted(existing_funcs))

            existing_mods = set(bug_info[bug_key]['module'].split(', '))
            existing_mods.update(modules)
            bug_info[bug_key]['module'] = ', '.join(sorted(existing_mods))

            if not bug_info[bug_key]['CWE'] and cwe_value:
                bug_info[bug_key]['CWE'] = cwe_value

            if min_requests is not None:
                if bug_info[bug_key]['min_requests'] == '':
                    bug_info[bug_key]['min_requests'] = min_requests
                else:
                    bug_info[bug_key]['min_requests'] = min(bug_info[bug_key]['min_requests'], min_requests)

    csv_firmware_order = get_firmware_order_from_csv(crashes_csv_path)

    fw_order_map = {}
    for idx, fw in enumerate(csv_firmware_order):
        fw_order_map[fw] = idx
        fw_order_map[os.path.basename(fw)] = idx

    def bug_sort_key(bug_dict):
        fw_path = bug_dict.get('firmware_path', '')
        fw_idx = fw_order_map.get(fw_path, 999999)
        if fw_idx == 999999:
            fw_idx = fw_order_map.get(os.path.basename(fw_path), 999999)
        return (fw_idx, str(bug_dict['bug_id']))

    sorted_bugs = sorted(bug_info.values(), key=bug_sort_key)

    cve_cwe_rows = []
    for idx, bug in enumerate(sorted_bugs):
        row = {
            '#': idx,
            'Firmware': bug['firmware'],
            'Category': bug['category'],
            'Binary': bug['module'],
            'Functions': bug['functions'],
            '# Min Reqs': bug['min_requests'],
            'CVE': bug['CVE'],
            'CWE': bug['CWE'],
            'STAFF Discovery': bug['discovery_status']
        }
        cve_cwe_rows.append(row)

    cve_cwe_csv = os.path.join(output_dir, "out_cve_cwe_summary.csv")
    cve_cwe_headers = ['#', 'Firmware', 'Category', 'Binary', 'Functions', '# Min Reqs', 'CVE', 'CWE', 'STAFF Discovery']

    with open(cve_cwe_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=cve_cwe_headers)
        writer.writeheader()
        writer.writerows(cve_cwe_rows)

    if verbose:
        print(f"[INFO] Wrote CVE/CWE summary to: {cve_cwe_csv}")

    cve_cwe_tex = os.path.join(output_dir, "out_cve_cwe_summary.tex")
    with open(cve_cwe_tex, 'w', encoding='utf-8') as f:
        f.write("\\begin{table*}[h]\n")
        f.write("\\centering\n")
        f.write("\\begin{tabular}{|c|l|l|l|l|c|l|l|l|}\n")
        f.write("\\hline\n")
        f.write("{\\sc \\#} & {\\sc Firmware} & {\\sc Category} & {\\sc Module} & {\\sc Functions} & {\\sc \\# Min Reqs} & {\\sc CVE} & {\\sc CWE} & {\\sc STAFF discovery} \\\\\n")
        f.write("\\hline\n")

        for row in cve_cwe_rows:
            def escape(s):
                s = str(s)
                s = s.replace('\\', '\\textbackslash{}')
                s = s.replace('&', '\\&')
                s = s.replace('%', '\\%')
                s = s.replace('$', '\\$')
                s = s.replace('#', '\\#')
                s = s.replace('_', '\\_')
                s = s.replace('{', '\\{')
                s = s.replace('}', '\\}')
                s = s.replace('~', '\\textasciitilde{}')
                s = s.replace('^', '\\textasciicircum{}')
                return s

            f.write(f"{row['#']} & {escape(row['Firmware'])} & {escape(row['Category'])} & {escape(row['Binary'])} & {escape(row['Functions'])} & ")
            f.write(f"{escape(row['# Min Reqs'])} & {escape(row['CVE'])} & {escape(row['CWE'])} & {escape(row['STAFF Discovery'])} \\\\\n")
            f.write("\\hline\n")

        f.write("\\end{tabular}\n")
        f.write("\\caption{CVE and CWE Summary}\n")
        f.write("\\end{table*}\n")

    if verbose:
        print(f"[INFO] Wrote LaTeX table to: {cve_cwe_tex}")

    return cve_cwe_rows


def generate_ablation_improvement_tables_per_firmware(agg, firmware_set, fw_map, baseline_method, variants, output_csv, output_tex, verbose=True):
    improvement_rows = []

    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        baseline_crashes = set()
        baseline_ttes = []
        for key, method_dict in agg.items():
            if len(key) >= 3 and key[0] == fw:
                baseline_entries = method_dict.get(baseline_method, {})
                if baseline_entries:
                    baseline_crashes.add(key)
                    for exp, data in baseline_entries.items():
                        tte = data.get("tte")
                        if tte is not None:
                            baseline_ttes.append(tte)

        baseline_crash_count = len(baseline_crashes)
        baseline_avg_tte = (sum(baseline_ttes) / len(baseline_ttes)) if baseline_ttes else None

        for variant in variants:
            variant_crashes = set()
            variant_ttes = []
            for key, method_dict in agg.items():
                if len(key) >= 3 and key[0] == fw:
                    variant_entries = method_dict.get(variant, {})
                    if variant_entries:
                        variant_crashes.add(key)
                        for exp, data in variant_entries.items():
                            tte = data.get("tte")
                            if tte is not None:
                                variant_ttes.append(tte)

            variant_crash_count = len(variant_crashes)
            variant_avg_tte = (sum(variant_ttes) / len(variant_ttes)) if variant_ttes else None

            if variant_crash_count > 0 and baseline_crash_count > 0:
                crash_improvement = ((baseline_crash_count - variant_crash_count) / variant_crash_count) * 100
                row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = f"{crash_improvement:+.2f}%"
            else:
                row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = "N/A"

            if baseline_avg_tte is not None and variant_avg_tte is not None and variant_avg_tte > 0:
                tte_improvement = ((variant_avg_tte - baseline_avg_tte) / variant_avg_tte) * 100
                row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = f"{tte_improvement:+.2f}%"
            else:
                row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = "N/A"

        improvement_rows.append(row)

    overall_row = {"firmware": "OVERALL"}

    baseline_all_crashes = set()
    baseline_all_ttes = []
    for key, method_dict in agg.items():
        baseline_entries = method_dict.get(baseline_method, {})
        if baseline_entries:
            baseline_all_crashes.add(key)
            for exp, data in baseline_entries.items():
                tte = data.get("tte")
                if tte is not None:
                    baseline_all_ttes.append(tte)

    baseline_total_crashes = len(baseline_all_crashes)
    baseline_overall_avg_tte = (sum(baseline_all_ttes) / len(baseline_all_ttes)) if baseline_all_ttes else None

    for variant in variants:
        variant_all_crashes = set()
        variant_all_ttes = []
        for key, method_dict in agg.items():
            variant_entries = method_dict.get(variant, {})
            if variant_entries:
                variant_all_crashes.add(key)
                for exp, data in variant_entries.items():
                    tte = data.get("tte")
                    if tte is not None:
                        variant_all_ttes.append(tte)

        variant_total_crashes = len(variant_all_crashes)
        variant_overall_avg_tte = (sum(variant_all_ttes) / len(variant_all_ttes)) if variant_all_ttes else None

        if variant_total_crashes > 0 and baseline_total_crashes > 0:
            crash_improvement = ((baseline_total_crashes - variant_total_crashes) / variant_total_crashes) * 100
            overall_row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = f"{crash_improvement:+.2f}%"
        else:
            overall_row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = "N/A"

        if baseline_overall_avg_tte is not None and variant_overall_avg_tte is not None and variant_overall_avg_tte > 0:
            tte_improvement = ((variant_overall_avg_tte - baseline_overall_avg_tte) / variant_overall_avg_tte) * 100
            overall_row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = f"{tte_improvement:+.2f}%"
        else:
            overall_row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = "N/A"

    improvement_rows.append(overall_row)

    improvement_headers = ["firmware"]
    for variant in variants:
        improvement_headers.append(f"{METHOD_ABBR.get(variant, variant)}_crash_impr")
        improvement_headers.append(f"{METHOD_ABBR.get(variant, variant)}_tte_impr")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=improvement_headers)
        writer.writeheader()
        writer.writerows(improvement_rows)

    if verbose:
        print(f"[INFO] Ablation improvements (per-firmware) written to: {output_csv}")

    baseline_abbr = METHOD_ABBR.get(baseline_method, baseline_method)
    with open(output_tex, "w", encoding="utf-8") as f:
        f.write(f"% Ablation Study: Performance Improvements (Per-Firmware) - Baseline: {baseline_abbr}\n")
        f.write("\\begin{table}[h]\n")
        f.write("\\centering\n")
        f.write(f"\\caption{{Ablation Study Performance Improvements (Per-Firmware, Baseline: {baseline_abbr})}}\n")
        f.write("\\begin{tabular}{l" + "rr" * len(variants) + "}\n")
        f.write("\\hline\n")

        header_parts = [r"{\sc Firmware}"]
        for variant in variants:
            abbr = METHOD_ABBR.get(variant, variant)
            header_parts.append(f"\\multicolumn{{{{2}}}}{{{{c}}}}{{{{\\sc {abbr}}}}}")
        f.write(" & ".join(header_parts) + " \\\\\n")

        subheader_parts = [""]
        for variant in variants:
            subheader_parts.append(r"{\sc Crash}")
            subheader_parts.append(r"{\sc TTE}")
        f.write(" & ".join(subheader_parts) + " \\\\\n")
        f.write("\\hline\n")

        for row in improvement_rows:
            parts = [row.get("firmware", "")]
            for variant in variants:
                abbr = METHOD_ABBR.get(variant, variant)
                parts.append(row.get(f"{abbr}_crash_impr", "N/A"))
                parts.append(row.get(f"{abbr}_tte_impr", "N/A"))
            f.write(" & ".join(parts) + " \\\\\n")

        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    if verbose:
        print(f"[INFO] Ablation improvements LaTeX (per-firmware) written to: {output_tex}")


def generate_ablation_improvement_tables_per_category(agg, baseline_method, variants, output_csv, output_tex, verbose=True):
    all_categories = set()
    for key, method_dict in agg.items():
        if len(key) >= 4:
            category = key[3] if len(key) >= 4 else None
            if category:
                all_categories.add(category)

    category_improvement_rows = []

    for category in sorted(all_categories):
        row = {"category": category}

        baseline_crashes = set()
        baseline_ttes = []
        for key, method_dict in agg.items():
            if len(key) >= 4 and key[3] == category:
                baseline_entries = method_dict.get(baseline_method, {})
                if baseline_entries:
                    baseline_crashes.add(key)
                    for exp, data in baseline_entries.items():
                        tte = data.get("tte")
                        if tte is not None:
                            baseline_ttes.append(tte)

        baseline_crash_count = len(baseline_crashes)
        baseline_avg_tte = (sum(baseline_ttes) / len(baseline_ttes)) if baseline_ttes else None

        for variant in variants:
            variant_crashes = set()
            variant_ttes = []
            for key, method_dict in agg.items():
                if len(key) >= 4 and key[3] == category:
                    variant_entries = method_dict.get(variant, {})
                    if variant_entries:
                        variant_crashes.add(key)
                        for exp, data in variant_entries.items():
                            tte = data.get("tte")
                            if tte is not None:
                                variant_ttes.append(tte)

            variant_crash_count = len(variant_crashes)
            variant_avg_tte = (sum(variant_ttes) / len(variant_ttes)) if variant_ttes else None

            if variant_crash_count > 0 and baseline_crash_count > 0:
                crash_improvement = ((baseline_crash_count - variant_crash_count) / variant_crash_count) * 100
                row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = f"{crash_improvement:+.2f}%"
            else:
                row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = "N/A"

            if baseline_avg_tte is not None and variant_avg_tte is not None and variant_avg_tte > 0:
                tte_improvement = ((variant_avg_tte - baseline_avg_tte) / variant_avg_tte) * 100
                row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = f"{tte_improvement:+.2f}%"
            else:
                row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = "N/A"

        category_improvement_rows.append(row)

    overall_category_row = {"category": "OVERALL"}

    baseline_all_crashes = set()
    baseline_all_ttes = []
    for key, method_dict in agg.items():
        baseline_entries = method_dict.get(baseline_method, {})
        if baseline_entries:
            baseline_all_crashes.add(key)
            for exp, data in baseline_entries.items():
                tte = data.get("tte")
                if tte is not None:
                    baseline_all_ttes.append(tte)

    baseline_total_crashes = len(baseline_all_crashes)
    baseline_overall_avg_tte = (sum(baseline_all_ttes) / len(baseline_all_ttes)) if baseline_all_ttes else None

    for variant in variants:
        variant_all_crashes = set()
        variant_all_ttes = []
        for key, method_dict in agg.items():
            variant_entries = method_dict.get(variant, {})
            if variant_entries:
                variant_all_crashes.add(key)
                for exp, data in variant_entries.items():
                    tte = data.get("tte")
                    if tte is not None:
                        variant_all_ttes.append(tte)

        variant_total_crashes = len(variant_all_crashes)
        variant_overall_avg_tte = (sum(variant_all_ttes) / len(variant_all_ttes)) if variant_all_ttes else None

        if variant_total_crashes > 0 and baseline_total_crashes > 0:
            crash_improvement = ((baseline_total_crashes - variant_total_crashes) / variant_total_crashes) * 100
            overall_category_row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = f"{crash_improvement:+.2f}%"
        else:
            overall_category_row[f"{METHOD_ABBR.get(variant, variant)}_crash_impr"] = "N/A"

        if baseline_overall_avg_tte is not None and variant_overall_avg_tte is not None and variant_overall_avg_tte > 0:
            tte_improvement = ((variant_overall_avg_tte - baseline_overall_avg_tte) / variant_overall_avg_tte) * 100
            overall_category_row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = f"{tte_improvement:+.2f}%"
        else:
            overall_category_row[f"{METHOD_ABBR.get(variant, variant)}_tte_impr"] = "N/A"

    category_improvement_rows.append(overall_category_row)

    category_improvement_headers = ["category"]
    for variant in variants:
        category_improvement_headers.append(f"{METHOD_ABBR.get(variant, variant)}_crash_impr")
        category_improvement_headers.append(f"{METHOD_ABBR.get(variant, variant)}_tte_impr")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=category_improvement_headers)
        writer.writeheader()
        writer.writerows(category_improvement_rows)

    if verbose:
        print(f"[INFO] Ablation improvements (per-category) written to: {output_csv}")

    baseline_abbr = METHOD_ABBR.get(baseline_method, baseline_method)
    with open(output_tex, "w", encoding="utf-8") as f:
        f.write(f"% Ablation Study: Performance Improvements (Per-Category) - Baseline: {baseline_abbr}\n")
        f.write("\\begin{table}[h]\n")
        f.write("\\centering\n")
        f.write(f"\\caption{{Ablation Study Performance Improvements (Per-Category, Baseline: {baseline_abbr})}}\n")
        f.write("\\begin{tabular}{l" + "rr" * len(variants) + "}\n")
        f.write("\\hline\n")

        header_parts = [r"{\sc Category}"]
        for variant in variants:
            abbr = METHOD_ABBR.get(variant, variant)
            header_parts.append(f"\\multicolumn{{{{2}}}}{{{{c}}}}{{{{\\sc {abbr}}}}}")
        f.write(" & ".join(header_parts) + " \\\\\n")

        subheader_parts = [""]
        for variant in variants:
            subheader_parts.append(r"{\sc Crash}")
            subheader_parts.append(r"{\sc TTE}")
        f.write(" & ".join(subheader_parts) + " \\\\\n")
        f.write("\\hline\n")

        for row in category_improvement_rows:
            parts = [row.get("category", "")]
            for variant in variants:
                abbr = METHOD_ABBR.get(variant, variant)
                parts.append(row.get(f"{abbr}_crash_impr", "N/A"))
                parts.append(row.get(f"{abbr}_tte_impr", "N/A"))
            f.write(" & ".join(parts) + " \\\\\n")

        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    if verbose:
        print(f"[INFO] Ablation improvements LaTeX (per-category) written to: {output_tex}")


def generate_ablation_tables(pc_ranges, experiments_dir, experiments_ablation_dir, extracted_root, out_causality_csv=None, out_causality_tex=None, out_tte_csv=None, out_tte_tex=None, out_count_tex=None, out_count_csv=None, show_exp_count=False, extracted_ablation_root=None, firmwares_csv="analysis/fw_names.csv", include_zero_crashes=False, output_dir=".", verbose=True):
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

    agg_raw = build_agg_from_extracted_ablation(extracted_ablation_root=extracted_ablation_root, verbose=verbose)

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
                if len(tpl) == 6:
                    start, end, category, cve_id, bug_id, min_reqs = tpl
                elif len(tpl) == 5:
                    start, end, category, cve_id, bug_id = tpl
                    min_reqs = 0
                elif len(tpl) == 4:
                    start, end, category, cve_id = tpl
                    bug_id = None
                    min_reqs = 0
                elif len(tpl) == 3:
                    start, end, category = tpl
                    cve_id = None
                    bug_id = None
                    min_reqs = 0
                else:
                    start, end = tpl
                    category = None
                    cve_id = None
                    bug_id = None
                    min_reqs = 0
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
        return (fw_name_only, method, module) in SKIP_MODULES or (fw_name_only, "any", module) in SKIP_MODULES or ("any", method, "any") in SKIP_MODULES or ("any", "any", module) in SKIP_MODULES

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

    # ---------- Ablation Tables: Number of crashes ----------
    suffix = "_ablation"
    out_count_csv_ablation = out_count_csv.replace(".csv", f"{suffix}.csv")
    out_count_tex_ablation = out_count_tex.replace(".tex", f"{suffix}.tex")

    baseline_method = "NoOpt"
    ablation_methods = ABLATION_VARIANTS

    table1_ablation_rows = []

    for fw in firmware_set:
        fw_name_only = os.path.basename(fw)
        brand, name, version = fw_map.get(fw_name_only, ("", fw_name_only, ""))
        row = {"firmware": name}

        for m in ablation_methods:
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

        table1_ablation_rows.append(row)

    headers1_ablation = ["firmware"]
    for m in ablation_methods:
        headers1_ablation.append(f"{METHOD_ABBR.get(m, m)}_mean_cnt")
        if show_exp_count:
            headers1_ablation.append(f"{METHOD_ABBR.get(m, m)}_exp_cnt")

    write_csv_and_latex(headers1_ablation, table1_ablation_rows, out_count_csv_ablation, out_count_tex_ablation, caption="Number of crashes (Ablation)")

    out_count_improvements_csv = out_count_csv_ablation.replace(".csv", "_improvements_per_firmware.csv")
    out_count_improvements_tex = out_count_csv_ablation.replace(".csv", "_improvements_per_firmware.tex")

    generate_ablation_improvement_tables_per_firmware(
        agg=agg,
        firmware_set=firmware_set,
        fw_map=fw_map,
        baseline_method=baseline_method,
        variants=ABLATION_VARIANTS,
        output_csv=out_count_improvements_csv,
        output_tex=out_count_improvements_tex,
        verbose=verbose
    )

    out_count_improvements_per_category_csv = out_count_improvements_csv.replace("_per_firmware.csv", "_per_category.csv")
    out_count_improvements_per_category_tex = out_count_improvements_csv.replace("_per_firmware.csv", "_per_category.tex")

    generate_ablation_improvement_tables_per_category(
        agg=agg,
        baseline_method=baseline_method,
        variants=ABLATION_VARIANTS,
        output_csv=out_count_improvements_per_category_csv,
        output_tex=out_count_improvements_per_category_tex,
        verbose=verbose
    )

    # ---------- Ablation Tables: TTE ----------
    out_tte_csv_ablation = out_tte_csv.replace(".csv", f"{suffix}.csv")
    out_tte_tex_ablation = out_tte_tex.replace(".tex", f"{suffix}.tex")

    fw_order_map = {fw: idx for idx, fw in enumerate(csv_firmware_order)}
    def crash_sort_key(item):
        key = item[0]
        fw = key[0]
        fw_idx = fw_order_map.get(fw, 999999)
        return (fw_idx, key[1], str(key[2]))

    table2_ablation_rows = []

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
        for m in ablation_methods:
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

            # Calculate taint causality: fraction of experiments where taint > 0
            taint_causality = None
            if taints:
                causality_scores = [1.0 if t > 0 else 0.0 for t in taints]
                taint_causality = sum(causality_scores) / len(causality_scores)

            row[f"{METHOD_ABBR.get(m, m)}_avg_tte"] = format_time_hm(avg_tte) if avg_tte is not None else ""
            row[f"{METHOD_ABBR.get(m, m)}_avg_taint"] = (round(avg_taint, 3) if avg_taint is not None else "")
            #row[f"{METHOD_ABBR.get(m, m)}_taint_causality"] = (round(taint_causality, 3) if taint_causality is not None else "")

        num_requests = 0
        succ_paths = [p for p in all_crash_seed_paths if p and p.endswith(".succ")]

        if succ_paths:
            num_requests = count_requests_in_seed(succ_paths[0])
        row["num_requests"] = num_requests if num_requests > 0 else ""

        table2_ablation_rows.append(row)

    headers2_ablation = ["firmware", "module", "function", "category", "cve_id", "num_requests"]
    for m in ablation_methods:
        headers2_ablation.append(f"{METHOD_ABBR.get(m, m)}_cnt")
        headers2_ablation.append(f"{METHOD_ABBR.get(m, m)}_avg_tte")
        #headers2_ablation.append(f"{METHOD_ABBR.get(m, m)}_taint_causality")

    write_csv_and_latex(headers2_ablation, table2_ablation_rows, out_tte_csv_ablation, out_tte_tex_ablation, caption="TTE crashes (Ablation)", count_tte_table=True, add_category_col=True, add_taint_col=True)

    # ---------- Ablation Performance Improvements (Percentage) ----------
    out_ablation_improvements_csv = out_tte_csv_ablation.replace(".csv", "_improvements.csv")
    out_ablation_improvements_tex = out_ablation_improvements_csv.replace(".csv", ".tex")

    generate_ablation_improvement_tables_per_firmware(
        agg=agg,
        firmware_set=firmware_set,
        fw_map=fw_map,
        baseline_method=baseline_method,
        variants=ABLATION_VARIANTS,
        output_csv=out_ablation_improvements_csv,
        output_tex=out_ablation_improvements_tex,
        verbose=verbose
    )

    # ---------- Per-Category Improvements ----------
    out_ablation_improvements_per_category_csv = out_ablation_improvements_csv.replace(".csv", "_per_category.csv")
    out_ablation_improvements_per_category_tex = out_ablation_improvements_csv.replace(".csv", "_per_category.tex")

    generate_ablation_improvement_tables_per_category(
        agg=agg,
        baseline_method=baseline_method,
        variants=ABLATION_VARIANTS,
        output_csv=out_ablation_improvements_per_category_csv,
        output_tex=out_ablation_improvements_per_category_tex,
        verbose=verbose
    )

    # ---------- Ablation Aggregated Statistics ----------
    out_ablation_stats_csv = out_count_csv.replace(".csv", f"{suffix}_stats.csv")
    out_ablation_stats_tex = out_count_tex.replace(".tex", f"{suffix}_stats.tex")

    stats_rows = []

    for m in ablation_methods:
        unique_crashes = set()
        all_ttes = []

        for key, method_dict in agg.items():
            entries = method_dict.get(m, {})
            if entries:
                unique_crashes.add(key)
                for exp, data in entries.items():
                    tte = data.get("tte")
                    if tte is not None:
                        all_ttes.append(tte)

        avg_tte_seconds = (sum(all_ttes) / len(all_ttes)) if all_ttes else None

        stats_rows.append({
            "method": METHOD_ABBR.get(m, m),
            "total_unique_crashes": len(unique_crashes),
            "avg_tte_seconds": avg_tte_seconds,
            "avg_tte_formatted": format_time_hm(avg_tte_seconds) if avg_tte_seconds is not None else "N/A"
        })

    comparison_rows = []

    if stats_rows:
        baseline = stats_rows[0]
        baseline_crashes = baseline["total_unique_crashes"]
        baseline_tte = baseline["avg_tte_seconds"]

        for i, variant_stats in enumerate(stats_rows[1:], start=1):
            variant_name = variant_stats["method"]
            variant_crashes = variant_stats["total_unique_crashes"]
            variant_tte = variant_stats["avg_tte_seconds"]

            crash_improvement = 0.0
            if variant_crashes > 0:
                crash_improvement = ((baseline_crashes - variant_crashes) / variant_crashes) * 100

            tte_improvement = 0.0
            if baseline_tte is not None and variant_tte is not None and variant_tte > 0:
                tte_improvement = ((variant_tte - baseline_tte) / variant_tte) * 100

            comparison_rows.append({
                "comparison": f"FullOpt vs {variant_name}",
                "crash_difference": baseline_crashes - variant_crashes,
                "crash_improvement_pct": round(crash_improvement, 2),
                "tte_improvement_pct": round(tte_improvement, 2) if baseline_tte is not None and variant_tte is not None else "N/A",
                "fullopt_crashes": baseline_crashes,
                "variant_crashes": variant_crashes,
                "fullopt_avg_tte": baseline["avg_tte_formatted"],
                "variant_avg_tte": variant_stats["avg_tte_formatted"]
            })

    stats_headers = ["method", "total_unique_crashes", "avg_tte_seconds", "avg_tte_formatted"]
    comparison_headers = ["comparison", "crash_difference", "crash_improvement_pct", "tte_improvement_pct",
                         "fullopt_crashes", "variant_crashes", "fullopt_avg_tte", "variant_avg_tte"]

    with open(out_ablation_stats_csv, "w", newline="", encoding="utf-8") as f:
        f.write("# Ablation Study: Method Statistics\n")
        writer = csv.DictWriter(f, fieldnames=stats_headers)
        writer.writeheader()
        writer.writerows(stats_rows)

        f.write("\n# Ablation Study: FullOpt vs Variants Comparison\n")
        writer2 = csv.DictWriter(f, fieldnames=comparison_headers)
        writer2.writeheader()
        writer2.writerows(comparison_rows)

    if verbose:
        print(f"[INFO] Ablation aggregated statistics written to: {out_ablation_stats_csv}")

    with open(out_ablation_stats_tex, "w", encoding="utf-8") as f:
        f.write("% Ablation Study: FullOpt vs Variants Comparison\n")
        f.write("\\begin{table}[h]\n")
        f.write("\\centering\n")
        f.write("\\caption{Ablation Study: Performance Comparison}\n")
        f.write("\\begin{tabular}{lrrrr}\n")
        f.write("\\hline\n")
        f.write("{\\sc Comparison} & {\\sc Crash Diff} & {\\sc Crash Impr.} & {\\sc TTE Impr.} & {\\sc FullOpt Avg TTE} \\\\\n")
        f.write("\\hline\n")

        for row in comparison_rows:
            comparison = row["comparison"].replace("_", "\\_")
            crash_diff = row["crash_difference"]
            crash_impr = row["crash_improvement_pct"]
            tte_impr = row["tte_improvement_pct"]
            fullopt_tte = row["fullopt_avg_tte"]

            tte_impr_str = f"{tte_impr}\\%" if isinstance(tte_impr, (int, float)) else tte_impr
            f.write(f"{comparison} & {crash_diff:+d} & {crash_impr:+.1f}\\% & {tte_impr_str} & {fullopt_tte} \\\\\n")

        f.write("\\hline\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table}\n")

    if verbose:
        print(f"[INFO] Ablation aggregated statistics LaTeX written to: {out_ablation_stats_tex}")


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
                        help="Extract all crash seeds and traces per firmware/module/function to OUTPUT_DIR and OUTPUT_DIR_traces (for fallback during crash_analysis)")
    parser.add_argument("--output-dir", default="analysis_results",
                        help="Directory to write analysis results (CSV and LaTeX files). Default: analysis_results")
    parser.add_argument("--extracted_root_ablation", default=None,
                        help="Separate extraction directory for ablation experiments (to avoid exp_N naming collisions)")
    parser.add_argument("--max-exp-ablation", type=int, default=None,
                        help="Maximum ablation experiment number to consider (similar to --max-exp but for ablation experiments)")

    args = parser.parse_args()
    verbose = not args.quiet

    OUTPUT_DIR = args.output_dir
    if verbose:
        print(f"[INFO] Output directory: {OUTPUT_DIR}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    MAX_EXP_NUM = args.max_exp
    if MAX_EXP_NUM is not None and verbose:
        print(f"[INFO] Filtering experiments: only considering exp_1 through exp_{MAX_EXP_NUM}")

    MAX_EXP_ABLATION_NUM = args.max_exp_ablation
    if MAX_EXP_ABLATION_NUM is not None and verbose:
        print(f"[INFO] Filtering ablation experiments: only considering exp_1 through exp_{MAX_EXP_ABLATION_NUM}")

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

    try:
        unify_crash_and_trace_filenames()
    except Exception as e:
        if verbose:
            print(f"[WARN] Error during unify_crash_and_trace_filenames: {e}")

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

    experiments_ablation_dir = os.path.join(os.path.dirname(args.experiments_dir), "experiments_ablation")
    extracted_ablation_root = None

    if os.path.isdir(experiments_ablation_dir):
        if verbose:
            print(f"\n[INFO] Found experiments_ablation directory: {experiments_ablation_dir}")

        if args.extracted_root_ablation:
            extracted_ablation_root = args.extracted_root_ablation
            if verbose:
                print(f"[INFO] Using specified ablation extraction directory: {extracted_ablation_root}")
        else:
            extracted_ablation_root = args.extracted_root.replace("extracted_crashes", "extracted_crashes_ablation")
            if verbose:
                print(f"[INFO] Auto-detected ablation extraction directory: {extracted_ablation_root}")

        if args.update:
            if verbose:
                print(f"\n[INFO] Updating ablation extraction directory from {experiments_ablation_dir}...")
            update_extracted_root_from_ablation_experiments(experiments_ablation_dir, extracted_ablation_root=extracted_ablation_root, verbose=verbose)
            count_and_log_crash_seeds(extracted_root=extracted_ablation_root, verbose=verbose)
        else:
            if verbose:
                print("[INFO] Skipping ablation copy step (--update not specified)")

        if args.annotate:
            if verbose:
                print(f"\n[INFO] Annotating ablation crashes with TTE...")
            annotate_extracted_ablation_with_tte(experiments_ablation_dir, extracted_ablation_root=extracted_ablation_root, verbose=verbose)
        else:
            if verbose:
                print("[INFO] Skipping ablation annotation step (--annotate not specified)")
    else:
        if verbose:
            print(f"\n[INFO] No experiments_ablation directory found at {experiments_ablation_dir}, skipping ablation extraction")

    tables, agg = build_crash_level_tables(
        extracted_root=args.extracted_root,
        verbose=True,
        show_exp_count=args.show_exp_count,
        experiments_dir=args.experiments_dir,
        include_zero_crashes=args.include_zero_crashes
    )

    bug_tables, bug_agg, bug_sites, bug_min_reqs = build_bug_level_tables(
        extracted_root=args.extracted_root,
        firmwares_csv="analysis/fw_names.csv",
        verbose=True,
        show_exp_count=args.show_exp_count,
        experiments_dir=args.experiments_dir,
        include_zero_bugs=args.include_zero_crashes,
    )

    generate_bugs_per_category_by_approach_table(
        bug_agg=bug_agg,
        output_dir=OUTPUT_DIR,
        verbose=True
    )

    generate_detection_consistency_table(
        bug_agg=bug_agg,
        experiments_dir=args.experiments_dir,
        output_dir=OUTPUT_DIR,
        verbose=True
    )

    def load_firmware_map_triplet(path):
        mapping = {}
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fw_file = row.get("firmware", "").strip()
                brand = row.get("brand", "").strip()
                name = row.get("name", "").strip()
                version = row.get("version", "").strip()
                mapping[fw_file] = (brand, name, version)
        return mapping

    fw_map = load_firmware_map_triplet("analysis/fw_names.csv")

    generate_cve_cwe_summary_table(
        bug_agg=bug_agg,
        bug_sites=bug_sites,
        fw_map=fw_map,
        crashes_csv_path="analysis/crashes.csv",
        output_dir=OUTPUT_DIR,
        verbose=True
    )

    if verbose:
        print("\n[INFO] Building executions per minute and total executions comparison tables...")
    execs_rate_data, execs_total_data = build_execs_per_sec_table(
        experiments_dir=args.experiments_dir,
        methods=DEFAULT_METHODS,
        verbose=verbose
    )
    write_execs_per_sec_tables(
        execs_data=execs_rate_data,
        methods=DEFAULT_METHODS,
        output_dir=OUTPUT_DIR,
        output_prefix="out_execs_per_min"
    )
    write_total_execs_tables(
        execs_data=execs_total_data,
        methods=DEFAULT_METHODS,
        output_dir=OUTPUT_DIR,
        output_prefix="out_total_execs"
    )

    chmod_recursive(args.extracted_root, 0o777)
    if extracted_ablation_root is not None and os.path.isdir(extracted_ablation_root):
        chmod_recursive(extracted_ablation_root, 0o777)

    if extracted_ablation_root is not None:
        if verbose:
            print(f"\n[INFO] Generating ablation study tables...")

        try:
            generate_ablation_tables(
                pc_ranges=PC_RANGES,
                experiments_dir=args.experiments_dir,
                experiments_ablation_dir=experiments_ablation_dir,
                extracted_root=args.extracted_root,
                extracted_ablation_root=extracted_ablation_root,
                output_dir=OUTPUT_DIR,
                verbose=verbose
            )
        except Exception as e:
            print(f"[WARN] Error generating ablation tables: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
    else:
        if verbose:
            print(f"[INFO] No experiments_ablation directory found at {experiments_ablation_dir}, skipping ablation study")


    if args.extract_unique:
        extract_unique_crashes_per_function(
            extracted_root=args.extracted_root,
            output_dir=args.extract_unique,
            verbose=verbose,
            require_succ=REQUIRE_SUCC_FLAG
        )

    chmod_recursive(args.extract_unique, 0o777)

    # print_seed_status_statistics(extracted_root=args.extracted_root, verbose=verbose)

    # print_unprocessed_seed_paths(extracted_root=args.extracted_root)

