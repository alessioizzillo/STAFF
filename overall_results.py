#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd
from scipy.stats import mannwhitneyu

BASE_DIRS = ["experiments_done/baseline", "experiments"]
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TOOLS = ["aflnet_base", "aflnet_state_aware", "staff_base", "staff_state_aware", "triforce"]
TOOL_RANK = {
    "aflnet_base": -1,
    "aflnet_state_aware": -2,
    "triforce": -3,
    "staff_base": 1,
    "staff_state_aware": 2,
}

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total", "paths_favored", "execs_done"]
BASELINE_TOOLS = ["aflnet_base", "aflnet_state_aware", "triforce"]

BASELINE_EXPERIMENTS = "0,1,2,5,6,7,10,11,12,15,16,17,20,21,22,25,26,27,"
STAFF_EDGE = "3,4,8,9,13,14,18,19,23,24,28,29"
STAFF_TAINT_BLOCK = "42-53"
# INCLUDE_EXPERIMENTS = BASELINE_EXPERIMENTS + STAFF_TAINT_BLOCK
INCLUDE_EXPERIMENTS = None

def effect_size_a12(x, y):
    n_x = len(x)
    n_y = len(y)
    ranks = pd.Series(x + y).rank()
    r_x = ranks.iloc[:n_x].sum()

    return (r_x / n_x - (n_x + 1) / 2) / n_y

def parse_range_list(skip_str):
    include_set = set()
    for part in skip_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            include_set.update(range(start, end + 1))
        elif part.strip():
            include_set.add(int(part))
    return include_set

def parse_fuzzer_stats(path, fallback_path=None, force_time_fallback=False):
    data = {}
    start_time = None
    last_update = None

    def load_times_from(p):
        nonlocal start_time, last_update
        if not os.path.exists(p):
            return 1
        with open(p) as f:
            for line in f:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip().rstrip('%')
                if key == "start_time":
                    try:
                        start_time = int(val)
                    except ValueError:
                        pass
                elif key == "last_update":
                    try:
                        last_update = int(val)
                    except ValueError:
                        pass
        return 0

    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().rstrip('%')
            try:
                if key == "start_time":
                    start_time = int(val)
                elif key == "last_update":
                    last_update = int(val)
                elif key in METRICS:
                    data[key] = float(val)
            except ValueError:
                pass

    if force_time_fallback and fallback_path:
        if (load_times_from(fallback_path)):
            return None

    if start_time and last_update:
        data["run_time"] = float(last_update - start_time)
    else:
        data["run_time"] = 0.0

    return data

agg = defaultdict(lambda: defaultdict(list))
valid_experiments = 0
firmwares = set()
include_set = None

if INCLUDE_EXPERIMENTS:
    include_set = parse_range_list(INCLUDE_EXPERIMENTS)

all_exp_dirs = []
for base in BASE_DIRS:
    all_exp_dirs.extend(glob.glob(os.path.join(base, "exp_*")))
for exp_dir in sorted(all_exp_dirs):
    exp_name = os.path.basename(exp_dir)
    try:
        exp_id = int(exp_name.split("_")[1])
        if include_set and exp_id not in include_set:
            continue
    except (IndexError, ValueError):
        continue

    cfg_path = os.path.join(exp_dir, "outputs", "config.ini")
    stats_path = os.path.join(exp_dir, "outputs", "fuzzer_stats")
    plotf = os.path.join(exp_dir, "outputs", "plot_data")

    if not os.path.isfile(cfg_path) or not os.path.isfile(stats_path):
        continue

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    if "GENERAL" not in cfg or "firmware" not in cfg["GENERAL"] or "mode" not in cfg["GENERAL"]:
        continue

    firmware = cfg["GENERAL"]["firmware"]
    mode = cfg["GENERAL"]["mode"]

    if mode not in TOOLS:
        continue

    old_stats = os.path.join(exp_dir, "outputs", "old_fuzzer_stats") if mode == "triforce" else None
    stats = parse_fuzzer_stats(stats_path, fallback_path=old_stats, force_time_fallback=(mode == "triforce"))
    if not stats or stats.get("execs_done", 0) <= 0:
        continue

    if (mode == "triforce"):
        dfp = pd.read_csv(plotf, comment="#", 
                        names=["unix_time","paths_total","map_size","unique_crashes",
                        "unique_hangs","stability","n_calibration"])
    else:
        dfp = pd.read_csv(plotf, comment="#", 
                        names=["unix_time","cycles_done","execs_done","cur_path",
                                "paths_total","pending_total","pending_favs",
                                "map_size","unique_crashes","unique_hangs",
                                "max_depth","execs_per_sec","stability",
                                "n_fetched_random_hints","n_fetched_state_hints",
                                "n_fetched_taint_hints","n_calibration"])

    dfp["map_size"] = dfp["map_size"].str.rstrip("%").astype(float)
    series = dfp["map_size"].tolist()

    valid_experiments += 1
    firmwares.add(firmware)
    key = (firmware, mode)
    for m in METRICS + ["run_time"]:
        agg[key][m].append(stats.get(m, 0.0))

if not valid_experiments:
    exit(1)

rows = []

headers = ["winner", "Firmware", "Mode", "num_experiments"] + [f"{m}_avg" for m in METRICS] + ["run_time_avg"]

for firmware in sorted(firmwares):
    rows.append({h: "" for h in headers})
    tool_rows = {}
    baseline_scores = []

    for tool in TOOLS:
        key = (firmware, tool)
        metrics = agg.get(key, {})
        vals = metrics.get("bitmap_cvg", [])

        row = {"Firmware": firmware, "Mode": tool}
        row["num_experiments"] = len(vals)

        for m in METRICS:
            vlist = metrics.get(m, [])
            avg = sum(vlist) / len(vlist) if vlist else 0.0
            row[f"{m}_avg"] = round(avg, 4) if m == "bitmap_cvg" else int(round(avg))

        runtimes = metrics.get("run_time", [])
        row["run_time_avg"] = int(round(sum(runtimes)/len(runtimes))) if runtimes else 0

        tool_rows[tool] = row

        if tool in BASELINE_TOOLS:
            baseline_scores.append((
                tool,
                row.get("unique_crashes_avg", 0),
                row.get("bitmap_cvg_avg", 0.0)
            ))

    if not baseline_scores:
        continue

    baseline_scores.sort(key=lambda x: (x[1], x[2]), reverse=True)
    best_baseline_tool = baseline_scores[0][0]
    best_baseline_vals_cvg = agg.get((firmware, best_baseline_tool), {}).get("bitmap_cvg", [])
    best_baseline_vals_crashes = agg.get((firmware, best_baseline_tool), {}).get("unique_crashes", [])

    def score(tool):
        r = tool_rows[tool]
        return (
            r.get("unique_crashes_avg", 0),
            r.get("bitmap_cvg_avg", 0),
            TOOL_RANK.get(tool, 0)
        )

    scores = {t: score(t) for t in tool_rows}
    max_crashes = max(s[0] for s in scores.values())
    tied_on_crashes = [t for t, s in scores.items() if s[0] == max_crashes]

    max_bitmap = max(scores[t][1] for t in tied_on_crashes)
    tied_finalists = [t for t in tied_on_crashes if scores[t][1] == max_bitmap]

    legacy = [t for t in BASELINE_TOOLS if t in tool_rows]
    staff = [t for t in ["staff_base", "staff_state_aware"] if t in tool_rows]

    best_legacy = max((tool_rows[t] for t in legacy), key=lambda r: r.get("bitmap_cvg_avg", 0), default=None)
    best_staff = max((tool_rows[t] for t in staff), key=lambda r: r.get("bitmap_cvg_avg", 0), default=None)

    abs_diff = abs(best_legacy["bitmap_cvg_avg"] - best_staff["bitmap_cvg_avg"]) if best_legacy and best_staff else 0
    rel_diff = abs_diff / max(best_legacy["bitmap_cvg_avg"], 1e-6) if best_legacy and best_staff else 0

    legacy_crashes = max((tool_rows[t]["unique_crashes_avg"] for t in legacy), default=0)
    staff_crashes = max((tool_rows[t]["unique_crashes_avg"] for t in staff), default=0)

    if legacy_crashes == staff_crashes and rel_diff < 0.05:
        winner_rank = 0
    elif len(tied_finalists) > 1 and any(TOOL_RANK[t] > 0 for t in tied_finalists) and any(TOOL_RANK[t] < 0 for t in tied_finalists):
        winner_rank = 0
    else:
        winner_tool = max(tied_finalists, key=lambda t: TOOL_RANK.get(t, 0))
        winner_rank = TOOL_RANK.get(winner_tool, 0)

    for tool, row in tool_rows.items():
        row["winner"] = winner_rank
        row["best_baseline"] = best_baseline_tool

        vals = agg.get((firmware, tool), {}).get("bitmap_cvg", [])
        if vals and best_baseline_vals_cvg:
            row["bitmap_cvg_p_value_with_best"] = round(mannwhitneyu(vals, best_baseline_vals_cvg, alternative='two-sided').pvalue, 4)
            row["bitmap_cvg_A12_with_best"] = round(effect_size_a12(vals, best_baseline_vals_cvg), 4)
        else:
            row["bitmap_cvg_p_value_with_best"] = None
            row["bitmap_cvg_A12_with_best"] = None

        vals_crashes = agg.get((firmware, tool), {}).get("unique_crashes", [])
        if vals_crashes and best_baseline_vals_crashes:
            row["unique_crashes_p_value_with_best"] = round(mannwhitneyu(vals_crashes, best_baseline_vals_crashes, alternative='two-sided').pvalue, 4)
            row["unique_crashes_A12_with_best"] = round(effect_size_a12(vals_crashes, best_baseline_vals_crashes), 4)
        else:
            row["unique_crashes_p_value_with_best"] = None
            row["unique_crashes_A12_with_best"] = None

        reordered = {
            "winner": row["winner"],
            "Firmware": row["Firmware"],
            "Mode": row["Mode"],
            "num_experiments": row["num_experiments"],
            "best_baseline": row["best_baseline"],
            "bitmap_cvg_p_value_with_best": row["bitmap_cvg_p_value_with_best"],
            "bitmap_cvg_A12_with_best": row["bitmap_cvg_A12_with_best"],
            "unique_crashes_p_value_with_best": row["unique_crashes_p_value_with_best"],
            "unique_crashes_A12_with_best": row["unique_crashes_A12_with_best"],
        }
        reordered.update({k: v for k, v in row.items() if k not in reordered})
        rows.append(reordered)

df_fw_mode = pd.DataFrame(rows)

out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)

rows = []
for mode, group in df_fw_mode[df_fw_mode["Firmware"] != ""].groupby("Mode"):
    row = {"Mode": mode}
    for m in METRICS:
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(group[f"{m}_avg"].astype(float).mean(), 4)
        else:
            row[f"{m}_sum"] = int(group[f"{m}_avg"].astype(float).sum())
    row["run_time_avg"] = int(round(group["run_time_avg"].astype(float).mean()))
    row["total_experiments"] = int(group["num_experiments"].astype(int).sum())
    rows.append(row)

df_mode = pd.DataFrame(rows).sort_values("Mode")
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)

print("\nPer-Firmware/Mode Averages:")
print(df_fw_mode)

print("\nPer-Mode Aggregated Totals:")
print(df_mode)