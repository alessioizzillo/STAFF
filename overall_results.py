#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd

BASE_DIR = "experiments"
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

def parse_fuzzer_stats(path):
    data = {}
    start_time = None
    last_update = None

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

    if start_time and last_update:
        data["run_time"] = float(last_update - start_time)
    else:
        data["run_time"] = 0.0

    return data

agg = defaultdict(lambda: defaultdict(list))
valid_experiments = 0
firmwares = set()

for exp_dir in sorted(glob.glob(os.path.join(BASE_DIR, "exp_*"))):
    cfg_path = os.path.join(exp_dir, "outputs", "config.ini")
    stats_path = os.path.join(exp_dir, "outputs", "fuzzer_stats")

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

    stats = parse_fuzzer_stats(stats_path)
    if stats.get("execs_done", 0.0) <= 0:
        continue

    valid_experiments += 1
    firmwares.add(firmware)
    key = (firmware, mode)
    for m in METRICS + ["run_time"]:
        agg[key][m].append(stats.get(m, 0.0))

if not valid_experiments:
    exit(1)

# Build firmware-mode table with winner logic and tool rows
rows = []

# Add one initial empty row after header
empty_template = {"winner": "", "Firmware": "", "Mode": ""}
empty_template.update({f"{m}_avg": "" for m in METRICS})
empty_template["run_time_avg"] = ""
rows.append(empty_template)

for firmware in sorted(firmwares):
    tool_rows = {}
    for tool in TOOLS:
        key = (firmware, tool)
        row = {"Firmware": firmware, "Mode": tool}

        if key in agg:
            metrics = agg[key]
            for m in METRICS:
                vals = metrics[m]
                avg_val = sum(vals) / len(vals) if vals else 0.0
                row[f"{m}_avg"] = round(avg_val, 4) if m == "bitmap_cvg" else int(round(avg_val))
            row["run_time_avg"] = int(round(sum(metrics["run_time"]) / len(metrics["run_time"])))
        else:
            for m in METRICS:
                row[f"{m}_avg"] = 0 if m != "bitmap_cvg" else 0.0
            row["run_time_avg"] = 0

        tool_rows[tool] = row

    # Determine winner with tie-breaking logic
    def score(tool):
        r = tool_rows[tool]
        return (
            r["unique_crashes_avg"],
            r["bitmap_cvg_avg"],
            TOOL_RANK[tool]
        )

    scores = {tool: score(tool) for tool in TOOLS}
    max_crashes = max(s[0] for s in scores.values())
    tied_on_crashes = [t for t, s in scores.items() if s[0] == max_crashes]

    max_bitmap = max(scores[t][1] for t in tied_on_crashes)
    tied_finalists = [t for t in tied_on_crashes if scores[t][1] == max_bitmap]

    positive = any(TOOL_RANK[t] > 0 for t in tied_finalists)
    negative = any(TOOL_RANK[t] < 0 for t in tied_finalists)

    if len(tied_finalists) > 1 and positive and negative:
        winner_rank = 0
    else:
        winner_tool = max(tied_finalists, key=lambda t: TOOL_RANK[t])
        winner_rank = TOOL_RANK[winner_tool]

    for tool in TOOLS:
        row = tool_rows[tool]
        row["winner"] = winner_rank
        reordered = {"winner": row["winner"], "Firmware": row["Firmware"], "Mode": row["Mode"]}
        reordered.update({k: v for k, v in row.items() if k not in reordered})
        rows.append(reordered)

    # Add empty row to separate firmware blocks
    rows.append({k: "" for k in rows[-1].keys()})

df_fw_mode = pd.DataFrame(rows)

out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)

# Per-mode aggregate table
rows = []
for mode, group in df_fw_mode[df_fw_mode["Firmware"] != ""].groupby("Mode"):
    row = {"Mode": mode}
    for m in METRICS:
        if m == "bitmap_cvg":
            row[f"{m}_avg"] = round(group[f"{m}_avg"].astype(float).mean(), 4)
        else:
            row[f"{m}_sum"] = int(group[f"{m}_avg"].astype(float).sum())
    row["run_time_avg"] = int(round(group["run_time_avg"].astype(float).mean()))
    rows.append(row)

df_mode = pd.DataFrame(rows).sort_values("Mode")
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)

print("\nPer-Firmware/Mode Averages:")
print(df_fw_mode)

print("\nPer-Mode Aggregated Totals:")
print(df_mode)
