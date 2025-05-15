#!/usr/bin/env python3
import os
import glob
import configparser
from collections import defaultdict
import pandas as pd

BASE_DIR    = "experiments"
OUTPUT_DIR  = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

METRICS = ["bitmap_cvg", "unique_crashes", "unique_hangs", "paths_total"]
WEIGHT  = "execs_done"

def parse_fuzzer_stats(path):
    """Read fuzzer_stats and return a dict of floats for METRICS + WEIGHT."""
    data = {}
    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().rstrip('%')
            if key in METRICS + [WEIGHT]:
                try:
                    data[key] = float(val)
                except ValueError:
                    data[key] = 0.0
    return data

agg = defaultdict(lambda: {w: 0.0 for w in METRICS + [WEIGHT]})

for exp_dir in sorted(glob.glob(os.path.join(BASE_DIR, "exp_*"))):
    cfg_path   = os.path.join(exp_dir, "config.ini")
    stats_path = os.path.join(exp_dir, "fuzzer_stats")
    if not (os.path.isfile(cfg_path) and os.path.isfile(stats_path)):
        continue

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    try:
        firmware = cfg["GENERAL"]["firmware"]
        mode     = cfg["GENERAL"]["mode"]
    except KeyError:
        continue

    stats = parse_fuzzer_stats(stats_path)
    w     = stats.get(WEIGHT, 0.0)
    if w <= 0:
        continue

    key = (firmware, mode)
    agg[key][WEIGHT] += w
    for m in METRICS:
        agg[key][m] += stats.get(m, 0.0) * w

rows = []
for (firmware, mode), vals in agg.items():
    total_w = vals[WEIGHT]
    row = {
        "Firmware": firmware,
        "Mode":     mode,
    }
    for m in METRICS:
        row[m] = round(vals[m] / total_w, 4) if total_w > 0 else 0.0
    rows.append(row)

df_fw_mode = pd.DataFrame(rows).sort_values(["Firmware", "Mode"])
out1 = os.path.join(OUTPUT_DIR, "per_firmware_mode.csv")
df_fw_mode.to_csv(out1, index=False)
print(f"-> saved per-firmware/mode averages to {out1}")

df_mode = (
    df_fw_mode
    .groupby("Mode")[METRICS]
    .sum()
    .reset_index()
)
out2 = os.path.join(OUTPUT_DIR, "per_mode_aggregate.csv")
df_mode.to_csv(out2, index=False)
print(f"-> saved per-mode aggregates to    {out2}")

print("\nPer-Firmware/Mode weighted averages:")
print(df_fw_mode.to_markdown(index=False))
print("\nPer-Mode aggregated sums:")
print(df_mode.to_markdown(index=False))
