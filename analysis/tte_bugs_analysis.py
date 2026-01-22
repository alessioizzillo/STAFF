#!/usr/bin/env python3
import argparse
import pandas as pd
import numpy as np

TOOLS = ["TRI", "ASA", "STAFF"]
CAUSALITY_CATEGORY_ORDER = ["OIB", "OID", "OII", "MIB", "MID", "MII"]
CATEGORY_COL = "category"
DEFAULT_RUNS = 10  # _cnt is successes out of DEFAULT_RUNS runs

def to_int_series(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").fillna(0).astype(int)

def geo_mean_strict_positive(x: pd.Series) -> float:
    """
    Geometric mean over strictly positive values in x.
    Returns 0.0 if there are no positive values.
    """
    x = pd.to_numeric(x, errors="coerce").dropna()
    x = x[x > 0]
    if x.empty:
        return 0.0
    return float(np.exp(np.log(x).mean()))

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Compute per-category per-tool consistency (ARITH mean) among detected bugs only, "
            "plus overall; also detected counts. Adds GEO_MEAN row = geometric mean of "
            "per-category arithmetic means."
        )
    )
    ap.add_argument("csv_path", help="Path to input CSV (bug-level table).")
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="Number of runs (default: 10).")
    args = ap.parse_args()
    runs = args.runs

    df = pd.read_csv(args.csv_path)

    if CATEGORY_COL not in df.columns:
        raise SystemExit(f"[ERROR] Missing required column: {CATEGORY_COL}")

    df[CATEGORY_COL] = df[CATEGORY_COL].astype(str)

    for t in TOOLS:
        col = f"{t}_cnt"
        if col not in df.columns:
            raise SystemExit(f"[ERROR] Missing required column: {col}")
        df[col] = to_int_series(df[col])

    # Preserve category order as they appear, respecting CAUSALITY_CATEGORY_ORDER first
    seen = list(dict.fromkeys(df[CATEGORY_COL].tolist()))
    categories = (
        [c for c in CAUSALITY_CATEGORY_ORDER if c in seen] +
        [c for c in seen if c not in CAUSALITY_CATEGORY_ORDER]
    )

    # ---------- Detected counts per category + overall ----------
    detected_counts = {}
    for t in TOOLS:
        cnt_col = f"{t}_cnt"
        detected_counts[t] = (
            (df[cnt_col] > 0)
            .groupby(df[CATEGORY_COL])
            .sum()
            .reindex(categories, fill_value=0)
            .astype(int)
        )
    detected_df = pd.DataFrame(detected_counts)
    detected_df.loc["OVERALL"] = pd.Series({t: int((df[f"{t}_cnt"] > 0).sum()) for t in TOOLS})

    # ---------- Consistency per category (detected-only) ----------
    # consistency = cnt/runs, averaged only over rows where cnt>0
    arith_cons = {}

    for t in TOOLS:
        cnt_col = f"{t}_cnt"
        det = df[df[cnt_col] > 0].copy()
        det["consistency"] = det[cnt_col] / float(runs)

        grp = det.groupby(CATEGORY_COL)["consistency"]
        arith_cons[t] = grp.mean().reindex(categories, fill_value=0.0)

    arith_df = pd.DataFrame(arith_cons)

    # Overall consistency (detected-only): mean of per-bug consistency over detected bugs
    overall_arith = {}
    for t in TOOLS:
        cnt_col = f"{t}_cnt"
        s = (df.loc[df[cnt_col] > 0, cnt_col] / float(runs))
        overall_arith[t] = float(s.mean()) if not s.empty else 0.0

    arith_df.loc["ARITH_MEAN"] = pd.Series(overall_arith)

    # ---------- NEW: geometric mean of the per-category arithmetic means ----------
    # This is "geo mean of aggregated OIB/OID/... values" (i.e., geo-mean over the category means),
    # using only strictly positive category means.
    geo_of_cats = {}
    for t in TOOLS:
        geo_of_cats[t] = geo_mean_strict_positive(arith_df.loc[categories, t])

    arith_df.loc["GEO_MEAN"] = pd.Series(geo_of_cats)

    # Optional: keep ARITH_MEAN last for readability
    # (Reorder so GEO_MEAN comes just before ARITH_MEAN)
    arith_df = arith_df.loc[categories + ["ARITH_MEAN", "GEO_MEAN"]]

    # ---------- Output ----------
    print("\n=== Consistency per category (ARITHMETIC mean, detected bugs only) ===")
    print(f"(Mean of cnt/{runs} over bugs where tool_cnt > 0; bugs with cnt==0 are excluded)")
    print("Added row GEO_MEAN = geometric mean over the per-category arithmetic means (positive categories only).")
    print(arith_df.to_string(float_format=lambda x: f"{x:.3f}"))

    print("\n=== Detected bugs per category (tool_cnt > 0) ===")
    print(detected_df.to_string())

    print("\n=== Overall summary (detected-only) ===")
    for t in TOOLS:
        print(
            f"{t}: detected={int(detected_df.loc['OVERALL', t])}  "
            f"arith_overall={arith_df.loc['ARITH_MEAN', t]:.3f}  "
            f"geo_of_cats={arith_df.loc['GEO_MEAN', t]:.3f}"
        )

if __name__ == "__main__":
    main()
