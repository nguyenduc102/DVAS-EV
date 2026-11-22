#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import time
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd


def find_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    lower = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in df.columns:
            return c
        if c.lower() in lower:
            return lower[c.lower()]
    return None


def read_energy(df: pd.DataFrame) -> pd.Series:
    col = find_col(df, ["delivered_kwh", "energy_kwh", "kWhDelivered", "kwh", "total_kwh"])
    if col is None:
        raise ValueError(f"Cannot find delivered energy column. Columns={df.columns.tolist()}")
    return pd.to_numeric(df[col], errors="coerce").fillna(0.0).clip(lower=0.0)


def read_native_amount(df: pd.DataFrame, dataset: str, kwh: pd.Series) -> pd.Series:
    if dataset.upper() == "ACN":
        col = find_col(df, ["expected_amount", "amount"])
    else:
        col = find_col(df, ["amount", "expected_amount"])

    if col is not None:
        s = pd.to_numeric(df[col], errors="coerce")
        if not s.isna().all():
            return s.fillna(0.0).clip(lower=0.0)

    unit = read_unit_price(df, kwh)
    return kwh * unit


def read_native_reserve(df: pd.DataFrame, native_amount: pd.Series) -> pd.Series:
    col = find_col(df, ["preauth_limit_t", "valid_preauth_limit_t", "preauth_limit_valid"])
    if col is not None:
        s = pd.to_numeric(df[col], errors="coerce")
        if not s.isna().all():
            return s.fillna(native_amount * 1.05).clip(lower=0.0)
    return native_amount * 1.05


def read_unit_price(df: pd.DataFrame, kwh: pd.Series) -> pd.Series:
    col = find_col(df, ["unit_price"])
    if col is not None:
        s = pd.to_numeric(df[col], errors="coerce")
        if not s.isna().all():
            med = s[s > 0].median()
            if not math.isfinite(med):
                med = 1.0
            return s.fillna(med).clip(lower=0.0)

    amount_col = find_col(df, ["expected_amount", "amount"])
    if amount_col is not None:
        amount = pd.to_numeric(df[amount_col], errors="coerce").fillna(0.0)
        price = amount / kwh.replace(0, np.nan)
        med = price[price > 0].median()
        if math.isfinite(med):
            return pd.Series(np.full(len(df), med), index=df.index)

    return pd.Series(np.full(len(df), 1.0), index=df.index)


def read_start_hour(df: pd.DataFrame) -> pd.Series:
    col = find_col(
        df,
        [
            "connection_time_utc",
            "connectionTime",
            "start_ts",
            "start_time",
            "created_at",
        ],
    )
    if col is None:
        return pd.Series(np.arange(len(df)) % 24, index=df.index)

    dt = pd.to_datetime(df[col], errors="coerce", utc=True)
    hour = dt.dt.hour
    if hour.isna().all():
        return pd.Series(np.arange(len(df)) % 24, index=df.index)

    return hour.fillna(12).astype(int)


def read_duration_min(df: pd.DataFrame) -> pd.Series:
    for col in ["connection_duration_s", "parking_duration_s", "duration_raw"]:
        if col in df.columns:
            s = pd.to_numeric(df[col], errors="coerce")
            if not s.isna().all():
                # ACN duration columns are seconds, MFEV duration_raw is in minutes.
                if col.endswith("_s"):
                    return (s / 60.0).fillna((s / 60.0).median()).clip(lower=1.0)
                return s.fillna(s.median()).clip(lower=1.0)

    start_col = find_col(df, ["connection_time_utc", "connectionTime", "start_ts"])
    end_col = find_col(df, ["disconnect_time_utc", "disconnectTime", "end_ts"])

    if start_col and end_col:
        start = pd.to_datetime(df[start_col], errors="coerce", utc=True)
        end = pd.to_datetime(df[end_col], errors="coerce", utc=True)
        mins = (end - start).dt.total_seconds() / 60.0
        if not mins.isna().all():
            med = mins[mins > 0].median()
            if not math.isfinite(med):
                med = 90.0
            return mins.fillna(med).clip(lower=1.0)

    return pd.Series(90.0 + (np.arange(len(df)) % 90), index=df.index)


def tou_multiplier(hour: pd.Series) -> pd.Series:
    h = hour.astype(int) % 24

    # Conservative representative TOU pattern.
    # off-peak: 0.80x, mid: 1.00x, peak: 1.25x.
    m = pd.Series(np.full(len(h), 1.00), index=h.index)
    m[(h >= 0) & (h <= 6)] = 0.80
    m[(h >= 17) & (h <= 21)] = 1.25
    return m


def compute_tariff_amounts(df: pd.DataFrame, dataset: str, model: str) -> pd.Series:
    kwh = read_energy(df)
    unit = read_unit_price(df, kwh)
    hour = read_start_hour(df)
    duration_min = read_duration_min(df)

    native = read_native_amount(df, dataset, kwh)

    median_native = native[native > 0].median()
    if not math.isfinite(median_native):
        median_native = float((kwh * unit).median())

    session_fee = 0.10 * median_native

    # Idle fee is scaled using the dataset unit price so ACN and MFEV remain in their own monetary units.
    estimated_charge_min = (kwh / 7.2) * 60.0
    idle_min = (duration_min - estimated_charge_min).clip(lower=0.0)
    idle_fee_per_min = unit * 7.2 / 60.0 * 0.25
    idle_fee = idle_min * idle_fee_per_min

    flat = kwh * unit

    if model == "native_committed":
        amount = native
    elif model == "flat":
        amount = flat
    elif model == "tou":
        amount = kwh * unit * tou_multiplier(hour)
    elif model == "session_fee":
        amount = flat + session_fee
    elif model == "idle_fee":
        amount = flat + idle_fee
    elif model == "roaming_markup":
        amount = (kwh * unit * tou_multiplier(hour) + session_fee) * 1.15
    elif model == "stress_mixed":
        amount = (kwh * unit * tou_multiplier(hour) + session_fee + idle_fee) * 1.20
    else:
        raise ValueError(f"Unknown tariff model: {model}")

    return pd.to_numeric(amount, errors="coerce").fillna(0.0).clip(lower=0.0)


def compute_reserve(
    df: pd.DataFrame,
    dataset: str,
    model: str,
    policy: str,
    margin: float,
) -> pd.Series:
    actual = compute_tariff_amounts(df, dataset, model)

    if policy == "native_preauth":
        native = read_native_amount(df, dataset, read_energy(df))
        return read_native_reserve(df, native)

    if policy == "tariff_aware":
        return actual * (1.0 + margin)

    if policy == "flat_estimate":
        flat = compute_tariff_amounts(df, dataset, "flat")
        return flat * (1.0 + margin)

    raise ValueError(f"Unknown reserve policy: {policy}")


def bench_one(
    df: pd.DataFrame,
    dataset: str,
    model: str,
    policy: str,
    margin: float,
    repeat: int,
) -> dict:
    times = []

    actual = None
    reserve = None
    ok = None
    topup_delta = None

    for _ in range(repeat):
        t0 = time.perf_counter_ns()

        actual = compute_tariff_amounts(df, dataset, model)
        reserve = compute_reserve(df, dataset, model, policy, margin)
        ok = actual <= reserve
        topup_delta = (actual - reserve).clip(lower=0.0)

        t1 = time.perf_counter_ns()
        times.append((t1 - t0) / 1e6)

    assert actual is not None
    assert reserve is not None
    assert ok is not None
    assert topup_delta is not None

    blocked = ~ok

    return {
        "dataset": dataset,
        "tariff_model": model,
        "reserve_policy": policy,
        "rows": len(df),
        "settled_without_topup": int(ok.sum()),
        "blocked_without_topup": int(blocked.sum()),
        "blocked_rate_pct": float(blocked.mean() * 100.0),
        "topup_recovered": int(blocked.sum()),
        "settled_after_topup": int(len(df)),
        "amount_median": float(actual.median()),
        "amount_p95": float(actual.quantile(0.95)),
        "reserve_median": float(reserve.median()),
        "reserve_p95": float(reserve.quantile(0.95)),
        "topup_delta_median": float(topup_delta.median()),
        "topup_delta_p95": float(topup_delta.quantile(0.95)),
        "topup_delta_max": float(topup_delta.max()),
        "check_median_ms": float(np.median(times)),
        "check_p95_ms": float(np.quantile(times, 0.95)),
        "repeat": repeat,
    }


def run_dataset(
    dataset: str,
    path: str,
    max_rows: int,
    margin: float,
    repeat: int,
) -> pd.DataFrame:
    df = pd.read_csv(path)

    if max_rows > 0:
        df = df.head(max_rows).copy()

    cases = []

    # Sanity check using committed/native amount and preauthorization fields.
    cases.append(("native_committed", "native_preauth"))

    # Synthetic tariff sensitivity.
    models = [
        "flat",
        "tou",
        "session_fee",
        "idle_fee",
        "roaming_markup",
        "stress_mixed",
    ]

    for model in models:
        cases.append((model, "tariff_aware"))
        cases.append((model, "flat_estimate"))

    rows = []
    for model, policy in cases:
        rows.append(
            bench_one(
                df=df,
                dataset=dataset,
                model=model,
                policy=policy,
                margin=margin,
                repeat=repeat,
            )
        )

    return pd.DataFrame(rows)


def write_md(df: pd.DataFrame, path: Path, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        f.write(f"# {title}\n\n")
        if df.empty:
            f.write("_No rows._\n")
        else:
            try:
                f.write(df.to_markdown(index=False))
            except Exception:
                f.write(df.to_string(index=False))
            f.write("\n")


def make_paper_table(summary: pd.DataFrame) -> pd.DataFrame:
    # Paper table: native sanity row, tariff-aware flat row and flat-estimate stress rows.
    keep = (
        ((summary["tariff_model"] == "native_committed") & (summary["reserve_policy"] == "native_preauth"))
        | ((summary["tariff_model"] == "flat") & (summary["reserve_policy"] == "tariff_aware"))
        | ((summary["tariff_model"].isin(["tou", "session_fee", "idle_fee", "roaming_markup", "stress_mixed"]))
           & (summary["reserve_policy"] == "flat_estimate"))
    )

    df = summary[keep].copy()

    cols = [
        "dataset",
        "tariff_model",
        "reserve_policy",
        "rows",
        "settled_without_topup",
        "blocked_without_topup",
        "blocked_rate_pct",
        "topup_recovered",
        "amount_median",
        "amount_p95",
        "topup_delta_p95",
        "check_median_ms",
        "check_p95_ms",
    ]

    df = df[cols].copy()

    rename = {
        "dataset": "Dataset",
        "tariff_model": "Tariff model",
        "reserve_policy": "Reserve policy",
        "rows": "Rows",
        "settled_without_topup": "Settled w/o top-up",
        "blocked_without_topup": "Blocked w/o top-up",
        "blocked_rate_pct": "Blocked %",
        "topup_recovered": "Top-up recovered",
        "amount_median": "Amount median",
        "amount_p95": "Amount P95",
        "topup_delta_p95": "Top-up delta P95",
        "check_median_ms": "Check med ms",
        "check_p95_ms": "Check P95 ms",
    }

    df = df.rename(columns=rename)

    for c in ["Blocked %", "Amount median", "Amount P95", "Top-up delta P95", "Check med ms", "Check P95 ms"]:
        df[c] = df[c].map(lambda x: round(float(x), 3))

    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acn-csv", required=True)
    ap.add_argument("--mfev-csv", required=True)
    ap.add_argument("--max-acn-rows", type=int, default=30000)
    ap.add_argument("--max-mfev-rows", type=int, default=50000)
    ap.add_argument("--reserve-margin", type=float, default=0.05)
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--output-prefix", default="tariff_sensitivity_acn30k_mfev50k")
    args = ap.parse_args()

    acn = run_dataset(
        dataset="ACN",
        path=args.acn_csv,
        max_rows=args.max_acn_rows,
        margin=args.reserve_margin,
        repeat=args.repeat,
    )

    mfev = run_dataset(
        dataset="MFEV",
        path=args.mfev_csv,
        max_rows=args.max_mfev_rows,
        margin=args.reserve_margin,
        repeat=args.repeat,
    )

    summary = pd.concat([acn, mfev], ignore_index=True)
    paper = make_paper_table(summary)

    out_dir = Path("outputs/tables")
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_csv = out_dir / f"{args.output_prefix}_summary.csv"
    summary_md = out_dir / f"{args.output_prefix}_summary.md"
    paper_csv = out_dir / f"{args.output_prefix}_paper_table.csv"
    paper_md = out_dir / f"{args.output_prefix}_paper_table.md"
    config_md = out_dir / f"{args.output_prefix}_config.md"

    summary.to_csv(summary_csv, index=False)
    paper.to_csv(paper_csv, index=False)

    write_md(summary, summary_md, "Tariff sensitivity full summary")
    write_md(paper, paper_md, "Paper-ready tariff sensitivity table")

    with config_md.open("w", encoding="utf-8") as f:
        f.write("# Tariff sensitivity configuration\n\n")
        f.write(f"- ACN CSV: `{args.acn_csv}`\n")
        f.write(f"- MFEV CSV: `{args.mfev_csv}`\n")
        f.write(f"- ACN rows: {args.max_acn_rows}\n")
        f.write(f"- MFEV rows: {args.max_mfev_rows}\n")
        f.write(f"- Reserve margin: {args.reserve_margin}\n")
        f.write(f"- Repeat: {args.repeat}\n\n")

        f.write("## Tariff models\n\n")
        f.write("- `native_committed`: uses dataset committed amount and preauthorization fields.\n")
        f.write("- `flat`: delivered energy multiplied by row-level unit price.\n")
        f.write("- `tou`: flat energy price with representative off-peak/mid/peak multipliers.\n")
        f.write("- `session_fee`: flat energy price plus a dataset-scaled session fee.\n")
        f.write("- `idle_fee`: flat energy price plus duration-derived idle fee.\n")
        f.write("- `roaming_markup`: TOU amount plus session component and roaming markup.\n")
        f.write("- `stress_mixed`: TOU + session fee + idle fee with stress markup.\n\n")

        f.write("## Reserve policies\n\n")
        f.write("- `native_preauth`: uses the dataset preauthorization field.\n")
        f.write("- `tariff_aware`: reserves the current tariff amount with the configured margin.\n")
        f.write("- `flat_estimate`: reserves the flat tariff amount with the configured margin while actual settlement follows the selected richer tariff model.\n\n")

        f.write("## Fairness note\n\n")
        f.write(
            "This benchmark is a tariff-sensitivity and reserve/top-up stress test. "
            "It does not model every real tariff or market price. "
            "The monetary units remain dataset-specific: ACN uses deterministic protocol amounts, "
            "whereas MFEV uses its processed monetary scale. The main comparison is therefore "
            "within each dataset across tariff policies, not between ACN and MFEV currencies.\n"
        )

    print(f"[OK] wrote {summary_csv}")
    print(f"[OK] wrote {paper_md}")
    print(f"[OK] wrote {config_md}")


if __name__ == "__main__":
    main()
