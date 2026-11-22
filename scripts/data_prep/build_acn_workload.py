from __future__ import annotations

"""
Build DBAS-ET ACN workloads from already-downloaded ACN raw JSONL caches.

Used when the ACN API fails during deep pagination but enough raw sessions are
already in data/acn/raw/*.jsonl or *.partial.jsonl.

Modes
-----
1) unique (default): needs at least target_n unique normalized ACN sessions.
2) --allow-bootstrap: if there are fewer unique sessions, sample with
   replacement from them. Such a workload is resampled and is labelled so in
   the summary. The paper uses the unique mode only.

The script writes target-specific CSVs compatible with the existing benchmark
scripts:
  - profile_valid_preauthorization_*.csv
  - profile_original_cap_*.csv
  - profile_undercap_topup_*.csv

It never requires or stores an API token.
"""

import argparse
import csv
import glob
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from dbas_et.workloads import (  # noqa: E402
    PROCESSED_DIR,
    RAW_DIR,
    build_workload_profiles,
    ensure_acn_dirs,
    min_kwh_slug,
    normalize_acn_sessions,
    profile_summary_record,
    save_raw_sessions_jsonl,
    select_protocol_workload,
    sites_slug,
)


def ensure_output_dirs() -> tuple[Path, Path]:
    tables_dir = PROJECT_ROOT / "outputs" / "tables"
    traces_dir = PROJECT_ROOT / "outputs" / "traces"
    tables_dir.mkdir(parents=True, exist_ok=True)
    traces_dir.mkdir(parents=True, exist_ok=True)
    return tables_dir, traces_dir


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"cannot write empty CSV: {path}")
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip corrupt trailing lines if a download was interrupted.
                continue
    return rows


def session_key(row: dict[str, Any]) -> str:
    for key in ("_id", "sessionID", "sessionId", "id"):
        val = row.get(key)
        if val not in (None, ""):
            return f"{row.get('_acn_site_id','unknown')}::{key}::{val}"
    stable = json.dumps(row, sort_keys=True, default=str)
    return "hash::" + hashlib.sha256(stable.encode("utf-8")).hexdigest()


def dedupe_sessions(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = session_key(row)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def resolve_input_files(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pat in patterns:
        matched = [Path(p) for p in glob.glob(pat)]
        if not matched and Path(pat).exists():
            matched = [Path(pat)]
        for p in matched:
            if p.is_file() and p not in files:
                files.append(p)
    files = sorted(files, key=lambda p: (p.stat().st_size, str(p)), reverse=True)
    return files


def build_prefix(*, target_n: int, min_energy_kwh: float, mode: str, seed: int) -> str:
    suffix = f"cached_acn_{min_kwh_slug(min_energy_kwh)}_n{target_n}_{mode}"
    if mode == "bootstrap":
        suffix += f"_seed{seed}"
    return suffix


def write_artifacts(
    *,
    df_normalized: pd.DataFrame,
    df_workload: pd.DataFrame,
    profiles: dict[str, pd.DataFrame],
    target_n: int,
    min_energy_kwh: float,
    mode: str,
    seed: int,
    update_defaults: bool,
) -> dict[str, Any]:
    ensure_acn_dirs()
    prefix = build_prefix(target_n=target_n, min_energy_kwh=min_energy_kwh, mode=mode, seed=seed)

    normalized_path = PROCESSED_DIR / f"acn_sessions_normalized_{prefix}.csv"
    workload_path = PROCESSED_DIR / f"dbas_workload_{prefix}.csv"
    valid_path = PROCESSED_DIR / f"profile_valid_preauthorization_{prefix}.csv"
    original_path = PROCESSED_DIR / f"profile_original_cap_{prefix}.csv"
    undercap_path = PROCESSED_DIR / f"profile_undercap_topup_{prefix}.csv"

    df_normalized.to_csv(normalized_path, index=False)
    df_workload.to_csv(workload_path, index=False)
    profiles["valid_preauthorization"].to_csv(valid_path, index=False)
    profiles["original_cap"].to_csv(original_path, index=False)
    profiles["undercap_topup"].to_csv(undercap_path, index=False)

    default_paths: dict[str, str] = {}
    if update_defaults:
        normalized_default = PROCESSED_DIR / "acn_sessions_normalized.csv"
        workload_default = PROCESSED_DIR / "dbas_workload_5000.csv"
        valid_default = PROCESSED_DIR / "profile_valid_preauthorization.csv"
        original_default = PROCESSED_DIR / "profile_original_cap.csv"
        undercap_default = PROCESSED_DIR / "profile_undercap_topup.csv"
        df_normalized.to_csv(normalized_default, index=False)
        df_workload.to_csv(workload_default, index=False)
        profiles["valid_preauthorization"].to_csv(valid_default, index=False)
        profiles["original_cap"].to_csv(original_default, index=False)
        profiles["undercap_topup"].to_csv(undercap_default, index=False)
        default_paths = {
            "default_normalized_path": str(normalized_default),
            "default_workload_path": str(workload_default),
            "default_valid_profile_path": str(valid_default),
            "default_original_profile_path": str(original_default),
            "default_undercap_topup_profile_path": str(undercap_default),
        }

    return {
        "normalized_path": str(normalized_path),
        "workload_path": str(workload_path),
        "valid_profile_path": str(valid_path),
        "original_profile_path": str(original_path),
        "undercap_topup_profile_path": str(undercap_path),
        **default_paths,
    }


def bootstrap_workload(df_unique: pd.DataFrame, target_n: int, seed: int) -> pd.DataFrame:
    if df_unique.empty:
        raise ValueError("cannot bootstrap from an empty dataframe")
    base = df_unique.reset_index(drop=True).copy()
    base["real_unique_index"] = range(len(base))
    sampled = base.sample(n=target_n, replace=True, random_state=seed).reset_index(drop=True)
    sampled["workload_index"] = range(target_n)
    sampled["acn_bootstrap_resampled"] = True
    sampled["acn_bootstrap_seed"] = int(seed)
    sampled["acn_unique_pool_size"] = int(len(base))
    # Make source_session_id row-unique for downstream trace readability while
    # preserving the original ID in source_session_id_original.
    if "source_session_id" in sampled.columns:
        sampled["source_session_id_original"] = sampled["source_session_id"].astype(str)
        sampled["source_session_id"] = [
            f"{sid}__boot{i}" for i, sid in enumerate(sampled["source_session_id_original"].astype(str))
        ]
    return sampled


def main() -> int:
    parser = argparse.ArgumentParser(description="Build ACN workload from existing raw caches or ACN-derived bootstrap sampling.")
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--input-jsonl", nargs="+", default=["data/acn/raw/*.jsonl", "data/acn/raw/*.partial.jsonl"])
    parser.add_argument("--min-kwh", type=float, default=0.1)
    parser.add_argument("--allow-bootstrap", action="store_true")
    parser.add_argument("--bootstrap-seed", type=int, default=20260521)
    parser.add_argument("--min-unique-for-bootstrap", type=int, default=10000)
    parser.add_argument("--output-prefix", default="acn_cache_build")
    parser.add_argument("--update-defaults", action="store_true")
    args = parser.parse_args()

    tables_dir, traces_dir = ensure_output_dirs()
    input_files = resolve_input_files(args.input_jsonl)
    if not input_files:
        raise SystemExit("No input JSONL files found. Pass --input-jsonl data/acn/raw/*.partial.jsonl etc.")

    all_raw: list[dict[str, Any]] = []
    input_records: list[dict[str, Any]] = []
    for p in input_files:
        rows = read_jsonl(p)
        input_records.append({"path": str(p), "rows": len(rows), "bytes": p.stat().st_size})
        all_raw.extend(rows)

    unique_raw = dedupe_sessions(all_raw)
    raw_combined_path = RAW_DIR / f"acn_sessions_combined_cache_raw{len(unique_raw)}.jsonl"
    save_raw_sessions_jsonl(unique_raw, raw_combined_path)

    df_norm = normalize_acn_sessions(unique_raw)
    if "delivered_kwh" in df_norm.columns:
        df_norm = df_norm[df_norm["delivered_kwh"].astype(float) >= float(args.min_kwh)].copy()
    df_norm = df_norm.reset_index(drop=True)

    unique_normalized = int(len(df_norm))
    mode = "unique"
    if unique_normalized >= args.target:
        df_workload = select_protocol_workload(df_norm, args.target)
    else:
        if not args.allow_bootstrap:
            raise SystemExit(
                f"Not enough unique normalized sessions: have={unique_normalized}, target={args.target}. "
                "Use --allow-bootstrap for ACN-derived resampling, lower --min-kwh, or add more raw/static data."
            )
        if unique_normalized < args.min_unique_for_bootstrap:
            raise SystemExit(
                f"Refusing bootstrap: unique pool too small ({unique_normalized}) < "
                f"--min-unique-for-bootstrap {args.min_unique_for_bootstrap}."
            )
        mode = "bootstrap"
        df_workload = bootstrap_workload(df_norm, args.target, args.bootstrap_seed)

    profiles = build_workload_profiles(df_workload)
    artifact_paths = write_artifacts(
        df_normalized=df_norm,
        df_workload=df_workload,
        profiles=profiles,
        target_n=args.target,
        min_energy_kwh=args.min_kwh,
        mode=mode,
        seed=args.bootstrap_seed,
        update_defaults=args.update_defaults,
    )

    raw_sites = sorted({str(r.get("_acn_site_id") or r.get("siteID") or r.get("site") or "unknown") for r in unique_raw})
    summary = profile_summary_record(
        df_workload=df_workload,
        profiles=profiles,
        raw_count=len(unique_raw),
        raw_path=raw_combined_path,
        artifact_paths=artifact_paths,
        target_n=args.target,
        sites=raw_sites,
        min_energy_kwh=args.min_kwh,
        raw_limit_used=len(unique_raw),
    )
    summary.update(
        {
            "test_name": "acn_cache_or_bootstrap_workload",
            "status": "passed",
            "mode": mode,
            "unique_raw_sessions_combined": int(len(unique_raw)),
            "unique_normalized_sessions": unique_normalized,
            "target_n": int(args.target),
            "selected_samples_equals_target": int(len(df_workload)) == int(args.target),
            "allow_bootstrap": bool(args.allow_bootstrap),
            "bootstrap_seed": int(args.bootstrap_seed) if mode == "bootstrap" else "",
            "bootstrap_note": (
                "ACN-derived bootstrap workload sampled with replacement from unique real ACN sessions; "
                "do not claim as unique real sessions."
                if mode == "bootstrap"
                else "unique real ACN sessions"
            ),
            "input_files_count": len(input_files),
        }
    )

    summary_path = tables_dir / f"{args.output_prefix}_summary.csv"
    trace_path = traces_dir / f"{args.output_prefix}_inputs.jsonl"
    write_csv(summary_path, [summary])
    with trace_path.open("w", encoding="utf-8") as f:
        for row in input_records:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    print(json.dumps({
        "status": "passed",
        "mode": mode,
        "target": int(args.target),
        "unique_normalized_sessions": unique_normalized,
        "selected_samples_for_report": int(len(df_workload)),
        "summary_path": str(summary_path),
        "valid_profile_path": artifact_paths["valid_profile_path"],
        "undercap_topup_profile_path": artifact_paths["undercap_topup_profile_path"],
        "bootstrap_note": summary["bootstrap_note"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
