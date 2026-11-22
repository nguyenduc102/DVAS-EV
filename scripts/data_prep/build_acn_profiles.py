from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from dbas_et.workloads import (  # noqa: E402
    ACNDownloadConfig,
    DEFAULT_SITES,
    build_workload_profiles,
    ensure_acn_dirs,
    fetch_acn_sessions_rest,
    load_raw_sessions_jsonl,
    normalize_acn_sessions,
    profile_summary_record,
    raw_cache_path,
    read_api_token_from_env_or_file,
    save_raw_sessions_jsonl,
    select_protocol_workload,
    write_workload_artifacts,
)


def ensure_output_dirs() -> tuple[Path, Path]:
    tables_dir = PROJECT_ROOT / "outputs" / "tables"
    traces_dir = PROJECT_ROOT / "outputs" / "traces"

    tables_dir.mkdir(parents=True, exist_ok=True)
    traces_dir.mkdir(parents=True, exist_ok=True)

    return tables_dir, traces_dir


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError("cannot write empty CSV")

    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download/load real ACN data and build DBAS-ET workload profiles. "
            "The script downloads raw sessions with oversampling, then selects exactly "
            "target_n usable normalized samples for the report workload."
        )
    )

    parser.add_argument("--api-token", type=str, default="", help="ACN API token. Prefer env ACN_API_TOKEN.")
    parser.add_argument("--api-token-file", type=str, default="", help="File containing ACN API token.")

    parser.add_argument("--target-n", type=int, default=5000, help="Exact number of usable ACN samples for DBAS-ET workload/report.")

    parser.add_argument(
        "--site",
        dest="site",
        action="append",
        default=None,
        help="ACN site ID. Can be repeated, e.g., --site caltech --site jpl.",
    )

    parser.add_argument(
        "--sites",
        nargs="+",
        default=None,
        help="ACN site IDs, e.g., --sites caltech jpl office001.",
    )

    parser.add_argument(
        "--min-kwh",
        "--min-energy-kwh",
        dest="min_energy_kwh",
        type=float,
        default=0.1,
        help="Minimum delivered energy in kWh for raw API query.",
    )

    parser.add_argument(
        "--oversample-factor",
        type=float,
        default=1.5,
        help="Raw download multiplier. Example: target_n=5000, factor=1.5 -> raw limit starts at 7500.",
    )

    parser.add_argument(
        "--max-download-attempts",
        type=int,
        default=3,
        help="Increase raw limit and retry if normalized usable samples are fewer than target_n.",
    )

    parser.add_argument(
        "--download-step-factor",
        type=float,
        default=1.5,
        help="Multiplier used to increase raw limit on each retry.",
    )

    parser.add_argument("--force-download", action="store_true", help="Ignore cached raw JSONL and download again.")
    parser.add_argument("--no-download", action="store_true", help="Do not download; require cached raw JSONL.")
    parser.add_argument("--timeout-s", type=int, default=60)
    parser.add_argument("--sleep-s", type=float, default=0.10)

    return parser.parse_args()


def resolve_sites(args: argparse.Namespace) -> tuple[str, ...]:
    """Resolve --site repeated args and --sites list into one tuple."""
    selected: list[str] = []

    if args.sites:
        selected.extend(args.sites)

    if args.site:
        selected.extend(args.site)

    if not selected:
        selected = list(DEFAULT_SITES)

    cleaned = []
    for site in selected:
        s = str(site).strip()
        if s and s not in cleaned:
            cleaned.append(s)

    return tuple(cleaned)


def load_or_download_raw_sessions(
    *,
    api_token: str,
    sites: tuple[str, ...],
    min_energy_kwh: float,
    raw_limit: int,
    timeout_s: int,
    sleep_s: float,
    force_download: bool,
    no_download: bool,
    trace_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], Path]:
    """Load cached raw sessions or download them."""
    raw_path = raw_cache_path(
        sites=sites,
        min_energy_kwh=min_energy_kwh,
        raw_limit=raw_limit,
    )

    need_download = force_download or not raw_path.exists()

    if need_download:
        if no_download:
            raise RuntimeError(
                f"cached raw ACN file not found and --no-download was set: {raw_path}"
            )

        if not api_token:
            raise RuntimeError(
                "ACN API token missing. Set env ACN_API_TOKEN or pass --api-token / --api-token-file."
            )

        cfg = ACNDownloadConfig(
            api_token=api_token,
            target_raw_sessions=raw_limit,
            sites=sites,
            min_energy_kwh=min_energy_kwh,
            timeout_s=timeout_s,
            sleep_s=sleep_s,
        )

        trace_rows.append(
            {
                "event": "download_acn_sessions",
                **cfg.safe_record(),
                "raw_path": str(raw_path),
            }
        )

        sessions = fetch_acn_sessions_rest(cfg)
        save_raw_sessions_jsonl(sessions, raw_path)

        trace_rows.append(
            {
                "event": "save_raw_sessions",
                "raw_sessions": len(sessions),
                "raw_path": str(raw_path),
            }
        )

        return sessions, raw_path

    trace_rows.append(
        {
            "event": "use_cached_raw_sessions",
            "raw_limit": raw_limit,
            "raw_path": str(raw_path),
        }
    )

    sessions = load_raw_sessions_jsonl(raw_path)
    return sessions, raw_path


def main() -> int:
    args = parse_args()

    if args.target_n <= 0:
        raise ValueError("--target-n must be positive")
    if args.min_energy_kwh < 0:
        raise ValueError("--min-kwh must be non-negative")
    if args.oversample_factor < 1.0:
        raise ValueError("--oversample-factor must be >= 1.0")

    sites = resolve_sites(args)

    tables_dir, traces_dir = ensure_output_dirs()
    ensure_acn_dirs()

    api_token = read_api_token_from_env_or_file(
        api_token=args.api_token,
        token_file=args.api_token_file or None,
    )

    trace_rows: list[dict[str, Any]] = [
        {
            "event": "start_workload_profile_smoke",
            "target_n": int(args.target_n),
            "sites": ",".join(sites),
            "min_energy_kwh": float(args.min_energy_kwh),
            "oversample_factor": float(args.oversample_factor),
            "created_at": int(time.time()),
        }
    ]

    raw_limit = max(args.target_n, int(round(args.target_n * args.oversample_factor)))
    last_error: str = ""
    final_raw_sessions: list[dict[str, Any]] = []
    final_raw_path: Path | None = None
    final_df_normalized = None

    for attempt in range(1, args.max_download_attempts + 1):
        trace_rows.append(
            {
                "event": "download_attempt",
                "attempt": attempt,
                "raw_limit": raw_limit,
            }
        )

        raw_sessions, raw_path = load_or_download_raw_sessions(
            api_token=api_token,
            sites=sites,
            min_energy_kwh=args.min_energy_kwh,
            raw_limit=raw_limit,
            timeout_s=args.timeout_s,
            sleep_s=args.sleep_s,
            force_download=args.force_download,
            no_download=args.no_download,
            trace_rows=trace_rows,
        )

        df_normalized = normalize_acn_sessions(raw_sessions)

        trace_rows.append(
            {
                "event": "normalize_acn_sessions",
                "attempt": attempt,
                "raw_sessions": len(raw_sessions),
                "normalized_rows": len(df_normalized),
                "target_n": args.target_n,
            }
        )

        final_raw_sessions = raw_sessions
        final_raw_path = raw_path
        final_df_normalized = df_normalized

        if len(df_normalized) >= args.target_n:
            break

        last_error = (
            f"attempt={attempt}: normalized rows {len(df_normalized)} < target_n {args.target_n}"
        )

        if args.no_download:
            break

        raw_limit = max(raw_limit + 1, int(round(raw_limit * args.download_step_factor)))
        args.force_download = True

    if final_df_normalized is None or final_raw_path is None:
        raise RuntimeError("failed to load or download ACN sessions")

    if len(final_df_normalized) < args.target_n:
        raise RuntimeError(
            f"Not enough usable ACN sessions after normalization. "
            f"normalized={len(final_df_normalized)}, target_n={args.target_n}. "
            f"Last error: {last_error}. "
            f"Try: add more sites, lower --min-kwh, or increase --oversample-factor."
        )

    df_workload = select_protocol_workload(final_df_normalized, target_n=args.target_n)

    trace_rows.append(
        {
            "event": "select_protocol_workload",
            "selected_workload_rows": len(df_workload),
            "target_n": args.target_n,
        }
    )

    profiles = build_workload_profiles(df_workload)

    trace_rows.append(
        {
            "event": "build_workload_profiles",
            "valid_profile_rows": len(profiles["valid_preauthorization"]),
            "original_profile_rows": len(profiles["original_cap"]),
            "undercap_topup_rows": len(profiles["undercap_topup"]),
        }
    )

    artifact_paths = write_workload_artifacts(
        df_normalized=final_df_normalized,
        df_workload=df_workload,
        profiles=profiles,
        target_n=args.target_n,
        sites=sites,
        min_energy_kwh=args.min_energy_kwh,
    )

    summary = profile_summary_record(
        df_workload=df_workload,
        profiles=profiles,
        raw_count=len(final_raw_sessions),
        raw_path=final_raw_path,
        artifact_paths=artifact_paths,
        target_n=args.target_n,
        sites=sites,
        min_energy_kwh=args.min_energy_kwh,
        raw_limit_used=raw_limit,
    )

    status_ok = (
        summary["selected_samples_for_report"] == args.target_n
        and summary["selected_samples_equals_target"] is True
        and summary["valid_profile_rows"] == args.target_n
        and summary["original_profile_rows"] == args.target_n
        and summary["undercap_topup_rows"] >= 0
    )

    # undercap_topup_rows is zero when the original preauthorization covers every
    # session. The top-up benchmark needs at least one such row.
    summary["status"] = "passed" if status_ok else "failed"
    summary["topup_subset_available"] = summary["undercap_topup_rows"] > 0

    summary_path = tables_dir / "workload_profile_summary.csv"
    trace_path = traces_dir / "workload_profile_trace.jsonl"

    write_csv(summary_path, [summary])
    write_jsonl(trace_path, trace_rows)

    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Saved summary: {summary_path}")
    print(f"Saved trace: {trace_path}")

    if not summary["topup_subset_available"]:
        print(
            "WARNING: undercap_topup_rows is 0. The workload has 5000 samples, "
            "but top-up benchmark will need a stricter original-cap policy or "
            "different tariff settings to create under-cap cases."
        )

    return 0 if status_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())