from __future__ import annotations

"""
ACN downloader with checkpoints, for the 10k/30k workloads.

The ACN API sometimes returns 502/503/504 on long downloads. Each page is
appended to a JSONL checkpoint, so a re-run loads it, removes duplicates and
continues until there are enough sessions for the target size.

- The API token is never written to outputs.
- Output names include the target size; the default 5k inputs are only
  replaced with --update-defaults.
- One ACN charging session becomes one DBAS-ET transaction.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from dbas_et.workloads import (  # noqa: E402
    ACNDownloadConfig,
    DEFAULT_ACN_BASE_URL,
    DEFAULT_SITES,
    PROCESSED_DIR,
    RAW_DIR,
    _build_where_clause,
    _extract_items,
    _extract_next_href,
    _join_api_url,
    _now_utc_iso,
    build_workload_profiles,
    ensure_acn_dirs,
    load_raw_sessions_jsonl,
    min_kwh_slug,
    normalize_acn_sessions,
    profile_summary_record,
    raw_cache_path,
    read_api_token_from_env_or_file,
    save_raw_sessions_jsonl,
    select_protocol_workload,
    sites_slug,
    workload_cache_prefix,
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


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def append_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def load_jsonl_if_exists(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
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


def resolve_sites(args: argparse.Namespace) -> tuple[str, ...]:
    selected: list[str] = []
    if args.sites:
        selected.extend(args.sites)
    if args.site:
        selected.extend(args.site)
    if not selected:
        selected = list(DEFAULT_SITES)
    out: list[str] = []
    for site in selected:
        s = str(site).strip()
        if s and s not in out:
            out.append(s)
    return tuple(out)


def checkpoint_path_for(raw_path: Path) -> Path:
    return raw_path.with_name(raw_path.stem + ".partial.jsonl")


def state_path_for(raw_path: Path) -> Path:
    return raw_path.with_name(raw_path.stem + ".state.json")


def checkpoint_meta_path_for(raw_path: Path) -> Path:
    return raw_path.with_name(raw_path.stem + ".checkpoint_meta.json")


def request_with_retries(
    *,
    requests_module: Any,
    url: str,
    params: dict[str, Any] | None,
    token: str,
    timeout_s: int,
    site_id: str,
    page_no: int,
    max_retries: int,
    base_backoff_s: float,
    max_backoff_s: float,
) -> Any:
    transient_statuses = {429, 500, 502, 503, 504}
    last_error = ""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests_module.get(url, params=params, auth=(token, ""), timeout=timeout_s)
        except requests_module.exceptions.RequestException as exc:
            last_error = f"request_exception={type(exc).__name__}: {exc}"
            sleep_s = min(max_backoff_s, base_backoff_s * (2 ** (attempt - 1)))
            print(
                f"[acn] retry site={site_id} page={page_no} "
                f"attempt={attempt}/{max_retries} after {last_error}; sleep={sleep_s:.1f}s",
                flush=True,
            )
            time.sleep(sleep_s)
            continue

        if resp.status_code == 200:
            return resp, attempt - 1

        if resp.status_code in {401, 403}:
            raise RuntimeError(
                f"ACN API authentication/authorization failed: site={site_id}, "
                f"status={resp.status_code}, body={resp.text[:300]}"
            )

        if resp.status_code in transient_statuses:
            last_error = f"status={resp.status_code}, body={resp.text[:180]}"
            sleep_s = min(max_backoff_s, base_backoff_s * (2 ** (attempt - 1)))
            print(
                f"[acn] retry site={site_id} page={page_no} "
                f"attempt={attempt}/{max_retries} after {last_error}; sleep={sleep_s:.1f}s",
                flush=True,
            )
            time.sleep(sleep_s)
            continue

        raise RuntimeError(
            f"ACN API request failed: site={site_id}, status={resp.status_code}, body={resp.text[:300]}"
        )

    raise RuntimeError(
        f"ACN API page failed after {max_retries} retries: site={site_id}, page={page_no}, last_error={last_error}"
    )


def fetch_acn_sessions_checkpointed(
    cfg: ACNDownloadConfig,
    *,
    raw_path: Path,
    resume: bool,
    progress_pages: int,
    checkpoint_every_pages: int,
    max_retries_per_page: int,
    base_backoff_s: float,
    max_backoff_s: float,
    allow_site_skip: bool,
    max_pages_per_site: int = 0,
    max_consecutive_retry_pages: int = 0,
    max_transient_pages_per_site: int = 0,
    max_transient_events_per_site: int = 0,
    seed_jsonl_paths: list[str] | None = None,
) -> tuple[list[dict[str, Any]], Path, Path, dict[str, Any]]:
    try:
        import requests
    except Exception as exc:
        raise RuntimeError("requests is required. Install with: pip install requests") from exc

    partial_path = checkpoint_path_for(raw_path)
    state_path = state_path_for(raw_path)
    meta_path = checkpoint_meta_path_for(raw_path)

    sessions: list[dict[str, Any]] = []

    # Optional seed files allow continuing from a checkpoint created with a
    # different site order or a different raw-limit filename. This is useful
    # when caltech deep pagination becomes unhealthy and we want to continue
    # with jpl/office001 without losing already fetched caltech sessions.
    for seed in seed_jsonl_paths or []:
        seed_path = Path(seed)
        if seed_path.exists():
            seed_rows = load_jsonl_if_exists(seed_path)
            sessions.extend(seed_rows)
            print(f"[acn] loaded seed_jsonl={seed_path}, rows={len(seed_rows)}", flush=True)
        else:
            print(f"[acn] warning: seed_jsonl not found: {seed_path}", flush=True)

    if resume and partial_path.exists():
        partial_rows = load_jsonl_if_exists(partial_path)
        sessions.extend(partial_rows)
        sessions = dedupe_sessions(sessions)
        print(f"[acn] resume checkpoint={partial_path}, loaded_total={len(sessions)} sessions", flush=True)
    else:
        sessions = dedupe_sessions(sessions)
        if partial_path.exists() and not resume:
            partial_path.unlink()
        if state_path.exists() and not resume:
            state_path.unlink()
        if meta_path.exists() and not resume:
            meta_path.unlink()

    seen = {session_key(row) for row in sessions}
    where_clause = _build_where_clause(cfg.min_energy_kwh)
    meta = {
        "target_raw_sessions": int(cfg.target_raw_sessions),
        "sites": list(cfg.sites),
        "min_energy_kwh": float(cfg.min_energy_kwh),
        "base_url": cfg.base_url,
        "partial_path": str(partial_path),
        "raw_path": str(raw_path),
        "started_at_utc": _now_utc_iso(),
        "api_token_stored_in_outputs": False,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

    total_pages = 0
    new_sessions_this_run = 0

    # Resume: load the partial file, then scan sites from the beginning and skip
    # duplicates. Earlier pages may be read again, but no work is lost and we do
    # not depend on pagination URLs staying valid across runs.
    for site_id in cfg.sites:
        if len(sessions) >= cfg.target_raw_sessions:
            break

        endpoint = urllib.parse.urljoin(cfg.base_url.rstrip("/") + "/", f"sessions/{site_id}")
        next_url: str | None = endpoint
        next_params: dict[str, Any] | None = {"where": where_clause, "sort": cfg.sort}
        page_no = 0
        site_added = 0
        site_seen_before = len(sessions)
        site_transient_pages = 0
        site_transient_events = 0
        consecutive_retry_pages = 0

        print(
            f"[acn] start site={site_id}, already_collected={len(sessions)}, "
            f"target_raw={cfg.target_raw_sessions}",
            flush=True,
        )

        while next_url and len(sessions) < cfg.target_raw_sessions:
            page_no += 1
            total_pages += 1
            try:
                resp, retry_events = request_with_retries(
                    requests_module=requests,
                    url=next_url,
                    params=next_params,
                    token=cfg.api_token,
                    timeout_s=cfg.timeout_s,
                    site_id=site_id,
                    page_no=page_no,
                    max_retries=max_retries_per_page,
                    base_backoff_s=base_backoff_s,
                    max_backoff_s=max_backoff_s,
                )
                if retry_events > 0:
                    site_transient_pages += 1
                    site_transient_events += retry_events
                    consecutive_retry_pages += 1
                else:
                    consecutive_retry_pages = 0

                breaker_reason = ""
                if max_consecutive_retry_pages > 0 and consecutive_retry_pages >= max_consecutive_retry_pages:
                    breaker_reason = f"consecutive_retry_pages={consecutive_retry_pages} >= {max_consecutive_retry_pages}"
                elif max_transient_pages_per_site > 0 and site_transient_pages >= max_transient_pages_per_site:
                    breaker_reason = f"transient_pages={site_transient_pages} >= {max_transient_pages_per_site}"
                elif max_transient_events_per_site > 0 and site_transient_events >= max_transient_events_per_site:
                    breaker_reason = f"transient_events={site_transient_events} >= {max_transient_events_per_site}"

                if breaker_reason:
                    state = {
                        "updated_at_utc": _now_utc_iso(),
                        "collected": len(sessions),
                        "target_raw_sessions": cfg.target_raw_sessions,
                        "current_site": site_id,
                        "current_site_page": page_no,
                        "total_pages_scanned": total_pages,
                        "new_sessions_this_run": new_sessions_this_run,
                        "partial_path": str(partial_path),
                        "breaker_reason": breaker_reason,
                        "action": "skip_site_by_circuit_breaker",
                    }
                    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
                    print(
                        f"[acn] circuit breaker for site={site_id} page={page_no}: {breaker_reason}; "
                        f"collected_total={len(sessions)}/{cfg.target_raw_sessions}; moving to next site",
                        flush=True,
                    )
                    break
            except RuntimeError as exc:
                # Large ACN downloads sometimes hit a bad deep-pagination window
                # for one site.  If we have already collected useful sessions
                # from this site, keep the checkpoint and continue with the next
                # site instead of losing all progress.
                state = {
                    "updated_at_utc": _now_utc_iso(),
                    "collected": len(sessions),
                    "target_raw_sessions": cfg.target_raw_sessions,
                    "current_site": site_id,
                    "failed_site_page": page_no,
                    "total_pages_scanned": total_pages,
                    "new_sessions_this_run": new_sessions_this_run,
                    "partial_path": str(partial_path),
                    "last_error": str(exc),
                    "action": "skip_site_after_page_failure" if allow_site_skip and len(sessions) > site_seen_before else "raise",
                }
                state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
                if allow_site_skip and len(sessions) > site_seen_before:
                    print(
                        f"[acn] warning: site={site_id} page={page_no} failed after retries; "
                        f"kept partial checkpoint rows={len(sessions)}; moving to next site. error={exc}",
                        flush=True,
                    )
                    break
                raise

            payload = resp.json()
            items = _extract_items(payload)
            new_rows: list[dict[str, Any]] = []
            for item in items:
                row = dict(item)
                row["_acn_site_id"] = site_id
                row["_downloaded_at_utc"] = _now_utc_iso()
                key = session_key(row)
                if key in seen:
                    continue
                seen.add(key)
                new_rows.append(row)
                sessions.append(row)
                site_added += 1
                new_sessions_this_run += 1
                if len(sessions) >= cfg.target_raw_sessions:
                    break

            if new_rows:
                append_jsonl(partial_path, new_rows)

            if checkpoint_every_pages > 0 and total_pages % checkpoint_every_pages == 0:
                state = {
                    "updated_at_utc": _now_utc_iso(),
                    "collected": len(sessions),
                    "target_raw_sessions": cfg.target_raw_sessions,
                    "current_site": site_id,
                    "current_site_page": page_no,
                    "total_pages_scanned": total_pages,
                    "new_sessions_this_run": new_sessions_this_run,
                    "partial_path": str(partial_path),
                }
                state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

            if progress_pages > 0 and (page_no == 1 or page_no % progress_pages == 0):
                print(
                    f"[acn] site={site_id} page={page_no} items={len(items)} "
                    f"new={len(new_rows)} collected={len(sessions)}/{cfg.target_raw_sessions} "
                    f"retry_pages={site_transient_pages} retry_events={site_transient_events}",
                    flush=True,
                )

            if max_pages_per_site > 0 and page_no >= max_pages_per_site:
                print(
                    f"[acn] max_pages_per_site reached for site={site_id}: "
                    f"page={page_no}, collected_total={len(sessions)}/{cfg.target_raw_sessions}; moving to next site",
                    flush=True,
                )
                break

            href = _extract_next_href(payload)
            next_url = _join_api_url(cfg.base_url, href) if href else None
            next_params = None

            if cfg.sleep_s > 0:
                time.sleep(cfg.sleep_s)

            if not items and not href:
                break

        print(
            f"[acn] done site={site_id}, added_site={site_added}, "
            f"collected_total={len(sessions)}/{cfg.target_raw_sessions}",
            flush=True,
        )

        if allow_site_skip and len(sessions) == site_seen_before:
            print(f"[acn] warning: site={site_id} added zero new sessions", flush=True)

    sessions = dedupe_sessions(sessions)
    if not sessions:
        raise RuntimeError("ACN download produced zero sessions. Check token, sites, and API availability.")

    if len(sessions) >= cfg.target_raw_sessions:
        sessions = sessions[: cfg.target_raw_sessions]
        save_raw_sessions_jsonl(sessions, raw_path)
        print(f"[acn] saved complete raw cache: {raw_path} rows={len(sessions)}", flush=True)
    else:
        print(
            f"[acn] warning: only collected {len(sessions)}/{cfg.target_raw_sessions}. "
            f"Partial checkpoint remains at {partial_path}",
            flush=True,
        )

    final_state = {
        "updated_at_utc": _now_utc_iso(),
        "collected": len(sessions),
        "target_raw_sessions": cfg.target_raw_sessions,
        "complete": len(sessions) >= cfg.target_raw_sessions,
        "partial_path": str(partial_path),
        "raw_path": str(raw_path),
        "new_sessions_this_run": new_sessions_this_run,
    }
    state_path.write_text(json.dumps(final_state, indent=2, sort_keys=True), encoding="utf-8")
    return sessions, partial_path, state_path, final_state


def write_target_specific_artifacts(
    *,
    df_normalized: pd.DataFrame,
    df_workload: pd.DataFrame,
    profiles: dict[str, pd.DataFrame],
    target_n: int,
    sites: Iterable[str],
    min_energy_kwh: float,
    update_defaults: bool,
) -> dict[str, Any]:
    ensure_acn_dirs()
    prefix = workload_cache_prefix(target_n, sites, min_energy_kwh)

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
        workload_default = PROCESSED_DIR / "dbas_workload_current.csv"
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
        "normalized_rows": int(len(df_normalized)),
        "workload_rows": int(len(df_workload)),
        "valid_profile_rows": int(len(profiles["valid_preauthorization"])),
        "original_profile_rows": int(len(profiles["original_cap"])),
        "undercap_topup_rows": int(len(profiles["undercap_topup"])),
        "update_defaults": bool(update_defaults),
        **default_paths,
    }


def load_or_download_raw_checkpointed(
    *,
    api_token: str,
    sites: tuple[str, ...],
    min_energy_kwh: float,
    raw_limit: int,
    timeout_s: int,
    sleep_s: float,
    force_download: bool,
    no_download: bool,
    resume: bool,
    progress_pages: int,
    checkpoint_every_pages: int,
    max_retries_per_page: int,
    base_backoff_s: float,
    max_backoff_s: float,
    max_pages_per_site: int,
    max_consecutive_retry_pages: int,
    max_transient_pages_per_site: int,
    max_transient_events_per_site: int,
    seed_jsonl_paths: list[str] | None,
) -> tuple[list[dict[str, Any]], Path, dict[str, Any], bool]:
    raw_path = raw_cache_path(sites=sites, min_energy_kwh=min_energy_kwh, raw_limit=raw_limit)
    if raw_path.exists() and not force_download:
        print(f"[acn] using complete raw cache: {raw_path}", flush=True)
        return load_raw_sessions_jsonl(raw_path), raw_path, {"cache_complete": True}, False

    if no_download:
        raise RuntimeError(f"cached raw ACN file not found and --no-download was set: {raw_path}")
    if not api_token:
        raise RuntimeError("ACN API token missing. Use ACN_API_TOKEN or --api-token-file.")

    cfg = ACNDownloadConfig(
        api_token=api_token,
        target_raw_sessions=raw_limit,
        sites=sites,
        min_energy_kwh=min_energy_kwh,
        timeout_s=timeout_s,
        sleep_s=sleep_s,
    )
    sessions, partial_path, state_path, state = fetch_acn_sessions_checkpointed(
        cfg,
        raw_path=raw_path,
        resume=resume and not force_download,
        progress_pages=progress_pages,
        checkpoint_every_pages=checkpoint_every_pages,
        max_retries_per_page=max_retries_per_page,
        base_backoff_s=base_backoff_s,
        max_backoff_s=max_backoff_s,
        allow_site_skip=True,
        max_pages_per_site=max_pages_per_site,
        max_consecutive_retry_pages=max_consecutive_retry_pages,
        max_transient_pages_per_site=max_transient_pages_per_site,
        max_transient_events_per_site=max_transient_events_per_site,
        seed_jsonl_paths=seed_jsonl_paths,
    )
    state.update({"partial_path": str(partial_path), "state_path": str(state_path)})
    return sessions, raw_path, state, True


def build_one_target(args: argparse.Namespace, *, target_n: int, api_token: str, sites: tuple[str, ...]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_limit = max(target_n, int(round(target_n * args.oversample_factor)))
    trace_rows: list[dict[str, Any]] = []
    last_error = ""

    for attempt in range(1, args.max_download_attempts + 1):
        current_raw_limit = int(round(raw_limit * (args.download_step_factor ** (attempt - 1))))
        try:
            sessions, raw_path, download_state, downloaded = load_or_download_raw_checkpointed(
                api_token=api_token,
                sites=sites,
                min_energy_kwh=args.min_kwh,
                raw_limit=current_raw_limit,
                timeout_s=args.timeout_s,
                sleep_s=args.sleep_s,
                force_download=args.force_download,
                no_download=args.no_download,
                resume=args.resume,
                progress_pages=args.progress_pages,
                checkpoint_every_pages=args.checkpoint_every_pages,
                max_retries_per_page=args.max_retries_per_page,
                base_backoff_s=args.base_backoff_s,
                max_backoff_s=args.max_backoff_s,
                max_pages_per_site=args.max_pages_per_site,
                max_consecutive_retry_pages=args.max_consecutive_retry_pages,
                max_transient_pages_per_site=args.max_transient_pages_per_site,
                max_transient_events_per_site=args.max_transient_events_per_site,
                seed_jsonl_paths=args.seed_jsonl,
            )
            df_norm = normalize_acn_sessions(sessions)
            df_workload = select_protocol_workload(df_norm, target_n=target_n)
            profiles = build_workload_profiles(df_workload)
            artifacts = write_target_specific_artifacts(
                df_normalized=df_norm,
                df_workload=df_workload,
                profiles=profiles,
                target_n=target_n,
                sites=sites,
                min_energy_kwh=args.min_kwh,
                update_defaults=args.update_defaults,
            )
            summary = profile_summary_record(
                df_workload=df_workload,
                profiles=profiles,
                raw_count=len(sessions),
                raw_path=raw_path,
                artifact_paths=artifacts,
                target_n=target_n,
                sites=sites,
                min_energy_kwh=args.min_kwh,
                raw_limit_used=current_raw_limit,
            )
            summary.update(
                {
                    "test_name": "acn_real_scale_checkpointed_download",
                    "status": "passed",
                    "downloaded_this_run": bool(downloaded),
                    "api_token_present": bool(api_token),
                    "api_token_stored_in_outputs": False,
                    "checkpoint_complete": bool(download_state.get("complete", True)),
                    "checkpoint_state_path": download_state.get("state_path", ""),
                    "partial_checkpoint_path": download_state.get("partial_path", ""),
                    "recommended_rbc_timing_cmd": (
                        f"PYTHONPATH=. python scripts/run_phase_timing_rbc.py --input-csv {artifacts['valid_profile_path']} "
                        f"--output-prefix rbc_real_acn_{target_n}_oqs --pq-backend oqs --kem-backend oqs --strict-pq"
                    ),
                    "recommended_topup_cmd": (
                        f"PYTHONPATH=. python scripts/run_topup_benchmark.py --input-csv {artifacts['undercap_topup_profile_path']} "
                        f"--output-prefix topup_real_acn_{target_n}"
                    ),
                }
            )
            trace_rows.append({"event": "target_passed", "target_n": target_n, **summary})
            return summary, trace_rows
        except Exception as exc:
            last_error = str(exc)
            trace_rows.append(
                {
                    "event": "target_attempt_failed",
                    "target_n": target_n,
                    "attempt": attempt,
                    "raw_limit": current_raw_limit,
                    "error": last_error,
                }
            )
            print(f"[acn] target={target_n} attempt={attempt} failed: {last_error}", flush=True)
            if attempt >= args.max_download_attempts:
                break
            time.sleep(min(args.max_backoff_s, args.base_backoff_s * attempt))

    raise RuntimeError(f"failed to build target={target_n}; last_error={last_error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Checkpointed ACN downloader for 10k/50k DBAS-ET workloads.")
    parser.add_argument("--targets", nargs="+", type=int, default=[10000])
    parser.add_argument("--sites", nargs="*", default=[])
    parser.add_argument("--site", action="append", default=[])
    parser.add_argument("--min-kwh", type=float, default=0.1)
    parser.add_argument("--oversample-factor", type=float, default=1.5)
    parser.add_argument("--max-download-attempts", type=int, default=2)
    parser.add_argument("--download-step-factor", type=float, default=1.3)
    parser.add_argument("--timeout-s", type=int, default=60)
    parser.add_argument("--sleep-s", type=float, default=0.10)
    parser.add_argument("--api-token", default="")
    parser.add_argument("--api-token-file", default="")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--no-download", action="store_true")
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--no-resume", dest="resume", action="store_false")
    parser.add_argument("--update-defaults", action="store_true")
    parser.add_argument("--output-prefix", default="acn_real_scale_checkpointed")
    parser.add_argument("--progress-pages", type=int, default=int(os.environ.get("ACN_PROGRESS_PAGES", "25")))
    parser.add_argument("--checkpoint-every-pages", type=int, default=1)
    parser.add_argument("--max-retries-per-page", type=int, default=int(os.environ.get("ACN_MAX_RETRIES_PER_PAGE", "12")))
    parser.add_argument("--base-backoff-s", type=float, default=float(os.environ.get("ACN_BASE_BACKOFF_S", "3")))
    parser.add_argument("--max-backoff-s", type=float, default=float(os.environ.get("ACN_MAX_BACKOFF_S", "120")))
    parser.add_argument(
        "--max-pages-per-site",
        type=int,
        default=int(os.environ.get("ACN_MAX_PAGES_PER_SITE", "0")),
        help="0 means no cap. Useful for avoiding deep-pagination 502 windows; e.g., 350.",
    )
    parser.add_argument(
        "--max-consecutive-retry-pages",
        type=int,
        default=int(os.environ.get("ACN_MAX_CONSECUTIVE_RETRY_PAGES", "3")),
        help="Skip current site after this many consecutive pages require retry. 0 disables.",
    )
    parser.add_argument(
        "--max-transient-pages-per-site",
        type=int,
        default=int(os.environ.get("ACN_MAX_TRANSIENT_PAGES_PER_SITE", "25")),
        help="Skip current site after this many pages with transient errors. 0 disables.",
    )
    parser.add_argument(
        "--max-transient-events-per-site",
        type=int,
        default=int(os.environ.get("ACN_MAX_TRANSIENT_EVENTS_PER_SITE", "60")),
        help="Skip current site after this many transient retry events. 0 disables.",
    )
    parser.add_argument(
        "--seed-jsonl",
        action="append",
        default=[],
        help="Optional existing partial/raw JSONL files to seed the session pool before downloading more.",
    )
    parser.add_argument(
        "--skip-sites",
        nargs="*",
        default=[],
        help="Sites to remove from --sites after loading any seed JSONL. Useful when a site is unhealthy.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sites = resolve_sites(args)
    if args.skip_sites:
        skip = {str(x).strip() for x in args.skip_sites if str(x).strip()}
        sites = tuple(site for site in sites if site not in skip)
        if not sites:
            raise SystemExit("all sites were removed by --skip-sites")
    api_token = read_api_token_from_env_or_file(args.api_token, args.api_token_file)
    tables_dir, traces_dir = ensure_output_dirs()

    print(
        json.dumps(
            {
                "event": "config",
                "targets": args.targets,
                "sites": sites,
                "min_kwh": args.min_kwh,
                "oversample_factor": args.oversample_factor,
                "api_token_present": bool(api_token),
                "api_token_stored_in_outputs": False,
                "resume": bool(args.resume),
                "max_consecutive_retry_pages": args.max_consecutive_retry_pages,
                "max_transient_pages_per_site": args.max_transient_pages_per_site,
                "max_transient_events_per_site": args.max_transient_events_per_site,
                "seed_jsonl": args.seed_jsonl,
                "skip_sites": args.skip_sites,
            },
            indent=2,
        ),
        flush=True,
    )

    summary_rows: list[dict[str, Any]] = []
    all_trace_rows: list[dict[str, Any]] = []
    for target_n in args.targets:
        summary, trace = build_one_target(args, target_n=target_n, api_token=api_token, sites=sites)
        summary_rows.append(summary)
        all_trace_rows.extend(trace)
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)

    summary_path = tables_dir / f"{args.output_prefix}_summary.csv"
    trace_path = traces_dir / f"{args.output_prefix}_trace.jsonl"
    write_csv(summary_path, summary_rows)
    write_jsonl(trace_path, all_trace_rows)

    print(
        json.dumps(
            {
                "status": "passed",
                "rows": len(summary_rows),
                "targets": args.targets,
                "sites": sites,
                "min_energy_kwh": args.min_kwh,
                "summary_path": str(summary_path),
                "trace_path": str(trace_path),
                "api_token_present": bool(api_token),
                "api_token_stored_in_outputs": False,
            },
            indent=2,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
