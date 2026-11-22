"""Checks the merged campaign outputs against the raw per-run files and writes
raw_audit.json and resource_uncertainty.csv."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from run_matched_campaign import GROUP_KEYS, METHODS, ROOT, bootstrap, percentile, write_csv, write_json


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def as_float(r, name):
    return float(r[name])


def audit(out, rows, summary, run_stats):
    cfg = json.loads((out / "config.json").read_text())
    assert len(list((out / "runs").glob("run_*/complete.json"))) == cfg["runs"]
    raw_rows = []
    for path in sorted((out / "runs").glob("run_*/raw/*.csv")):
        raw_rows.extend(read_csv(path))
    assert raw_rows == rows, "merged raw differs from group raw"
    expected = cfg["runs"] * (24 * cfg["sessions"] + 36 * cfg["fault_sessions"] + 60 * cfg["security_sessions"])
    assert len(rows) == expected
    phase_counts = Counter(r["phase"] for r in rows)
    assert all(not r["harness_error"] and r["unexpected_result"] == "False" for r in rows)
    assert all(r["accounting_ok"] == "True" for r in rows)
    by_run = defaultdict(list)
    for r in rows:
        key = tuple(r[k] for k in GROUP_KEYS) + (r["run_id"],)
        by_run[key].append(r)
        assert r["ok"] == r["expected_accept"]
        if r["ok"] == "True":
            assert r["ledger_state"] == "SETTLED"
            if r["scenario"] != "threshold_collusion_outside_safety":
                assert Decimal(r["captured"]) == Decimal(r["expected_amount"])
            else:
                assert Decimal(r["captured"]) > Decimal(r["expected_amount"])
        else:
            assert r["ledger_state"] == "RECEIPT_SUBMITTED"
        if r["mutation"] == "replay":
            assert r["replay_refused"] == "True"
    independent = defaultdict(list)
    for s in run_stats:
        key = tuple(s[k] for k in GROUP_KEYS) + (s["run_id"],)
        samples = [float(r[s["metric"]]) for r in by_run[key]]
        assert len(samples) == int(s["sample_count"])
        assert math.isclose(statistics.median(samples), float(s["median"]), abs_tol=1e-9)
        assert math.isclose(percentile(samples, .95), float(s["p95"]), abs_tol=1e-9)
        independent[key[:-1] + (s["metric"],)].append(s)
    for s in summary:
        key = tuple(s[k] for k in GROUP_KEYS) + (s["metric"],)
        run_s = independent[key]
        assert int(s["independent_runs"]) == cfg["runs"] == len(run_s)
        assert math.isclose(statistics.median(float(r["median"]) for r in run_s),
                            float(s["median_of_run_medians"]), abs_tol=1e-9)
        assert math.isclose(statistics.median(float(r["p95"]) for r in run_s),
                            float(s["median_of_run_p95s"]), abs_tol=1e-9)
        assert float(s["median_ci95_low"]) <= float(s["median_of_run_medians"]) <= float(s["median_ci95_high"])
    manifest = json.loads((out / "source_data_sha256.json").read_text())
    current_aggregation_hash = ""
    for name, expected_hash in manifest.items():
        path = ROOT / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_hash:
            assert name == "scripts/dvas/run_matched_campaign.py", f"unexplained source change: {name}"
            archive = out / "measured_source/run_matched_campaign.py"
            assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected_hash
            before = archive.read_text()
            after = path.read_text()
            assert before.replace('"n": len(vals)', '"sample_count": len(vals)') == after
            current_aggregation_hash = actual
    resources = []
    first_ns, last_ns = None, None
    for path in sorted((out / "runs").glob("run_*/resources/*.json")):
        r = json.loads(path.read_text())
        samples = r["resource_samples"]
        low, high = min(v["timestamp_ns"] for v in samples), max(v["timestamp_ns"] for v in samples)
        first_ns = low if first_ns is None else min(first_ns, low)
        last_ns = high if last_ns is None else max(last_ns, high)
        key = tuple(str(r[k]) for k in GROUP_KEYS) + (str(r["run_id"]),)
        if r["method"] != METHODS[0]:
            assert r["coordinator_pid"] not in r["worker_pids"]
            for session in by_run[key]:
                responding = {int(p) for p in session["responding_pids"].split(",") if p}
                assert responding <= set(r["worker_pids"])
                if session["ok"] == "True":
                    assert len(responding) >= r["t"]
        resources.append(r)
    windows = []
    for line in (out / "windows_host.jsonl").read_text(encoding="utf-8-sig").splitlines():
        r = json.loads(line)
        ns = int(datetime.fromisoformat(r["timestamp_utc"].replace("Z", "+00:00")).timestamp() * 1e9)
        if first_ns <= ns <= last_ns:
            windows.append(r)
    assert windows
    result = dict(verified_at_utc=datetime.now(timezone.utc).isoformat(),
        verification="raw_audit_passed", measured_attempts=len(rows), phase_counts=dict(phase_counts),
        independent_runs=cfg["runs"], groups=len(resources), harness_errors=0, unexpected_results=0,
        healthy_rejections=0, healthy_denominator=phase_counts["healthy"],
        security_negative_count=sum(r["phase"] == "security" and r["mutation"] != "replay" for r in rows),
        replay_refusals=sum(r["mutation"] == "replay" for r in rows),
        outside_model_collusion_cases=sum(r["scenario"] == "threshold_collusion_outside_safety" for r in rows),
        measured_core_source_hashes_unchanged=True,
        aggregation_correction=dict(description="preserve verifier n; rename per-run metric sample count to sample_count",
            archived_original="measured_source/run_matched_campaign.py", corrected_sha256=current_aggregation_hash),
        windows_samples=len(windows),
        windows_cpu_percent=dict(median=statistics.median(r["host_cpu_percent"] for r in windows),
            p95=percentile([r["host_cpu_percent"] for r in windows], .95), max=max(r["host_cpu_percent"] for r in windows)),
        windows_free_ram_gib=dict(min=min(r["free_ram_kib"] for r in windows) / 1024**2,
            max=max(r["free_ram_kib"] for r in windows) / 1024**2),
        measurement_window_utc=dict(start=datetime.fromtimestamp(first_ns / 1e9, timezone.utc).isoformat(),
            end=datetime.fromtimestamp(last_ns / 1e9, timezone.utc).isoformat()))
    write_json(out / "raw_audit.json", result)
    return result, resources


def resource_summary(out, resources, seed):
    grouped = defaultdict(list)
    metrics = ("group_cpu_ms_per_attempt", "sampled_peak_rss_sum_kib", "sampled_peak_pss_sum_kib", "setup_ms")
    for r in resources:
        grouped[tuple(str(r[k]) for k in GROUP_KEYS)].append(r)
    summary = []
    for idx, (key, rows) in enumerate(sorted(grouped.items())):
        for j, metric in enumerate(metrics):
            vals = [r[metric] for r in rows]
            lo, hi = bootstrap(vals, seed + 300000 + idx * 4 + j)
            summary.append({**dict(zip(GROUP_KEYS, key)), "metric": metric, "independent_runs": len(rows),
                "median_of_runs": statistics.median(vals), "ci95_low": lo, "ci95_high": hi,
                "run_min": min(vals), "run_max": max(vals)})
    write_csv(out / "resource_uncertainty.csv", summary)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "outputs/matched_benchmark_20261013")
    args = ap.parse_args()
    out = args.out.resolve()
    rows = read_csv(out / "all_sessions.csv")
    summary = read_csv(out / "summary_uncertainty.csv")
    run_stats = read_csv(out / "run_statistics.csv")
    a, resources = audit(out, rows, summary, run_stats)
    resource_summary(out, resources, 20261013)
    print(json.dumps(a, indent=2))


if __name__ == "__main__":
    main()
