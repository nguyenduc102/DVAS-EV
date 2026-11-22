"""Independent-process, matched DVAS experiment campaign.

Run through scripts/env/dvas_run.sh under Linux/WSL. --prepare-only does
not generate keys, spawn verifiers, or measure performance. No host process
is stopped by this program. Each run only appends to its outputs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from dbas_et.dvas.attacks import unique
from dbas_et.dvas.matched_benchmark import METHODS, ResourceSampler, WorkerCluster, proc_cpu_ns, run_session
from dbas_et.dvas.profiles import PROFILES
from dbas_et.dvas.protocol import DvasEnvironment
from dbas_et.dvas.workload import ACN_VALID, MFEV_VALID_5K, acn_sessions, honest_amount, mfev_sessions
from bench_env import environment_metadata, percentile

DEFAULT_OUT = ROOT / "outputs" / "matched_benchmark_20261013"
GROUP_KEYS = ("phase", "method", "profile", "dataset", "n", "t", "scenario", "mutation")
METRICS = ("elapsed_ms", "verification_release_ms", "quorum_elapsed_ms", "parent_cpu_ms",
           "public_application_bytes", "private_application_bytes", "decision_bytes",
           "tcp_sent_bytes", "tcp_received_bytes", "worker_cpu_received_ms")
MUTATIONS = ("tariff_swap", "over_cap", "private_substitution", "incomplete_opening", "replay")


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path, rows):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)


def workload(dataset, count, seed, *, headroom=False):
    loader = acn_sessions if dataset == "ACN" else mfev_sessions
    pool = loader(max_rows=max(1000, count * 5))
    # This primary campaign studies no-top-up, valid preauthorization.
    # Eligibility is semantic and frozen before measuring, never timing based.
    valid = [s for s in pool if not s.expected_undercap and s.delivered_kwh <= s.cap_kwh
             and honest_amount(s) <= s.preauth_limit
             and (not headroom or s.preauth_limit > honest_amount(s))]
    random.Random(seed).shuffle(valid)
    if len(valid) < count:
        raise ValueError(f"not enough valid {dataset} records: {len(valid)} < {count}")
    return valid[:count]


def scenarios(n, t, deadline):
    ids = [f"SV{i}" for i in range(1, n + 1)]
    base = {"deadline_ms": deadline}
    return [
        ("delay_5ms_each_direction", dict(base, delay_ms=5), [], True, "honest"),
        ("delay_25ms_jitter_0to5ms_each_direction", dict(base, delay_ms=25, jitter_ms=5), [], True, "honest"),
        ("offline_tolerated", base, ids[:n-t], True, "honest"),
        ("offline_beyond_liveness", base, ids[:n-t+1], False, "honest"),
        ("withholding_tolerated", dict(base, withholding=ids[:n-t]), [], True, "honest"),
        ("withholding_beyond_liveness", dict(base, withholding=ids[:n-t+1]), [], False, "honest"),
        ("one_inflating_verifier", dict(base, behaviors={ids[0]: "inflate"}), [], True, "honest"),
        ("one_inflating_plus_offline", dict(base, behaviors={ids[0]: "inflate"}), ids[1:n-t+1], False, "honest"),
        ("threshold_collusion_outside_safety", dict(base, behaviors={v: "inflate" for v in ids[:t]}), [], True, "honest"),
    ]


def plan(config):
    groups = []
    for profile in ("C0", "C3"):
        for dataset in ("ACN", "MFEV"):
            for n, t in ((3, 2), (5, 3)):
                for method in METHODS:
                    groups.append(dict(phase="healthy", method=method, profile=profile, dataset=dataset,
                        n=n, t=t, scenario="healthy", mutation="honest", count=config["sessions"],
                        warmup=config["warmup"], expected_accept=True,
                        fault={"deadline_ms": config["healthy_deadline_ms"]}, offline=[]))
    for n, t in ((3, 2), (5, 3)):
        for method in METHODS[1:]:
            for name, fault, offline, expected, mutation in scenarios(n, t, config["fault_deadline_ms"]):
                groups.append(dict(phase="fault", method=method, profile="C3", dataset="ACN", n=n, t=t,
                    scenario=name, mutation=mutation, count=config["fault_sessions"], warmup=2,
                    expected_accept=expected, fault=fault, offline=offline))
    for profile in ("C0", "C3"):
        for n, t in ((3, 2), (5, 3)):
            for method in METHODS:
                for mutation in MUTATIONS:
                    groups.append(dict(phase="security", method=method, profile=profile, dataset="ACN",
                        n=n, t=t, scenario="attack_probe", mutation=mutation,
                        count=config["security_sessions"], warmup=0, expected_accept=mutation == "replay",
                        fault={"deadline_ms": config["healthy_deadline_ms"]}, offline=[]))
    return groups


def group_run(config, group, run_id, ordinal, out):
    count = group["count"] + group["warmup"]
    # Paired workload order across methods/profiles/quorum sizes within a run.
    specs = workload(group["dataset"], count, config["seed"] + run_id * 1009,
                     headroom=group["phase"] == "fault")
    specs = [unique(s, f"r{run_id:02d}-g{ordinal:03d}-s{i:05d}") for i, s in enumerate(specs)]
    setup0 = time.perf_counter_ns()
    env = DvasEnvironment(profile=PROFILES[group["profile"]], n=group["n"], t=group["t"])
    for s in specs:
        env.register_spec(s)
    cluster = None
    rows = []
    gid = f"g{ordinal:03d}"
    try:
        if group["method"] != METHODS[0]:
            cluster = WorkerCluster(env, group["profile"])
            cluster.offline(group["offline"])
        else:
            env.verifiers.clear()  # public execution retains no unused verifier private keys
        setup_ms = (time.perf_counter_ns() - setup0) / 1e6
        for i in range(group["warmup"]):
            run_session(env, specs[i], group["method"], cluster, scenario=group["fault"],
                        mutation=group["mutation"], seed=config["seed"] + i)
        pids = [os.getpid()] + (cluster.pids if cluster else [])
        cpu0 = {pid: proc_cpu_ns(pid) for pid in pids}
        group_start = time.perf_counter_ns()
        with ResourceSampler(pids) as sampler:
            for i, spec in enumerate(specs[group["warmup"]:]):
                identity = {k: group[k] for k in GROUP_KEYS}
                identity.update(run_id=run_id, group_id=gid, sample=i, row_index=spec.row_index,
                                expected_accept=group["expected_accept"])
                try:
                    result = run_session(env, spec, group["method"], cluster, scenario=group["fault"],
                                         mutation=group["mutation"], seed=config["seed"] + run_id * 1009 + i)
                    exact = str(honest_amount(spec))
                    expected_semantics = group["scenario"] != "threshold_collusion_outside_safety"
                    bad = result["ok"] != group["expected_accept"] or not result["accounting_ok"]
                    if result["ok"] and expected_semantics:
                        from decimal import Decimal
                        bad |= Decimal(result["captured"]) != honest_amount(spec) or not result["accounting_ok"]
                    if group["mutation"] == "replay":
                        bad |= result["replay_refused"] is not True
                    identity.update(result, expected_amount=exact, unexpected_result=bad, harness_error="")
                except Exception as exc:
                    identity.update(harness_error=f"{type(exc).__name__}: {exc}", unexpected_result=True)
                rows.append(identity)
            # Include late worker work in CPU/resource accounting, outside session latency.
            drain_ms = 2 * (group["fault"].get("delay_ms", 0) + group["fault"].get("jitter_ms", 0)) + 10
            time.sleep(drain_ms / 1000)
        wall_ms = (time.perf_counter_ns() - group_start) / 1e6
        cpu_ns = sum(max(0, proc_cpu_ns(pid) - cpu0[pid]) for pid in pids)
        resource = {k: group[k] for k in GROUP_KEYS}
        resource.update(run_id=run_id, group_id=gid, coordinator_pid=os.getpid(), worker_pids=pids[1:],
            measured_sessions=group["count"], setup_ms=setup_ms,
            worker_startup_ms=cluster.startup_s * 1000 if cluster else 0,
            registry_snapshot_bytes_fanout=cluster.control_bytes if cluster else 0,
            group_wall_ms=wall_ms, post_group_drain_ms=drain_ms,
            total_group_cpu_ms=cpu_ns / 1e6, group_cpu_ms_per_attempt=cpu_ns / 1e6 / group["count"],
            sampled_peak_rss_sum_kib=max(r["rss_sum_kib"] for r in sampler.rows),
            sampled_peak_pss_sum_kib=max(r["pss_sum_kib"] for r in sampler.rows),
            resource_samples=sampler.rows)
        write_json(out / "resources" / f"{gid}.json", resource)
        write_csv(out / "raw" / f"{gid}.csv", rows)
    finally:
        if cluster:
            cluster.close()
    return {**{k: group[k] for k in GROUP_KEYS}, "run_id": run_id, "group_id": gid,
            "rows": len(rows), "harness_errors": sum(bool(r["harness_error"]) for r in rows),
            "unexpected_results": sum(r["unexpected_result"] for r in rows)}


def child(config, out, run_id):
    run_out = out / "runs" / f"run_{run_id:02d}"
    run_out.mkdir(parents=True, exist_ok=False)
    groups = plan(config)
    random.Random(config["seed"] + run_id * 7919).shuffle(groups)
    write_json(run_out / "order.json", groups)
    completed = []
    for ordinal, group in enumerate(groups):
        result = group_run(config, group, run_id, ordinal, run_out)
        completed.append(result)
        write_json(run_out / "progress.json", completed)
        print(json.dumps({"run_id": run_id, "group": ordinal + 1, "total": len(groups), **result}), flush=True)
    write_json(run_out / "complete.json", {"groups": len(completed), "pid": os.getpid()})


def bootstrap(values, seed):
    if len(values) < 2:
        return min(values), max(values)
    rng = random.Random(seed)
    draws = [statistics.median(rng.choices(values, k=len(values))) for _ in range(5000)]
    return percentile(draws, .025), percentile(draws, .975)


def summarize(out, config):
    by_run = defaultdict(list)
    all_rows = []
    for path in sorted((out / "runs").glob("run_*/raw/*.csv")):
        with path.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        all_rows.extend(rows)
        for r in rows:
            by_run[tuple(r[k] for k in GROUP_KEYS) + (r["run_id"],)].append(r)
    summaries, run_stats, validation = [], [], []
    estimates = defaultdict(list)
    for key, rows in sorted(by_run.items()):
        base = dict(zip((*GROUP_KEYS, "run_id"), key))
        valid = [r for r in rows if not r["harness_error"]]
        attempts = len(rows)
        accepted = sum(r.get("ok") == "True" for r in valid)
        expected_accept = rows[0]["expected_accept"] == "True"
        validation.append({**base, "attempts": attempts, "harness_errors": attempts - len(valid),
            "accepted": accepted, "rejected_or_unsettled": len(valid) - accepted,
            "unexpected_results": sum(r["unexpected_result"] == "True" for r in rows),
            "honest_rejections": len(valid)-accepted if base["phase"] == "healthy" else "",
            "attack_false_accepts": accepted if base["phase"] == "security" and not expected_accept else "",
            "expected_accept": expected_accept})
        for metric in METRICS:
            vals = [float(r[metric]) for r in valid if metric in r and r[metric] != ""]
            if not vals:
                continue
            med, p95 = statistics.median(vals), percentile(vals, .95)
            run_stats.append({**base, "metric": metric, "sample_count": len(vals), "median": med, "p95": p95,
                              "min": min(vals), "max": max(vals)})
            estimates[key[:-1] + (metric,)].append((int(base["run_id"]), med, p95))
    for idx, (key, vals) in enumerate(sorted(estimates.items())):
        medians, p95s = [v[1] for v in vals], [v[2] for v in vals]
        lo, hi = bootstrap(medians, config["seed"] + idx)
        plo, phi = bootstrap(p95s, config["seed"] + idx + 100000)
        summaries.append({**dict(zip((*GROUP_KEYS, "metric"), key)), "independent_runs": len(vals),
            "median_of_run_medians": statistics.median(medians), "median_ci95_low": lo, "median_ci95_high": hi,
            "median_of_run_p95s": statistics.median(p95s), "p95_ci95_low": plo, "p95_ci95_high": phi,
            "run_median_min": min(medians), "run_median_max": max(medians)})
    resources = []
    for path in sorted((out / "runs").glob("run_*/resources/*.json")):
        r = json.loads(path.read_text())
        r.pop("resource_samples")
        resources.append(r)
    write_csv(out / "all_sessions.csv", all_rows)
    write_csv(out / "run_statistics.csv", run_stats)
    write_csv(out / "summary_uncertainty.csv", summaries)
    write_csv(out / "validation.csv", validation)
    write_csv(out / "resource_summary.csv", resources)
    # Pair independent-run summaries by workload/configuration. Bootstrap runs,
    # not individual sessions. Positive difference means selective is slower.
    paired = []
    matched = defaultdict(dict)
    for r in run_stats:
        if r["phase"] != "healthy":
            continue
        k = (r["profile"], r["dataset"], r["n"], r["t"], r["metric"], r["run_id"])
        matched[k][r["method"]] = r["median"]
    differences = defaultdict(list)
    for k, values in matched.items():
        if METHODS[2] not in values:
            continue
        for baseline in METHODS[:2]:
            if baseline in values:
                differences[k[:-1] + (baseline,)].append(values[METHODS[2]] - values[baseline])
    for idx, (k, values) in enumerate(sorted(differences.items())):
        lo, hi = bootstrap(values, config["seed"] + 200000 + idx)
        paired.append({**dict(zip(("profile", "dataset", "n", "t", "metric", "baseline"), k)),
            "comparison": "DVASSelectiveQuorum-minus-baseline", "independent_runs": len(values),
            "median_paired_run_difference": statistics.median(values), "ci95_low": lo, "ci95_high": hi})
    write_csv(out / "paired_differences.csv", paired)
    report = ["# Matched DVAS measured-process campaign", "",
        "Status: measured results; consult config.json, environment.json and per-run raw files.", "",
        f"Independent fresh coordinator runs: {len(list((out / 'runs').glob('run_*/complete.json')))}.",
        f"Measured attempts: {len(all_rows)}. Harness errors: {sum(bool(r['harness_error']) for r in all_rows)}.",
        f"Unexpected outcomes: {sum(r['unexpected_result'] == 'True' for r in all_rows)}.", "",
        "95% intervals resample independent run medians or P95s, 5,000 fixed-seed bootstrap draws. "
        "Five runs offer limited precision; raw session counts do not increase the independent-run count.", "",
        "## Healthy results", "",
        "|Method|Profile|Data|t/n|Protocol elapsed ms (95% run CI)|P95 ms|Public serialized B|Private application B|",
        "|---|---|---|---|---|---|---|---|"]
    lookup = {tuple(s[k] for k in GROUP_KEYS) + (s["metric"],): s for s in summaries}
    for s in summaries:
        if s["phase"] != "healthy" or s["metric"] != "elapsed_ms":
            continue
        key = tuple(s[k] for k in GROUP_KEYS)
        pub = lookup[key + ("public_application_bytes",)]["median_of_run_medians"]
        priv = lookup[key + ("private_application_bytes",)]["median_of_run_medians"]
        report.append(f"|{s['method']}|{s['profile']}|{s['dataset']}|{s['t']}/{s['n']}|"
            f"{s['median_of_run_medians']:.3f} [{s['median_ci95_low']:.3f}, {s['median_ci95_high']:.3f}]|"
            f"{s['median_of_run_p95s']:.3f}|{pub:.0f}|{priv:.0f}|")
    report.extend(["", "Full scenario/rejection/CPU/memory results are in validation.csv, "
                   "summary_uncertainty.csv and resource_summary.csv. See METHODOLOGY.md for interpretation."])
    (out / "RESULTS.md").write_text("\n".join(report) + "\n", encoding="utf-8")


def freeze(out, config):
    out.mkdir(parents=True, exist_ok=True)
    cfg = out / "config.json"
    if cfg.exists() and json.loads(cfg.read_text()) != config:
        raise ValueError("existing frozen configuration differs; choose a new output directory")
    write_json(cfg, config)
    write_json(out / "planned_groups.json", plan(config))
    source_paths = sorted((ROOT / "dbas_et" / "dvas").glob("*.py")) + [Path(__file__), ROOT / "scripts/dvas/bench_env.py",
        ROOT / "tests/dvas/test_matched_benchmark.py", ACN_VALID, MFEV_VALID_5K]
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths if p.exists()}
    manifest = out / "source_data_sha256.json"
    if (out / "runs").exists() and manifest.exists() and json.loads(manifest.read_text()) != hashes:
        raise ValueError("source changed during campaign; use a new output directory")
    write_json(manifest, hashes)
    # Preflight only parses deterministic inputs. No crypto or timing begins.
    for dataset in ("ACN", "MFEV"):
        workload(dataset, config["sessions"] + config["warmup"], config["seed"])
    workload("ACN", config["fault_sessions"] + 2, config["seed"], headroom=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--fault-sessions", type=int, default=12)
    ap.add_argument("--security-sessions", type=int, default=10)
    ap.add_argument("--seed", type=int, default=20261013)
    ap.add_argument("--healthy-deadline-ms", type=float, default=1000)
    ap.add_argument("--fault-deadline-ms", type=float, default=150)
    ap.add_argument("--prepare-only", action="store_true")
    ap.add_argument("--summarize-only", action="store_true")
    ap.add_argument("--child-run", type=int)
    args = ap.parse_args()
    if min(args.runs, args.sessions, args.fault_sessions, args.security_sessions) < 1 or args.warmup < 0:
        ap.error("counts must be positive, warmup nonnegative")
    out = args.out.resolve()
    config = {k: v for k, v in vars(args).items() if k not in ("out", "prepare_only", "summarize_only", "child_run")}
    if args.child_run is not None:
        child(json.loads((out / "config.json").read_text()), out, args.child_run)
        return 0
    if args.summarize_only:
        summarize(out, json.loads((out / "config.json").read_text()))
        return 0
    freeze(out, config)
    if args.prepare_only:
        print(f"Prepared {len(plan(config))} groups/run; no measurements started: {out}")
        return 0
    if (out / "runs").exists():
        raise ValueError("campaign already started; choose new directory, or --summarize-only")
    md = environment_metadata()
    md["scope"] = "measured_loopback_multiprocess_protocol_not_EV_or_blockchain_latency"
    md["clock"] = time.get_clock_info("perf_counter")._asdict() if hasattr(time.get_clock_info("perf_counter"), "_asdict") else vars(time.get_clock_info("perf_counter"))
    write_json(out / "environment.json", md)
    for run_id in range(1, config["runs"] + 1):
        subprocess.run([sys.executable, str(Path(__file__)), "--out", str(out), "--child-run", str(run_id)], check=True)
    summarize(out, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
