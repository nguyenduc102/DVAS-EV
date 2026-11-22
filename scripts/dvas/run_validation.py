"""Runs all validation checks and writes

  outputs/validation.md     criteria table + environment + commands
  outputs/validation_results.csv       one row per check (metric, value, expected, pass)
  outputs/raw/regression_rows.csv       per-row legacy-vs-DVAS settlement comparison

Prerequisite outputs (produced by the other runners, executed here unless --skip-experiments):
  attack_results.csv, pam_ablation.csv, pq_ablation.csv, timing_raw.csv, baselines.csv,
  multi_operator_summary.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, RAW, ROOT, environment_metadata, write_csv  # noqa: E402

PY = sys.executable
RESULTS: list[dict] = []


def check(cid: str, name: str, metric: str, value, expected: str, ok: bool, note: str = "") -> None:
    RESULTS.append({"criterion": cid, "check": name, "metric": metric, "value": value, "expected": expected,
                    "pass": bool(ok), "note": note})
    print(f"[{'PASS' if ok else 'FAIL'}] {cid} {name}: {metric}={value} (expected {expected})", flush=True)


def run(cmd: list[str], cwd: Path = ROOT, timeout: int = 3600) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# 1-2: regression vs the unchanged legacy pipeline
# ---------------------------------------------------------------------------

def legacy_outcomes(path: Path, n: int, flow: str, topup: bool) -> dict[int, tuple[bool, Decimal | None]]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import benchmark_common as bc  # legacy harness, unchanged

    df = bc.load_profile_csv(path, max_rows=n)
    env = bc.build_benchmark_environment(df, pq_backend="oqs", kem_backend="oqs", strict_pq=True)
    out = {}
    for idx, row in df.iterrows():
        rec, _ = bc.run_one_workload_row(env, row, int(idx), flow, apply_topup=topup)
        cap = rec.get("captured_amount")
        out[int(idx)] = (bool(rec.get("settlement_ok")), Decimal(str(cap)).quantize(Decimal("0.000001")) if cap is not None else None)
    return out


def regression(rows_out: list[dict], n: int) -> None:
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import ACN_ORIGINAL_CAP, ACN_TOPUP, ACN_VALID, acn_sessions, mfev_sessions

    cases = [("acn_valid", ACN_VALID, "valid", False), ("acn_original_cap", ACN_ORIGINAL_CAP, "original_cap", False),
             ("acn_topup", ACN_TOPUP, "topup", True)]
    for label, path, flow, topup in cases:
        specs = acn_sessions(path, max_rows=n)
        legacy = legacy_outcomes(path, len(specs), flow, topup)
        env = DvasEnvironment(profile=PROFILES["C3"])
        from dbas_et.dvas.tariff import tariff_amount

        agree = settled = exact = 0
        explained: list[int] = []
        exp_settle = 0
        max_err = Decimal(0)
        t0 = time.perf_counter()
        for sp in specs:
            r = env.run(sp, topup=topup)
            l_ok, l_cap = legacy[sp.row_index]
            same = (r.ok == l_ok) and (not r.ok or r.captured == l_cap or abs(r.captured - l_cap) <= Decimal("0.000001"))
            exact_amount = tariff_amount(mode=sp.tariff_mode, unit_price=sp.unit_price, delivered_kwh=sp.delivered_kwh,
                                         connection_duration_s=sp.connection_duration_s,
                                         active_charging_duration_s=sp.active_charging_duration_s,
                                         parking_duration_s=sp.parking_duration_s)
            exp_settle += exact_amount <= sp.preauth_limit + (sp.topup_delta if topup else 0)
            # legacy float tolerance (MONEY_EPS=1e-5) can capture slightly more than the hold
            legacy_over_hold = l_ok and not r.ok and l_cap is not None and l_cap > sp.preauth_limit
            if not same and legacy_over_hold:
                explained.append(sp.row_index)
            agree += same
            settled += r.ok
            if r.ok:
                err = abs(r.captured - sp.expected_amount)
                max_err = max(max_err, err)
                exact += err == 0
            if topup and r.ok:
                assert env.ledger.records[sp.tid].topup_count == 1
            rows_out.append({"workload": label, "row_index": sp.row_index, "legacy_ok": l_ok, "legacy_captured": l_cap,
                             "dvas_ok": r.ok, "dvas_stage": r.stage, "dvas_code": r.code[:120],
                             "dvas_captured": r.captured, "expected_amount": sp.expected_amount,
                             "exact_tariff_amount": exact_amount,
                             "expected_undercap": sp.expected_undercap, "agree": same,
                             "explained_legacy_over_hold": (not same) and legacy_over_hold})
        el = time.perf_counter() - t0
        cid = {"acn_valid": "1", "acn_original_cap": "2", "acn_topup": "2"}[label]
        check(cid, f"{label}: DVAS outcome == legacy outcome (or explained legacy over-hold capture)",
              "agree+explained", f"{agree}+{len(explained)}/{len(specs)}", f"{len(specs)}/{len(specs)}",
              agree + len(explained) == len(specs),
              f"explained rows (legacy captured > hold via MONEY_EPS): {explained}" if explained else "")
        check(cid, f"{label}: settled == rows whose exact tariff amount <= hold", "settled", settled, str(exp_settle),
              settled == exp_settle, f"{el:.1f}s; max|captured-expected|={max_err}")
        check(cid, f"{label}: captured amount vs dataset expected_amount", "max_abs_error", str(max_err), "<= 1e-6",
              max_err <= Decimal("0.000001"), f"exact={exact}")
    specs = mfev_sessions(max_rows=n)
    env = DvasEnvironment(profile=PROFILES["C3"])
    res = [env.run(sp) for sp in specs]
    ok = sum(r.ok for r in res)
    err = max((abs(r.captured - s.expected_amount) for r, s in zip(res, specs) if r.ok), default=Decimal(0))
    check("1", "mfev_valid: all sessions settle", "settled", f"{ok}/{len(specs)}", "all", ok == len(specs), f"max_err={err}")


# ---------------------------------------------------------------------------
# quorum / availability / malicious verifier at workload scale
# ---------------------------------------------------------------------------

def quorum_scale(n: int) -> None:
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import acn_sessions, honest_amount

    specs = acn_sessions(max_rows=n)
    for cid, label, beh in [("6", "2-of-3 all honest", {}), ("7", "one malicious (inflate)", {"SV2": "inflate"}),
                            ("7", "one malicious (approve_all)", {"SV1": "approve_all"}),
                            ("7", "one malicious (wrong_root)", {"SV3": "wrong_root"}),
                            ("8", "one unavailable verifier", {"SV3": "offline"})]:
        env = DvasEnvironment(profile=PROFILES["C3"], behaviors=beh)
        res = [env.run(sp) for sp in specs]
        good = sum(r.ok and r.captured == honest_amount(sp) for r, sp in zip(res, specs))
        check(cid, f"quorum: {label}", "settled_with_honest_amount", f"{good}/{len(specs)}", "all", good == len(specs))
    env = DvasEnvironment(profile=PROFILES["C3"], behaviors={"SV2": "offline", "SV3": "offline"})
    res = [env.run(sp) for sp in specs[:20]]
    check("8", "quorum: two unavailable verifiers cannot settle (liveness bound)", "settled",
          sum(r.ok for r in res), "0", sum(r.ok for r in res) == 0)


# ---------------------------------------------------------------------------
# test suites
# ---------------------------------------------------------------------------

def pytest_suite() -> None:
    p = run([PY, "-m", "pytest", "tests", "-p", "no:cacheprovider"], timeout=7200)
    m = re.search(r"(\d+) passed", p.stdout)
    f = re.search(r"(\d+) failed", p.stdout)
    passed, failed = int(m.group(1)) if m else 0, int(f.group(1)) if f else 0
    (RAW / "pytest_output.txt").write_text(p.stdout[-20000:] + p.stderr[-5000:])
    check("tests", "pytest (DVAS-EV unit/integration + legacy regression)", "passed/failed",
          f"{passed}/{failed}", "failed=0", p.returncode == 0 and failed == 0)


def forge_suite() -> None:
    forge = Path.home() / ".foundry" / "bin" / "forge"
    if not forge.exists():
        check("17", "forge test", "status", "forge not installed", "pass", False)
        return
    p = run([str(forge), "test", "-vv"], cwd=ROOT / "foundry", timeout=1800)
    (RAW / "forge_output.txt").write_text(p.stdout[-40000:])
    m = re.search(r"(\d+) tests passed, (\d+) failed", p.stdout)
    gas: dict[str, str] = {}
    gas_rows = []
    suite = ""
    for line in p.stdout.splitlines():
        ms = re.match(r"Ran \d+ tests? for test/([^:]+)", line)
        if ms:
            suite = ms.group(1)
        mg = re.search(r"GAS_RESULT (\S+) (\d+)", line)
        if mg:
            contract = "DVASQuorumSettle" if suite.startswith("DVASQuorumSettle") else suite.split(".")[0]
            gas_rows.append({"contract_suite": contract, "measurement": mg.group(1), "gas": int(mg.group(2)),
                             "note": "gasleft() delta around the call inside a Foundry test; excludes 21k intrinsic + calldata"})
            if contract == "DVASQuorumSettle":
                gas[mg.group(1)] = mg.group(2)
    write_csv(OUT / "solidity_gas.csv", gas_rows)
    check("17", "forge test (legacy + DVASQuorumSettle)", "passed/failed",
          f"{m.group(1)}/{m.group(2)}" if m else "?", "failed=0", p.returncode == 0 and bool(m) and m.group(2) == "0",
          f"releaseByQuorumRBC_2of3={gas.get('releaseByQuorumRBC_2of3')} gas")


# ---------------------------------------------------------------------------
# experiment outputs
# ---------------------------------------------------------------------------

def experiments(skip: bool, a: argparse.Namespace) -> None:
    D = ROOT / "scripts" / "dvas"
    if not skip:
        for script, args in [("run_attack_suite.py", ["--rows", str(a.attack_rows), "--mfev-rows", "10", "--random", str(a.attack_random)]),
                             ("run_pam_ablation.py", ["--capsules", str(a.ablation_capsules), "--repeats", "15"]),
                             ("run_pq_ablation.py", ["--sessions", str(a.pq_sessions), "--warmup", "30"]),
                             ("run_baselines.py", ["--sessions", "200", "--warmup", "20", "--attack-rows", "30"]),
                             ("run_multi_operator.py", ["--acn", "1000", "--mfev", "2000"])]:
            p = run([PY, str(D / script), *args], timeout=7200)
            (RAW / f"{script}.log").write_text(p.stdout[-20000:] + p.stderr[-5000:])
            check("12-15", f"{script} executed", "returncode", p.returncode, "0", p.returncode == 0)
    att = list(csv.DictReader(open(OUT / "attack_results.csv")))
    unexpected = sum(r["actual"] == "ACCEPTED" for r in att)
    errors = sum(r["actual"] == "ERROR" for r in att)
    gens = {g: sum(r["generation"] == g for r in att) for g in ("systematic", "randomized")}
    comp = sum(r["compound"] == "True" for r in att)
    check("14", "attack suite: unexpected acceptances", "unexpected_accepts", unexpected, "0", unexpected == 0,
          f"cases={len(att)} systematic={gens['systematic']} randomized={gens['randomized']} compound={comp} errors={errors}")
    check("14", "attack suite: harness errors", "errors", errors, "0", errors == 0)
    fams = {r["family"] for r in att}
    check("14", "attack suite covers families A, B, C", "families", ",".join(sorted(fams)), "A,B,C", fams == {"A", "B", "C"})
    pam = list(csv.DictReader(open(OUT / "pam_ablation.csv")))
    variants = {r["variant"] for r in pam}
    gains = [r for r in pam if r["variant"] == "GAINS"]
    b3 = all(float(g["b3_incomplete_accept_rate"]) == 0.0 for g in gains if g["b3_incomplete_accept_rate"] != "")
    b2 = all(float(g["b2_incomplete_accept_rate"]) == 1.0 for g in gains if g["b2_incomplete_accept_rate"] != "")
    check("12", "PA-MSP/PAM ablation completed (B0-full,B0-row,B1,B2,B3)", "variants",
          ",".join(sorted(variants - {"GAINS"})), "B0-full,B0-row,B1,B2,B3", {"B0-full", "B0-row", "B1", "B2", "B3"} <= variants)
    check("4", "ablation: B3 rejects every authentic-but-incomplete opening; B2 accepts them", "b3_accept=0 & b2_accept=1",
          f"{b3}&{b2}", "True&True", b3 and b2)
    pq = list(csv.DictReader(open(OUT / "pq_ablation.csv")))
    check("13", "classical/hybrid-PQ ablation completed", "profile x config rows", len(pq), ">=15",
          len(pq) >= 15 and {r["profile"] for r in pq} >= {"C0", "C1", "C2", "C3"})
    bl = list(csv.DictReader(open(OUT / "baselines.csv")))
    check("11", "all controlled baselines execute", "baselines", ",".join(r["baseline"] for r in bl),
          "FullEscrow,HashAnchor,CDR,DVAS-EV", {r["baseline"] for r in bl} == {"FullEscrow", "HashAnchor", "CDR", "DVAS-EV"})
    mo = list(csv.DictReader(open(OUT / "multi_operator_summary.csv")))
    pairs = [r for r in mo if r["home_operator"] != "REGISTRY"]
    allset = all(r["sessions"] == r["settled"] for r in pairs)
    check("14b", "multi-operator: all home x CPO pairs settle", "pairs", len(pairs), "9 (3x3)", len(pairs) == 9 and allset)


# ---------------------------------------------------------------------------
# reproducibility
# ---------------------------------------------------------------------------

def reproducibility() -> None:
    """Deterministic outputs must be identical across two independent runs (fresh keys)."""
    from dbas_et.dvas.attacks import ATTACKS, run_attack
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import acn_sessions, honest_amount

    specs = acn_sessions(max_rows=60)

    def once():
        env = DvasEnvironment(profile=PROFILES["C3"])
        res = [env.run(sp) for sp in specs]
        # receipt/RBC byte counts contain ECDSA DER signatures (70-72 bytes, random nonce) and are
        # therefore excluded. Signature-free sizes and all decisions must be identical.
        sig = [(r.ok, str(r.captured), r.sizes.get("opening_A_bytes"), r.sizes.get("opening_S_bytes"),
                r.sizes.get("private_envelope_bytes")) for r in res]
        atk = [(n, run_attack(env, n, specs[i % 10], specs, case_no=i).reason)
               for i, n in enumerate([a for a in ATTACKS if a != "randomized_compound"])]
        return sig, atk

    a, b = once(), once()
    check("15", "reproducible deterministic outputs (outcomes, amounts, opening/envelope sizes, attack reasons)",
          "identical_runs", a == b, "True", a == b,
          "two runs with independent fresh keys; ECDSA-DER-length-dependent byte counts excluded (vary by <=2 B/signature)")
    vec = run([PY, "-m", "pytest", "tests/dvas/test_canonical.py::test_golden_vectors_are_stable", "-q", "-p", "no:cacheprovider"])
    check("15", "pinned canonical test vectors reproduced", "returncode", vec.returncode, "0", vec.returncode == 0)
    if (OUT / "timing_raw.csv").exists():
        check("15", "raw timing samples stored", "rows", sum(1 for _ in open(OUT / "timing_raw.csv")) - 1, ">0", True)


def write_report(md: dict, started: float) -> None:
    write_csv(OUT / "validation_results.csv", RESULTS)
    passed = sum(r["pass"] for r in RESULTS)
    lines = [
        "# DVAS-EV validation", "",
        f"Generated {md['timestamp_utc']} by `scripts/dvas/run_validation.py` "
        f"({time.time() - started:.0f} s). **{passed}/{len(RESULTS)} checks passed.**", "",
        "Timings in this artifact are local protocol-processing latency in one Python process "
        "(no network, no blockchain inclusion); they are not EV-charging end-to-end latency.", "",
        "## Environment", "",
        *[f"- {k}: {md.get(k)}" for k in ("cpu_model", "logical_cores", "physical_cores", "ram_gib", "os", "python",
                                          "gcc", "cryptography", "openssl", "liboqs_version", "liboqs_python_version",
                                          "oqs_enabled_sig", "oqs_enabled_kem", "forge", "solc", "git_commit",
                                          "source_digest_dbas_et_dvas")], "",
        "## Checks", "", "| # | check | metric | value | expected | pass | note |", "|---|---|---|---|---|---|---|",
        *[f"| {r['criterion']} | {r['check']} | {r['metric']} | {r['value']} | {r['expected']} | "
          f"{'PASS' if r['pass'] else '**FAIL**'} | {r['note']} |" for r in RESULTS], "",
        "## Reproduce", "", "```bash", "bash scripts/env/setup_env.sh            # once: liboqs + venv",
        "scripts/env/dvas_run.sh python scripts/dvas/run_validation.py", "```", "",
    ]
    (OUT / "validation.md").write_text("\n".join(lines))
    (RAW / "validation_environment.json").write_text(json.dumps(md, indent=2, sort_keys=True))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=5000)
    ap.add_argument("--quorum-rows", type=int, default=300)
    ap.add_argument("--attack-rows", type=int, default=20)
    ap.add_argument("--attack-random", type=int, default=600)
    ap.add_argument("--ablation-capsules", type=int, default=100)
    ap.add_argument("--pq-sessions", type=int, default=200)
    ap.add_argument("--skip-experiments", action="store_true")
    a = ap.parse_args()
    started = time.time()
    RAW.mkdir(parents=True, exist_ok=True)
    md = environment_metadata()
    rows: list[dict] = []
    regression(rows, a.rows)
    write_csv(RAW / "regression_rows.csv", rows)
    quorum_scale(a.quorum_rows)
    experiments(a.skip_experiments, a)
    reproducibility()
    pytest_suite()
    forge_suite()
    write_report(md, started)
    return 0 if all(r["pass"] for r in RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
