"""Master paper-artifact runner.

    scripts/env/dvas_run.sh python scripts/dvas/run_paper_artifact.py [--quick]

Runs every experiment in a FIXED order with DVAS_OUT=outputs/paper_artifact (the
previously validated outputs/ are never overwritten), stops at the first
unexpected failure, then derives tables, figures, the paper
numbers, the scale comparison and the reproducibility manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
D = ROOT / "scripts" / "dvas"

FULL = {
    "regression": ["--rows", "5000"],
    "formal": ["--acn", "70", "--mfev", "30", "--scale", "2"],
    "minimality": ["--acn", "10", "--mfev", "5"],
    "attacks": ["--rows", "40", "--mfev-rows", "20", "--random", "1500", "--seed", "20261005"],
    "pam": ["--capsules", "500", "--repeats", "10", "--warmup", "100"],
    "fault": ["--rows", "100"],
    "qcost": ["--sessions", "500", "--warmup", "50"],
    "pq": ["--sessions", "500", "--warmup", "50"],
    "baselines": ["--sessions", "500", "--warmup", "50", "--attack-rows", "50"],
    "multiop": ["--acn", "2000", "--mfev", "3000"],
    "boundary": ["--replay-sessions", "30"],
}
QUICK = {
    "regression": ["--rows", "200"], "formal": ["--acn", "6", "--mfev", "3", "--scale", "1"],
    "minimality": ["--acn", "3", "--mfev", "2"], "attacks": ["--rows", "3", "--mfev-rows", "2", "--random", "60"],
    "pam": ["--capsules", "10", "--repeats", "3", "--warmup", "10"], "fault": ["--rows", "5"],
    "qcost": ["--sessions", "30", "--warmup", "5"], "pq": ["--sessions", "30", "--warmup", "5"],
    "baselines": ["--sessions", "30", "--warmup", "5", "--attack-rows", "5"], "multiop": ["--acn", "60", "--mfev", "90"],
    "boundary": ["--replay-sessions", "3"],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small smoke-scale run")
    ap.add_argument("--out", default=str(ROOT / "outputs" / "paper_artifact"))
    a = ap.parse_args()
    P = QUICK if a.quick else FULL
    out = Path(a.out)
    if out.resolve() == (ROOT / "outputs").resolve():
        raise SystemExit("refusing to write into the validated outputs/ directory")
    if out.exists():
        shutil.rmtree(out)
    (out / "raw").mkdir(parents=True)
    env = dict(os.environ, DVAS_OUT=str(out), PYTHONPATH=str(ROOT))
    py = sys.executable
    steps = [
        ("00 test suite (pytest)", [py, "-m", "pytest", "tests", "-p", "no:cacheprovider"]),
        ("01 regression workloads", [py, str(D / "run_regression_workloads.py"), *P["regression"]]),
        ("02 formal property checks", [py, str(D / "run_formal_properties.py"), *P["formal"]]),
        ("03 minimality analysis", [py, str(D / "run_minimality_checked.py"), *P["minimality"]]),
        ("04 attack suite", [py, str(D / "run_attack_suite.py"), *P["attacks"]]),
        ("05 PAM B0/B1/B2/B3 ablation", [py, str(D / "run_pam_ablation.py"), *P["pam"]]),
        ("06 quorum fault matrix", [py, str(D / "run_quorum_fault_matrix.py"), *P["fault"]]),
        ("07 quorum cost benchmark", [py, str(D / "run_quorum_cost.py"), *P["qcost"]]),
        ("08 PQ profile benchmark", [py, str(D / "run_pq_ablation.py"), *P["pq"]]),
        ("09 controlled baselines", [py, str(D / "run_baselines.py"), *P["baselines"]]),
        ("10 multi-operator workload", [py, str(D / "run_multi_operator.py"), *P["multiop"]]),
        ("11 standards-mapping demo", [py, str(D / "run_standards_demo.py")]),
        ("12 Foundry tests + gas", [py, str(D / "run_foundry_gas.py")]),
        ("13 legacy regression", [py, str(D / "run_legacy_regression.py")]),
        ("14 security boundary", [py, str(D / "make_security_boundary.py"), *P["boundary"]]),
        ("15 summary tables", [py, str(D / "make_paper_artifact_tables.py")]),
        ("16 figures", [py, str(D / "make_paper_artifact_figures.py")]),
        ("17 paper numbers", [py, str(D / "check_paper_numbers.py")]),
        ("18 comparison with validated run", [py, str(D / "compare_with_validated.py")]),
    ]
    (out / "experiment_parameters.json").write_text(json.dumps(
        {"mode": "quick" if a.quick else "full", "parameters": P,
         "order": [s for s, _ in steps] + ["19 reproducibility manifest"]}, indent=2))
    log = []
    t_all = time.time()
    for name, cmd in steps:
        t0 = time.time()
        print(f"== {name}", flush=True)
        p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        el = time.time() - t0
        slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        (out / "raw" / f"step_{slug}.log").write_text(p.stdout[-60000:] + "\n--- stderr ---\n" + p.stderr[-20000:])
        log.append({"step": name, "returncode": p.returncode, "seconds": round(el, 1)})
        if name.startswith("00"):
            m = re.search(r"(\d+) passed", p.stdout)
            f = re.search(r"(\d+) failed", p.stdout)
            (out / "test_summary.csv").write_text(
                "suite,passed,failed\npytest,%s,%s\n" % (m.group(1) if m else 0, f.group(1) if f else 0))
        if name.startswith("12"):
            m = re.search(r"passed/failed=(\d+)/(\d+)", p.stdout)
            if m:
                with open(out / "test_summary.csv", "a") as fh:
                    fh.write(f"foundry,{m.group(1)},{m.group(2)}\n")
        print(f"   rc={p.returncode} {el:.1f}s", flush=True)
        if p.returncode != 0:
            print(p.stdout[-3000:], p.stderr[-3000:])
            (out / "run_log.json").write_text(json.dumps(log, indent=2))
            print(f"STOPPED: unexpected failure in step '{name}'")
            return 1
    p = subprocess.run([py, str(D / "make_artifact_manifest.py")], cwd=ROOT, env=env, capture_output=True, text=True)
    log.append({"step": "19 reproducibility manifest", "returncode": p.returncode, "seconds": 0})
    log.append({"step": "TOTAL", "returncode": 0, "seconds": round(time.time() - t_all, 1)})
    (out / "run_log.json").write_text(json.dumps(log, indent=2))
    print(f"DONE in {time.time() - t_all:.0f}s -> {out}")
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
