"""Adversarial suite -> outputs/attack_results.csv.

Systematic: every attack in families A/B/C on each of the first --rows ACN
rows (plus --mfev-rows MFEV rows).  Randomized: --random cases whose attack
type and mutation parameters are drawn from random.Random(--seed); the seed
never touches key generation.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, RAW, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import RANDOMIZABLE, SYSTEMATIC, run_attack  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, mfev_sessions  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20)
    ap.add_argument("--mfev-rows", type=int, default=10)
    ap.add_argument("--random", type=int, default=600)
    ap.add_argument("--seed", type=int, default=20261005)
    ap.add_argument("--profile", default="C3")
    ap.add_argument("--out", default=str(OUT / "attack_results.csv"))
    args = ap.parse_args()
    write_metadata("attack_suite")

    pool = acn_sessions(max_rows=max(args.rows, 40)) + mfev_sessions(max_rows=max(args.mfev_rows, 20))
    rows = pool[: args.rows] + [p for p in pool if p.source == "MFEV"][: args.mfev_rows]
    env = DvasEnvironment(profile=PROFILES[args.profile])
    results = []
    for name in SYSTEMATIC:
        for i, spec in enumerate(rows):
            results.append(run_attack(env, name, spec, pool, generation="systematic", case_no=i))
    rng = random.Random(args.seed)
    for k in range(args.random):
        name = rng.choice(RANDOMIZABLE)
        spec = rng.choice(pool)
        results.append(run_attack(env, name, spec, pool, generation="randomized", rng=rng, seed=args.seed, case_no=k))

    out = [asdict(r) | {"unexpected_accept": r.unexpected_accept, "profile": args.profile} for r in results]
    write_csv(Path(args.out), out)
    summ = defaultdict(Counter)
    for r in results:
        summ[(r.family, r.attack, r.generation)][r.actual] += 1
    srows = [{"family": f, "attack": a, "generation": g, "cases": sum(c.values()), "rejected": c["REJECTED"],
              "accepted": c["ACCEPTED"], "errors": c["ERROR"]} for (f, a, g), c in sorted(summ.items())]
    write_csv(RAW / "attack_summary.csv", srows)
    tot = Counter(r.actual for r in results)
    print(f"cases={len(results)} rejected={tot['REJECTED']} unexpected_accepts={tot['ACCEPTED']} errors={tot['ERROR']}")
    for s in srows:
        if s["accepted"] or s["errors"]:
            print("ATTENTION", s)
    bad = [r for r in results if r.actual != "REJECTED"][:10]
    for r in bad:
        print(r)
    return 0 if tot["ACCEPTED"] == 0 and tot["ERROR"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
