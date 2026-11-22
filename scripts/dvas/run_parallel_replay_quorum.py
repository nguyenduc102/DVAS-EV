"""T4: multi-worker replay throughput of the quorum DVAS-EV path (replaces the
legacy 8-worker replay figures of the single-verifier pipeline).

Each worker owns an independent DvasEnvironment (registry, ledger, 2-of-3 C3
verifier cluster) and replays a disjoint shard of the workload.  Environment
construction and key generation happen before the timed region.  Throughput =
settled sessions / wall time of the timed region (workers start together on a
barrier).  Service time = per-session in-process total (SVs in parallel).
Local protocol-state replay only: no network, no blockchain inclusion.

Output: $DVAS_OUT/quorum_tables/t4_parallel_replay.csv
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv, write_metadata  # noqa: E402

ACN30 = ROOT / "data" / "acn" / "processed" / "profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv"
MFEV50 = ROOT / "data" / "processed" / "mfev" / "runner_fixed" / "mfev_50000_valid_fixed.csv"


def _worker(args):
    kind, path, idx, workers, n, t, barrier, q = args
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import acn_sessions, mfev_sessions
    specs = (acn_sessions(Path(path)) if kind == "acn" else mfev_sessions(Path(path)))[idx::workers]
    env = DvasEnvironment(profile=PROFILES["C3"], n=n, t=t)
    for sp in specs:
        env.register_spec(sp)
    barrier.wait()
    t0 = time.perf_counter()
    totals, ok, errors = [], 0, 0
    for sp in specs:
        try:
            r = env.run(sp)
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        ok += r.ok
        if r.ok:
            totals.append(r.timings_ms["total"])
    q.put((idx, time.perf_counter() - t0, len(specs), ok, errors, totals))


def run(kind: str, path: Path, workers: int, n: int, t: int) -> dict:
    ctx = mp.get_context("fork")
    barrier, q = ctx.Barrier(workers), ctx.Queue()
    procs = [ctx.Process(target=_worker, args=((kind, str(path), i, workers, n, t, barrier, q),)) for i in range(workers)]
    for p in procs:
        p.start()
    res = [q.get() for _ in procs]
    for p in procs:
        p.join()
    wall = max(r[1] for r in res)
    totals = sorted(x for r in res for x in r[5])
    settled, sessions, errors = sum(r[3] for r in res), sum(r[2] for r in res), sum(r[4] for r in res)
    return {"workload": "ACN-30k" if kind == "acn" else "MFEV-50k", "quorum": f"{t}-of-{n}", "workers": workers,
            "sessions": sessions, "settled": settled, "errors": errors, "wall_s": round(wall, 2),
            "throughput_sessions_per_s": round(settled / wall, 2),
            "service_median_ms": round(statistics.median(totals), 3),
            "service_p95_ms": round(totals[int(round(0.95 * (len(totals) - 1)))], 3)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    write_metadata("parallel_replay_quorum")
    rows = []
    for kind, path in (("acn", ACN30), ("mfev", MFEV50)):
        for n, t in ((3, 2), (5, 3)):
            rows.append(run(kind, path, a.workers, n, t))
            print("T4", rows[-1], flush=True)
    out = OUT / "quorum_tables"
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "t4_parallel_replay.csv", rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
