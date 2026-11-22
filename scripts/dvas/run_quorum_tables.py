"""Tables 4 and 5(a) and the Fig. 4 component times, computed with the quorum code.

  T1  tab:settlement_baselines   controlled baselines vs DVAS-EV (2-of-3, 3-of-5, top-up)
                                 on the ACN-30k valid workload, one in-process harness
                                 (dbas_et.dvas.baselines), C3 profile for DVAS-EV.
  T2  tab:attack_matrix          10,000 attack cases from the current attack suite
                                 (27 attack types: systematic over 300 rows + 1,900 randomized),
                                 grouped by attack family.
  T3  tab:rbc_timing             per-stage in-process time of the quorum RBC path on
                                 ACN-10k, ACN-30k and MFEV-50k (2-of-3), plus 3-of-5 totals.

All timings are local in-process protocol time (not matched loopback, not end-to-end).
Outputs under $DVAS_OUT/quorum_tables/.
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.baselines import CDR, DVASEV, PHASES, FullEscrow, HashAnchor  # noqa: E402
from dbas_et.dvas.ledger import auth_request_message, session_open_message, topup_message  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.schema import PROTOCOL_VERSION_VALUE  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, honest_amount, mfev_sessions  # noqa: E402

ACN = ROOT / "data" / "acn" / "processed"
ACN10 = ACN / "profile_valid_preauthorization_sites-caltech-jpl-office001_min0p1_n10000.csv"
ACN30 = ACN / "profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv"
# Exact-amount top-up set (3,395 rows): every original-cap row whose Decimal amount exceeds
# its hold.  The legacy float-flagged file (3,394 rows) missed workload_index 14598.
ACN30_TOPUP = ACN / "profile_undercap_topup_cached_acn_0p1_n30000_unique_exact.csv"
MFEV50 = ROOT / "data" / "processed" / "mfev" / "runner_fixed" / "mfev_50000_valid_fixed.csv"


def pct(xs, q):
    v = sorted(xs)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def med_p95(xs):
    return round(statistics.median(xs), 3), round(pct(xs, 0.95), 3)


# ---------------------------------------------------------------- T1
EXCLUDED = ("verifiers_sum", "private_open_max", "total", "receipt_sign", "private_protect")


def session_total(timings: dict) -> float:
    """Same total as Session.run_all: stage timers, verifiers in parallel (max over SVs)."""
    return sum(v for k, v in timings.items() if k not in EXCLUDED)


class DVASQuorum(DVASEV):
    def __init__(self, n: int, t: int, label: str) -> None:
        super().__init__(PROFILES["C3"])
        self.env = DvasEnvironment(profile=PROFILES["C3"], n=n, t=t)
        self.name = label
        self.last_session = None

    def prepare(self, spec, ctx):
        super().prepare(spec, ctx)
        self.last_session = ctx["s"]

    # Byte accounting fix (untimed): the library harness adds a fixed 200 B for the
    # signed authorization request.  Count the real request message and signature,
    # and the signed session-open record, so C3 signature sizes are not undercounted.
    def authorize(self, spec, ctx):
        ok = super().authorize(spec, ctx)
        s = ctx["s"]
        msg = auth_request_message(s.auth_request())
        self._pub(len(msg) + len(s.user.signer.sign(msg)) - 200)
        return ok

    def submit_receipt(self, spec, ctx):
        ok = super().submit_receipt(spec, ctx)
        s = ctx["s"]
        vals = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": spec.tid, "sid": s.sid, "rho_t": s.commitment.rho_t,
                "station_id": spec.station_id, "meter_id": spec.meter_id, "nonce_s": spec.nonce_s}
        msg = session_open_message(vals)
        self._pub(len(msg) + len(s.station.signer.sign(msg)))
        return ok


class DVASTopUp(DVASQuorum):
    def submit_receipt(self, spec, ctx):
        ok = super().submit_receipt(spec, ctx)
        if not ok:
            return False
        s = ctx["s"]
        rec = s.env.ledger.records[spec.tid]
        vals = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": spec.tid, "rho_t": rec.rho_t, "sid": s.sid or "-",
                "user_account": rec.user_account, "old_limit": rec.effective_limit, "delta_limit": spec.topup_delta,
                "new_limit": rec.effective_limit + spec.topup_delta,
                "event_nonce": f"topup-{spec.tid}-{rec.topup_count}"}
        msg = topup_message(vals)
        self._pub(len(msg) + len(s.user.signer.sign(msg)))  # signed top-up record (untimed size)
        return s.topup().ok


def t1(n_sessions: int, warmup: int, out: Path) -> list[dict]:
    valid = acn_sessions(ACN30, max_rows=n_sessions + warmup)
    topups = acn_sessions(ACN30_TOPUP)
    c3 = PROFILES["C3"]  # same cryptographic profile for every method
    methods = [("Full escrow", FullEscrow(c3), valid), ("Hash anchor", HashAnchor(c3), valid),
               ("CDR baseline", CDR(c3), valid)]
    if not BASELINES_ONLY:
        methods += [("DVAS-EV 2-of-3", DVASQuorum(3, 2, "DVAS-EV 2-of-3"), valid),
                    ("DVAS-EV 3-of-5", DVASQuorum(5, 3, "DVAS-EV 3-of-5"), valid),
                    ("DVAS-EV top-up", DVASTopUp(3, 2, "DVAS-EV top-up"), topups)]
    rows = []
    for label, b, specs in methods:
        tot, pub, priv, fails = [], [], [], 0
        t0 = time.perf_counter()
        for i, sp in enumerate(specs):
            run = b.run(unique(sp, f"t1:{label}:{i}"))
            if not (run.ok and run.captured == honest_amount(sp)):
                fails += 1
                continue
            if i < warmup and specs is valid:
                continue
            if isinstance(b, DVASQuorum):  # stage timers, SVs in parallel (as T3 and Fig. 2b)
                tot.append(session_total(b.last_session.timings))
            else:                          # single operator: harness phase wall time
                tot.append(sum(run.phases[ph].ms for ph in PHASES))
            pub.append(run.public_bytes)
            priv.append(run.private_bytes)
        m, p = med_p95(tot)
        rows.append({"method": label, "sessions": len(tot), "failed_or_mismatch": fails,
                     "public_bytes_median": statistics.median(pub), "private_bytes_median": statistics.median(priv),
                     "total_ms_median": m, "total_ms_p95": p, "wall_s": round(time.perf_counter() - t0, 1)})
        print("T1", rows[-1], flush=True)
    write_csv(out / ("t1_baselines_c3.csv" if BASELINES_ONLY else "t1_settlement_baselines.csv"), rows)
    return rows


BASELINES_ONLY = "--t1-baselines-only" in sys.argv


# ---------------------------------------------------------------- T2
GROUPS = {
    "Projection integrity": ["invalid_proof", "missing_required_field", "wrong_rho", "missing_operand_valid_multiproof_overcap"],
    "Meter/role binding": ["wrong_meter", "wrong_station", "wrong_meter_valid_receipt"],
    "Delivery matching": ["wrong_pricing", "wrong_time", "over_cap", "invalid_amount", "tariff_mismatch_authentic_opening"],
    "Private evidence": ["wrong_private_digest"],
    "Replay and session": ["replay", "wrong_sid", "wrong_tid", "stale_receipt_current_tx", "cross_session_receipt_reuse",
                           "duplicate_settlement"],
    "Quorum RBC": ["malicious_verifier_incorrect_decision", "mixed_attestations_different_roots",
                   "revoked_verifier_valid_signature", "cross_root_rbc_reuse", "settle_before_quorum"],
    "Lifecycle order": ["settle_before_receipt", "topup_after_settled"],
    "Randomized compound": ["randomized_compound"],
}


def t2(out: Path, rows: int, mfev_rows: int, random_n: int) -> list[dict]:
    res_csv = out / "attack_results.csv"
    env = dict(os.environ, DVAS_OUT=str(out / "attack_suite"), PYTHONPATH=str(ROOT))
    cmd = [sys.executable, "-W", "ignore", str(ROOT / "scripts" / "dvas" / "run_attack_suite.py"), "--rows", str(rows),
           "--mfev-rows", str(mfev_rows), "--random", str(random_n), "--profile", "C3", "--out", str(res_csv)]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True)
    print(p.stdout[-800:], p.stderr[-800:], flush=True)
    group_of = {a: g for g, al in GROUPS.items() for a in al}
    agg = defaultdict(Counter)
    for r in csv.DictReader(open(res_csv)):
        g = group_of.get(r["attack"], "UNMAPPED:" + r["attack"])
        src = r["case_id"].split(":")[2] if False else ""
        agg[g]["cases"] += 1
        agg[g]["rejected"] += r["actual"] == "REJECTED"
        agg[g]["accepted"] += r["actual"] == "ACCEPTED"
        agg[g]["errors"] += r["actual"] == "ERROR"
        agg[g]["systematic"] += r["generation"] == "systematic"
        agg[g]["randomized"] += r["generation"] == "randomized"
        agg[g]["compound"] += str(r.get("compound")) == "True"
    out_rows = [{"group": g, "attack_types": len(GROUPS.get(g, [])), **dict(c)} for g, c in agg.items()]
    write_csv(out / "t2_attack_matrix.csv", out_rows)
    for r in out_rows:
        print("T2", r, flush=True)
    return out_rows


# ---------------------------------------------------------------- T3
STAGES = [("Commit root", ["commit"]), ("Authorization sign/open", ["auth_sign", "open_A"]),
          ("Authorize reserve", ["authorize_verify"]), ("Session open", ["session_open"]),
          ("Receipt build/sign", ["receipt_generate", "-private_protect"]), ("Protect private", ["private_protect"]),
          ("Receipt submit", ["receipt_submit"]), ("SV quorum/RBC", ["open_S", "verifiers_max", "rbc_aggregate"]),
          ("Release by RBC", ["settle"])]


def stage_val(t: dict, keys: list[str]) -> float:
    return sum(-t.get(k[1:], 0.0) if k.startswith("-") else t.get(k, 0.0) for k in keys)


def t3(out: Path, limit: int | None) -> list[dict]:
    workloads = [("ACN-10k", lambda: acn_sessions(ACN10, max_rows=limit)), ("ACN-30k", lambda: acn_sessions(ACN30, max_rows=limit)),
                 ("MFEV-50k", lambda: mfev_sessions(MFEV50, max_rows=limit))]
    rows = []
    for wl, loader in workloads:
        specs = loader()
        for n, t in ((3, 2), (5, 3)):
            env = DvasEnvironment(profile=PROFILES["C3"], n=n, t=t)
            per = defaultdict(list)
            ok = 0
            for sp in specs:
                r = env.run(sp)
                if not r.ok:
                    continue
                ok += 1
                for name, keys in STAGES:
                    per[name].append(stage_val(r.timings_ms, keys))
                per["Total"].append(r.timings_ms["total"])
            for name in [s for s, _ in STAGES] + ["Total"]:
                m, p = med_p95(per[name])
                rows.append({"workload": wl, "quorum": f"{t}-of-{n}", "component": name, "median_ms": m, "p95_ms": p,
                             "settled": ok, "sessions": len(specs)})
            print("T3", wl, f"{t}-of-{n}", ok, "/", len(specs), [r for r in rows if r["component"] == "Total"][-1], flush=True)
    write_csv(out / "t3_rbc_timing.csv", rows)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", default="t1,t2,t3")
    ap.add_argument("--t1-sessions", type=int, default=30000)
    ap.add_argument("--t1-warmup", type=int, default=50)
    ap.add_argument("--t2-rows", type=int, default=200)
    ap.add_argument("--t2-mfev-rows", type=int, default=100)
    ap.add_argument("--t2-random", type=int, default=1900)
    ap.add_argument("--t3-limit", type=int, default=None)
    ap.add_argument("--t1-baselines-only", action="store_true", help="rerun only the three baselines (C3)")
    a = ap.parse_args()
    out = OUT / "quorum_tables"
    out.mkdir(parents=True, exist_ok=True)
    write_metadata("quorum_tables")
    parts = set(a.part.split(","))
    if "t1" in parts:
        t1(a.t1_sessions, a.t1_warmup, out)
    if "t2" in parts:
        t2(out, a.t2_rows, a.t2_mfev_rows, a.t2_random)
    if "t3" in parts:
        t3(out, a.t3_limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
