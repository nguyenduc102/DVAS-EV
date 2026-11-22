"""Security/trust-boundary table -> <OUT>/security_boundary.csv.

Derived from <OUT>/quorum_fault_matrix.csv (raw per-cell counts) plus an explicit
replay-under-collusion experiment: after a session settles, the m malicious
verifiers (or, if m < t, the honest set) sign a FRESH, different RBC body for the
same transaction; SettleSC must refuse it.
"""

from __future__ import annotations

import argparse
import csv
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.rbc import QuorumRBC, RBCBody, VerificationAttestation, attestation_message  # noqa: E402
from dbas_et.dvas.workload import acn_sessions  # noqa: E402


def replay_attempts(n: int, t: int, m: int, o: int, sessions: int) -> tuple[int, set[str], int]:
    """Settle each session (last o verifiers offline), then have the available signers -- the m colluders
    if m >= t, else the available honest verifiers -- sign a FRESH body for the same transaction."""
    env = DvasEnvironment(profile=PROFILES["C3"], n=n, t=t, behaviors={f"SV{i}": "offline" for i in range(n - o + 1, n + 1)})
    available = [f"SV{i}" for i in range(1, n - o + 1)]
    signers = available[: max(m, t)]
    accepted, codes, settled_first = 0, set(), 0
    for i, sp in enumerate(acn_sessions(max_rows=sessions)):
        sp = unique(sp, f"sb:{n}:{t}:{m}:{o}:{i}")
        r = env.run(sp)
        if not r.ok:
            codes.add("NO_PRIOR_SETTLEMENT")
            continue
        settled_first += 1
        rec = env.ledger.records[sp.tid]
        last = [x for x in r.verifier_outcomes if x.body is not None][0].body
        s_body = RBCBody.build(**{**last.values, "captured_amount": last.captured - Decimal("0.000001"),
                                  "refund_amount": last["refund_amount"] + Decimal("0.000001"),
                                  "auth_digest": env.ledger.auth_digest(sp.tid)})
        atts = []
        for vid in signers:
            node = env.verifiers[vid]
            sig = node.signer.sign(attestation_message(vid, node.key_epoch, s_body.digest))
            atts.append(VerificationAttestation.for_body(s_body, vid, node.key_epoch, sig, node.signer.scheme))
        res = env.ledger.settle(QuorumRBC(s_body, tuple(atts)))
        accepted += res.ok
        codes.add(res.code)
        assert rec.state.value == "SETTLED"
    return accepted, codes, settled_first


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay-sessions", type=int, default=20)
    a = ap.parse_args()
    write_metadata("security_boundary")
    fm = list(csv.DictReader(open(OUT / "quorum_fault_matrix.csv")))
    cells = sorted({(r["config"], int(r["n"]), int(r["t"]), int(r["malicious_colluding"]), int(r["offline"])) for r in fm},
                   key=lambda x: (x[1], x[3], x[4]))
    rows = []
    for cfg, n, t, m, o in cells:
        g = {r["goal"]: r for r in fm if r["config"] == cfg and int(r["malicious_colluding"]) == m and int(r["offline"]) == o}
        sem_incorrect = int(g["inflate_valid"]["incorrect_settled"]) + int(g["approve_invalid"]["incorrect_settled"])
        settle_possible = int(g["inflate_valid"]["correct"]) + int(g["inflate_valid"]["incorrect_settled"])
        over_hold = int(g["over_hold"]["incorrect_settled"]) + (int(g["over_hold"]["correct"]) if m >= t else 0)
        rep_acc, rep_codes, rep_settled = replay_attempts(n, t, m, o, a.replay_sessions)
        available = n - o
        if available - m < t and m < t:
            reason = "available honest verifiers < t: no quorum, no settlement (never incorrect)"
        elif m < t:
            reason = "f < t: honest quorum decides; malicious attestations cannot reach t"
        else:
            reason = "f >= t colluding: semantic decision can be bypassed; SettleSC public invariants still enforced"
        rows.append({
            "config": cfg, "n": n, "t": t, "malicious_colluding": m, "offline": o, "available": available,
            "sessions_per_goal": g["inflate_valid"]["sessions"],
            "semantic_incorrect_settlement_observed": sem_incorrect,
            "semantic_incorrect_settlement_possible": "yes" if sem_incorrect else "no",
            "settlement_possible": "yes" if settle_possible else "no",
            "capture_above_hold_accepted": over_hold, "capture_above_hold_possible": "yes" if over_hold else "no",
            "replay_sessions": a.replay_sessions, "replay_attempts_after_settlement": rep_settled,
            "replay_accepted": rep_acc,
            "replay_possible": ("yes" if rep_acc else "no") if rep_settled else "no (nothing settled to replay: available < t)",
            "replay_refusal_codes": "|".join(sorted(rep_codes)),
            "over_hold_refusal_codes": g["over_hold"]["refusal_codes"],
            "within_f_lt_t_assumption": m < t, "expected_reason": reason,
        })
        print(rows[-1]["config"], f"m={m} o={o}", "incorrect", sem_incorrect, "settle", rows[-1]["settlement_possible"],
              "over_hold", over_hold, "replay", rep_acc, sorted(rep_codes))
    write_csv(OUT / "security_boundary.csv", rows)
    bad = [r for r in rows if r["capture_above_hold_accepted"] or r["replay_accepted"]
           or (r["within_f_lt_t_assumption"] and r["semantic_incorrect_settlement_observed"])]
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
