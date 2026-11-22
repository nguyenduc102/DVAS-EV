"""Classical / hybrid post-quantum ablation and raw timings.

Profiles C0..C4 (see dbas_et.dvas.profiles) x verifier configurations
1-of-1, 2-of-3, 3-of-5.  Every configuration runs --warmup untimed sessions
followed by --sessions measured sessions on ACN rows.

Phase definitions (milliseconds, local protocol-processing latency):
  authorization        user signs request + A-opening + AuthSC verify (PAM + predicate + reserve)
  session_open         station signs + ledger verify
  receipt_generation   meter canonical encoding + receipt signature
  private_protection   single-ciphertext AEAD + per-verifier KEM key wrap
  receipt_verification ledger meter-key lookup + signature + binding checks
  private_opening      max over verifiers of KEM decap + unwrap + AEAD open
  verifier_processing  max over verifiers (critical path, verifiers run in parallel)
  verifier_processing_sum  sum over verifiers (total CPU)
  rbc_quorum           RBC aggregation + SettleSC quorum verification
  settlement           SettleSC.settle only
  total                critical-path sum of all phases

Outputs: outputs/pq_ablation.csv, outputs/timing_raw.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, SCOPE, stats, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.profiles import PROFILES, KEMKeypair, Signer  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, honest_amount  # noqa: E402

CONFIGS = [(1, 1), (3, 2), (5, 3)]


def phases(t: dict[str, float]) -> dict[str, float]:
    return {
        "authorization": t.get("auth_sign", 0) + t.get("open_A", 0) + t.get("authorize_verify", 0),
        "session_open": t.get("session_open", 0),
        "receipt_generation": t.get("receipt_sign", 0),
        "private_protection": t.get("private_protect", 0),
        "receipt_verification": t.get("receipt_submit", 0),
        "private_opening": t.get("private_open_max", 0),
        "verifier_processing": t.get("verifiers_max", 0),
        "verifier_processing_sum": t.get("verifiers_sum", 0),
        "rbc_quorum": t.get("rbc_aggregate", 0) + t.get("settle", 0),
        "settlement": t.get("settle", 0),
        "total": t.get("total", 0),
    }


def artifact_sizes(profile) -> dict[str, int]:
    out = {}
    for role, scheme in [("auth", profile.auth_sig), ("station", profile.station_sig), ("meter", profile.meter_sig),
                         ("verifier", profile.verifier_sig)]:
        sg = Signer(scheme)
        out[f"{role}_pk_bytes"] = len(sg.public_key)
        out[f"{role}_sig_bytes"] = len(sg.sign(b"x" * 32))
    k = KEMKeypair(profile.kem)
    from dbas_et.dvas.profiles import kem_encapsulate

    ct, _ = kem_encapsulate(profile.kem, k.public_key)
    out["kem_pk_bytes"], out["kem_ct_bytes"] = len(k.public_key), len(ct)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=30)
    ap.add_argument("--profiles", default="C0,C1,C2,C3,C4")
    args = ap.parse_args()
    md = write_metadata("pq_ablation")
    specs = acn_sessions(max_rows=args.sessions + args.warmup)
    raw, summary = [], []
    for pname in args.profiles.split(","):
        prof = PROFILES[pname]
        sizes = artifact_sizes(prof)
        for n, t in CONFIGS:
            env = DvasEnvironment(profile=prof, n=n, t=t)
            for sp in specs:  # untimed key provisioning
                env.register_spec(sp)
            res_sizes = []
            for i, sp in enumerate(specs):
                r = env.run(unique(sp, f"pq:{pname}:{n}"))
                assert r.ok and r.captured == honest_amount(sp), (pname, n, r.stage, r.code)
                if i < args.warmup:
                    continue
                ph = phases(r.timings_ms)
                res_sizes.append(r.sizes)
                for k, v in ph.items():
                    raw.append({"experiment": "pq_ablation", "profile": pname, "pq_status": prof.pq_status,
                                "config": f"{t}-of-{n}", "session": i, "phase": k, "ms": round(v, 6)})
            rows = [x for x in raw if x["profile"] == pname and x["config"] == f"{t}-of-{n}"]
            agg = {"profile": pname, "label": prof.label, "pq_status": prof.pq_status, "config": f"{t}-of-{n}",
                   "sessions": args.sessions, "scope": SCOPE}
            for k in phases({}):
                st = stats([x["ms"] for x in rows if x["phase"] == k])
                agg[f"{k}_ms_median"] = round(st["median"], 4)
                agg[f"{k}_ms_p95"] = round(st["p95"], 4)
                agg[f"{k}_ms_mean"] = round(st["mean"], 4)
                agg[f"{k}_ms_std"] = round(st["std"], 4)
            for k in ("opening_A_bytes", "opening_S_bytes", "receipt_bytes", "private_envelope_bytes", "rbc_bytes"):
                agg[f"{k}_median"] = stats([s[k] for s in res_sizes])["median"]
            agg.update(sizes)
            agg.update({"auth_sig": prof.auth_sig, "meter_sig": prof.meter_sig, "verifier_sig": prof.verifier_sig,
                        "kem": prof.kem})
            summary.append(agg)
            print(pname, f"{t}-of-{n}", "total", agg["total_ms_median"], "auth", agg["authorization_ms_median"],
                  "verif", agg["verifier_processing_ms_median"], "env", agg["private_envelope_bytes_median"])
    write_csv(OUT / "timing_raw.csv", raw)
    write_csv(OUT / "pq_ablation.csv", summary)
    print("cpu", md.get("cpu_model"), "liboqs", md.get("liboqs_version"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
