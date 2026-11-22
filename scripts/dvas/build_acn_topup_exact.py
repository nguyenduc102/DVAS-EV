#!/usr/bin/env python3
"""Rebuild the ACN-30k top-up input from the original-cap workload using the exact
(Decimal, ROUND_HALF_EVEN) protocol amount instead of the float-rounded dataset flag.

The legacy top-up file (3,394 rows) used ``is_undercap_original``, computed with float
rounding.  One row (workload_index 14598: 0.959561 kWh x 0.55 = 0.52775855) rounds to
0.527758 in float but to 0.527759 exactly, so it exceeds its 0.527758 hold and is refused
under the original cap, yet was missing from the top-up set.  This script selects every
original-cap row whose exact amount exceeds its hold (3,395 rows).  Rows already in the
legacy file keep their recommended delta. New rows get the same rule
delta = 1.10 * amount - hold (fixed 6 decimals).
"""
from __future__ import annotations

import csv
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from dbas_et.dvas.workload import acn_sessions, honest_amount, to_fixed6  # noqa: E402

D = ROOT / "data" / "acn" / "processed"
SRC = D / "profile_original_cap_cached_acn_0p1_n30000_unique.csv"
OLD = D / "profile_undercap_topup_cached_acn_0p1_n30000_unique.csv"
DST = D / "profile_undercap_topup_cached_acn_0p1_n30000_unique_exact.csv"


def main() -> int:
    specs = acn_sessions(SRC)
    with SRC.open(newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        fields = rd.fieldnames
        rows = list(rd)
    with OLD.open(newline="", encoding="utf-8") as f:
        old = {r["workload_index"]: r for r in csv.DictReader(f)}
    out, added = [], []
    for sp, r in zip(specs, rows):
        amt = honest_amount(sp)
        if amt <= sp.preauth_limit:
            continue
        wi = r["workload_index"]
        if wi in old:
            out.append(old[wi])
            continue
        r = dict(r)
        r["is_undercap_original"] = "True"
        r["topup_delta_recommended"] = str(to_fixed6(max(Decimal(0), amt * Decimal("1.10") - sp.preauth_limit)))
        r["amount_minus_original_preauth"] = str(amt - sp.preauth_limit)
        r["profile"] = "undercap_topup"
        out.append(r)
        added.append((wi, str(amt), str(sp.preauth_limit), r["topup_delta_recommended"]))
    missing_old = set(old) - {r["workload_index"] for r in out}
    with DST.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out)
    print(f"exact over-hold rows: {len(out)} (legacy file {len(old)}); added {added}; legacy rows dropped: {sorted(missing_old)}")
    print(f"wrote {DST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
