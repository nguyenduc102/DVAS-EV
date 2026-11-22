"""Export the E9 (run_pam_ablation.py) capsules as per-field leaves for the
OpenZeppelin StandardMerkleTree multiproof baseline (OZ Compact).

Same capsules (ACN/MFEV split), same 26-field LAYOUT_V1, same canonical field
encoding and the same PA-MSP selected set per view as E9's B2/B3.
Also exports the canonical field encoding (base64url, ``value_b64u``) so the
SD-JWT and BBS baselines disclose the same bytes as E9.  Each row is
one (capsule, view, field) with the field's canonical-encoding SHA-256 digest,
which the OZ tree commits as a bytes32 leaf value, and the canonical encoded
length so the Node bench can report opened-value bytes on the same basis as E9.

Output: $DVAS_OUT/oz_e9/e9_leaves.csv
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv  # noqa: E402

from dbas_et.dvas.canonical import encode_field  # noqa: E402
from dbas_et.dvas.predicates import required_fields  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.schema import LAYOUT_V1, REGISTRY  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, mfev_sessions  # noqa: E402

VIEWS = ["authorization", "settlement", "dispute:tariff_mismatch", "dispute:time_window",
         "dispute:over_cap", "dispute:amount_exceeds_preauth", "dispute:replay"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capsules", type=int, default=100)
    a = ap.parse_args()
    env = DvasEnvironment(profile=PROFILES["C0"])
    specs = acn_sessions(max_rows=a.capsules // 2) + mfev_sessions(max_rows=a.capsules - a.capsules // 2)
    rows = []
    for ci, sp in enumerate(specs):
        env.register_spec(sp)
        c = env.session(sp).commit()
        for view in VIEWS:
            req = set(required_fields(LAYOUT_V1, view))
            for idx, name in enumerate(LAYOUT_V1.field_names):
                enc = encode_field(REGISTRY.spec(name), c.values[name])
                rows.append({"sample_id": f"{sp.source}-{ci}", "projection": view, "field_index": idx,
                             "field_path": name, "value_hash_hex": "0x" + hashlib.sha256(enc).hexdigest(),
                             "encoded_len": len(enc), "selected": int(name in req),
                             "value_b64u": base64.urlsafe_b64encode(enc).decode().rstrip("=")})
    write_csv(OUT / "oz_e9" / "e9_leaves.csv", rows)
    print(f"[OK] {len(specs)} capsules x {len(VIEWS)} views -> {OUT / 'oz_e9' / 'e9_leaves.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
