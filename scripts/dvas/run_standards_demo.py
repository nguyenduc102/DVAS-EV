"""Standards-mapping demo (semantic mapping only, not a compliance test).

OCPI-like Token/Location/Tariff + authorization request JSON
  -> DVAS capsule -> pre-service commitment (rho_t)
  -> OCPP-like TransactionEvents with signed meter values -> meter-signed DR_t + private evidence
  -> 2-of-3 verifier quorum -> RBC -> settlement.

Outputs:
  <OUT>/standards_mapping_trace.csv   source field -> DVAS field, lifecycle, committed/external status, settlement use
  <OUT>/standards_demo_result.json    end-to-end outcome
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.predicates import required_fields  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.schema import LAYOUT_V1, PRIVATE_RECEIPT, PUBLIC_RECEIPT, REGISTRY  # noqa: E402
from dbas_et.dvas.standards_adapter import session_spec_from_standards  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "standards"

# Source paths as implemented in dbas_et/dvas/standards_adapter.py
SOURCES = {
    "user_id": "OCPI Token.contract_id",
    "home_operator": "OCPI Token.country_code*party_id",
    "station_id": "OCPI Location.country_code*party_id*id*EVSE.uid",
    "foreign_operator": "OCPI Location.country_code*party_id",
    "evse_id": "OCPI Location.evses[].evse_id",
    "meter_id": "OCPI Location.evses[].meter_id",
    "tariff_id": "OCPI Tariff.id",
    "tariff_version": "OCPI Tariff.last_updated",
    "tariff_mode": "OCPI Tariff.elements[].price_components[].type (ENERGY[+TIME[+PARKING_TIME]])",
    "unit_price": "OCPI Tariff price_component ENERGY.price",
    "currency": "OCPI Tariff.currency",
    "requested_kwh": "DVAS authorization request.requested_kwh",
    "cap_kwh": "DVAS authorization request.max_kwh",
    "preauth_limit": "DVAS authorization request.preauthorized_amount",
    "tw_start": "DVAS authorization request.valid_from",
    "tw_end": "DVAS authorization request.valid_until",
    "nonce_u": "OCPI authorization_reference (derived)",
    "nonce_s": "OCPP transactionInfo.transactionId (derived)",
    "delivered_kwh": "OCPP TransactionEvent Ended - Started: Energy.Active.Import.Register",
    "ts_start": "OCPP TransactionEvent Started.timestamp",
    "ts_end": "OCPP TransactionEvent Ended.timestamp",
    "connection_duration_s": "OCPP Ended.timestamp - Started.timestamp",
    "active_charging_duration_s": "OCPP Updated(chargingState=SuspendedEV).timestamp - Started.timestamp",
    "parking_duration_s": "OCPP Ended.timestamp - Updated(SuspendedEV).timestamp",
    "meter_values_digest": "SHA-256 of OCPP sampledValue.signedMeterValue.signedMeterData (not verified)",
    "session_ref": "OCPP transactionInfo.transactionId",
    "applied_tariff_id": "CPO-applied tariff reference (OCPI Tariff.id in this demo)",
    "applied_tariff_version": "CPO-applied tariff version (OCPI Tariff.last_updated in this demo)",
}
EVIDENCE_OPERANDS = {"delivered_kwh", "ts_start", "ts_end", "connection_duration_s", "active_charging_duration_s",
                     "parking_duration_s", "applied_tariff_id", "applied_tariff_version"}


def _load(n):
    return json.loads((FX / n).read_text())


def main() -> int:
    write_metadata("standards_demo")
    objs = dict(token=_load("ocpi_token.json"), location=_load("ocpi_location.json"), tariff=_load("ocpi_tariff.json"),
                auth_request=_load("dvas_authorization_request.json"),
                transaction_events=_load("ocpp_transaction_events.json"))
    spec = session_spec_from_standards(tid="ocpi-demo-tx-0001", evse_uid="EVSE-1", **objs)
    env = DvasEnvironment(profile=PROFILES["C3"], n=3, t=2)
    s = env.session(spec)
    rho = s.commit().rho_t
    auth = s.authorize()
    sess = s.open_session()
    rc = s.deliver()
    sub = s.submit_receipt()
    outs = s.verify()
    rbc = s.aggregate()
    st = s.settle() if rbc else None
    settle_req = set(required_fields(LAYOUT_V1, "settlement"))
    auth_req = set(required_fields(LAYOUT_V1, "authorization"))
    amount_ops = {"tariff_mode", "unit_price"}
    trace = []
    for name, src in SOURCES.items():
        spec_field = REGISTRY.spec(name)
        where = []
        if name in LAYOUT_V1.field_names:
            where.append("committed in rho_t")
        if name in PUBLIC_RECEIPT.field_names:
            where.append("meter-signed public receipt DR_t")
        if name in PRIVATE_RECEIPT.field_names:
            where.append("private evidence DR_private (bound by h_priv)")
        if not where:
            where.append("external (not committed)")
        uses = []
        if name in settle_req:
            uses.append("settlement predicate operand (opened to verifiers)")
        if name in amount_ops:
            uses.append("tariff amount")
        if name in EVIDENCE_OPERANDS:
            uses.append("Match evidence operand")
        if name == "meter_values_digest":
            uses.append("bound into h_priv -> meter signature; RBC settle_h_priv")
        if name in auth_req and name not in settle_req:
            uses.append("authorization predicate only")
        if not uses:
            uses.append("committed; not opened at settlement" if name in LAYOUT_V1.field_names
                        else "carried in private evidence (h_priv-bound); not a predicate operand")
        value = s.values.get(name, s.private_values.get(name, rc.values.get(name) if name in rc.values else ""))
        trace.append({"source_field": src, "dvas_field": name, "field_id": f"0x{spec_field.field_id:04x}",
                      "lifecycle": spec_field.lifecycle.name, "status": "; ".join(where),
                      "settlement_use": "; ".join(uses), "value": str(value)})
    write_csv(OUT / "standards_mapping_trace.csv", trace)
    result = {
        "scope": "semantic mapping demonstration with representative fixtures; not OCPI/OCPP compliance",
        "tid": spec.tid, "rho_t": rho, "authorize": auth.code, "session_open": sess.code, "receipt_submit": sub.code,
        "verifiers": {o.verifier_id: o.reason for o in outs},
        "rbc_attestations": [a.verifier_id for a in rbc.attestations] if rbc else [],
        "settle": st.code if st else "NO_QUORUM", "captured": str(st.value["captured"]) if st and st.ok else None,
        "expected_amount_from_ocpi_tariff": str(spec.expected_amount),
        "settled_ok": bool(st and st.ok and st.value["captured"] == spec.expected_amount),
    }
    (OUT / "standards_demo_result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["settled_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
