from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Mapping, Sequence


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def H_hex(label: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    if isinstance(payload, bytes):
        h.update(payload)
    else:
        h.update(canonical_json(payload))
    return h.hexdigest()


def digest_record(label: str, record: Mapping[str, Any]) -> str:
    return H_hex(label, dict(record))


def meter_values_root(samples: Sequence[Mapping[str, Any]]) -> str:
    """
    Lightweight deterministic root for reconstructed meter samples.

    This is a hash-chain style root, not a Merkle proof backend.
    It is suitable for protocol-state audit evidence.
    """
    acc = "00" * 32
    for i, sample in enumerate(samples):
        leaf = H_hex(
            "DBAS-ET:meter-sample-leaf:v1",
            {
                "index": i,
                "sample": dict(sample),
            },
        )
        acc = H_hex(
            "DBAS-ET:meter-sample-chain:v1",
            {
                "prev": acc,
                "leaf": leaf,
            },
        )
    return acc


@dataclass(frozen=True)
class ReceiptBindingCertificate:
    trade_id: str
    rho_t: str
    ar_digest: str
    dr_digest: str
    meter_values_root: str
    tariff_digest: str
    binding_digest: str
    predicate_result: bool
    failure_reason: str
    captured_amount: float
    preauth_limit: float
    refund_amount: float
    verifier_version: str = "receipt-binding-v1"


def verify_receipt_against_authorization(
    *,
    ar_t: Mapping[str, Any],
    dr_t: Mapping[str, Any],
    meter_samples: Sequence[Mapping[str, Any]],
    rho_t: str,
    tariff_record: Mapping[str, Any] | None = None,
    amount_tolerance: float = 1e-6,
) -> ReceiptBindingCertificate:
    """
    Semantic receipt-binding verifier.

    This function does not replace signature verification or projection opening.
    It should be called after:
      1. AR_t/admission certificate is valid.
      2. DR_t signature is valid.
      3. S_t projection opening against rho_t is valid.
    """
    tariff_record = tariff_record or {}

    required_equal_fields = [
        "trade_id",
        "user_id",
        "station_id",
        "meter_id",
        "tariff_id",
        "tariff_version",
    ]

    predicate_result = True
    reasons: list[str] = []

    for field in required_equal_fields:
        ar_val = ar_t.get(field)
        dr_val = dr_t.get(field)
        if ar_val is not None and dr_val is not None and ar_val != dr_val:
            predicate_result = False
            reasons.append(f"mismatch:{field}")

    trade_id = str(dr_t.get("trade_id") or ar_t.get("trade_id") or "")

    preauth_limit = float(
        ar_t.get("preauth_limit", ar_t.get("allow_cap", ar_t.get("cap", 0.0)))
    )
    captured_amount = float(
        dr_t.get("captured_amount", dr_t.get("amount", dr_t.get("settlement_amount", 0.0)))
    )
    refund_amount = max(preauth_limit - captured_amount, 0.0)

    if captured_amount - preauth_limit > amount_tolerance:
        predicate_result = False
        reasons.append("over_preauth_limit")

    delivered_kwh = float(dr_t.get("delivered_kwh", dr_t.get("energy_kwh", 0.0)))
    if delivered_kwh < -amount_tolerance:
        predicate_result = False
        reasons.append("negative_energy")

    # Optional time-window checks if fields exist.
    ar_start = ar_t.get("not_before", ar_t.get("start_time"))
    ar_end = ar_t.get("not_after", ar_t.get("end_time", ar_t.get("expiry_time")))
    dr_start = dr_t.get("start_time")
    dr_end = dr_t.get("end_time")

    if ar_start is not None and dr_start is not None and str(dr_start) < str(ar_start):
        predicate_result = False
        reasons.append("start_before_authorization_window")

    if ar_end is not None and dr_end is not None and str(dr_end) > str(ar_end):
        predicate_result = False
        reasons.append("end_after_authorization_window")

    m_root = meter_values_root(meter_samples)

    # If DR already carries a meter root, enforce equality.
    dr_m_root = dr_t.get("meter_values_root")
    if dr_m_root is not None and str(dr_m_root) != str(m_root):
        predicate_result = False
        reasons.append("meter_values_root_mismatch")

    ar_digest = digest_record("DBAS-ET:AR:v1", ar_t)
    dr_digest = digest_record("DBAS-ET:DR:v1", dr_t)
    tariff_digest = digest_record("DBAS-ET:tariff:v1", tariff_record)

    binding_digest = H_hex(
        "DBAS-ET:receipt-binding:v1",
        {
            "trade_id": trade_id,
            "rho_t": rho_t,
            "ar_digest": ar_digest,
            "dr_digest": dr_digest,
            "meter_values_root": m_root,
            "tariff_digest": tariff_digest,
        },
    )

    return ReceiptBindingCertificate(
        trade_id=trade_id,
        rho_t=str(rho_t),
        ar_digest=ar_digest,
        dr_digest=dr_digest,
        meter_values_root=m_root,
        tariff_digest=tariff_digest,
        binding_digest=binding_digest,
        predicate_result=predicate_result,
        failure_reason=";".join(reasons),
        captured_amount=captured_amount,
        preauth_limit=preauth_limit,
        refund_amount=refund_amount,
    )


def certificate_to_dict(cert: ReceiptBindingCertificate) -> dict[str, Any]:
    return asdict(cert)
