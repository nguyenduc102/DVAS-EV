"""
Independent settlement verifiers and quorum attestations.

Each verifier independently executes, in this order:

 1. resolve the registered meter key (role, epoch, revocation)
 2. verify the meter signature over the canonical public receipt
 3. verify tid/sid/rho_t against ledger state and the station-meter binding
 4. decapsulate its key slot and decrypt the private payload
 5. recompute h_priv = H(canonical DR_private)
 6. compare h_priv with the meter-signed public receipt
 7. public/private consistency checks
 8. verify the predicate-complete PAM opening and evaluate Match
    (the "settlement" predicate) without defaults
 9. build the canonical decision and sign its digest.

An attestation is produced only if every step succeeds.  ``behavior``
injects faults for the quorum experiments: "offline", "inflate", "over_hold",
"approve_all", "wrong_root".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, TYPE_CHECKING

from .canonical import EncodingError
from .delivery import PublicReceipt, decode_private_payload, h_priv_of
from .evidence import EvidenceContext, EvidenceEnvelope, open_evidence
from .pam import CompletenessPolicy, PAMOpening, verify_opening
from .predicates import evaluate, predicate_for
from .profiles import KEMKeypair, Signer, verify_signature
from .rbc import RBC_VERSION, SETTLEMENT_POLICY_ID, RBCBody, VerificationAttestation, attestation_message
from .registry import KeyRegistry, Role
from .schema import PROTOCOL_VERSION_VALUE

if TYPE_CHECKING:  # pragma: no cover
    from .ledger import DvasLedger


@dataclass(frozen=True)
class SettlementRequest:
    tid: str
    receipt: PublicReceipt
    envelope: EvidenceEnvelope
    opening: PAMOpening


@dataclass
class VerifierOutcome:
    verifier_id: str
    ok: bool
    stage: str
    reason: str
    body: RBCBody | None = None
    attestation: VerificationAttestation | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)


_CONSISTENT = ("receipt_tid", "sid", "rho_t", "receipt_meter_id", "delivered_kwh", "ts_start", "ts_end", "nonce_m")


@dataclass
class VerifierNode:
    verifier_id: str
    operator: str
    signer: Signer
    kem: KEMKeypair
    key_epoch: int = 1
    kem_epoch: int = 1
    behavior: str = "honest"
    completeness_policy: CompletenessPolicy = CompletenessPolicy.SUPERSET

    def evaluate(self, req: SettlementRequest, registry: KeyRegistry, ledger: "DvasLedger") -> VerifierOutcome:
        t: dict[str, float] = {}
        t0 = time.perf_counter()
        out = self._evaluate(req, registry, ledger, t)
        out.timings_ms = {**t, "total": (time.perf_counter() - t0) * 1000.0}
        return out

    def _reject(self, stage: str, reason: str) -> VerifierOutcome:
        return VerifierOutcome(self.verifier_id, False, stage, reason)

    def _evaluate(self, req: SettlementRequest, registry: KeyRegistry, ledger: "DvasLedger",
                  t: dict[str, float]) -> VerifierOutcome:
        if self.behavior == "offline":
            return self._reject("unavailable", "VERIFIER_OFFLINE")
        approve_all = self.behavior == "approve_all"
        r = req.receipt
        rec = ledger.records.get(req.tid)
        if rec is None:
            return self._reject("ledger", "UNKNOWN_TID")

        # 1. registered meter key
        s = time.perf_counter()
        lk = registry.lookup(r["receipt_meter_id"], Role.METER, epoch=r["meter_key_epoch"])
        if not lk.ok and not approve_all:
            return self._reject("1_meter_key", f"METER_KEY_{lk.reason}")
        # 2. meter signature
        if not approve_all and not verify_signature(lk.record.key_type, lk.record.public_key, r.message(), r.signature):  # type: ignore[union-attr]
            return self._reject("2_meter_signature", "BAD_METER_SIGNATURE")
        t["receipt_verify"] = (time.perf_counter() - s) * 1000.0

        # 3. tid/sid/rho and station-meter binding
        if not approve_all:
            if r["receipt_tid"] != req.tid or rec.tid != req.tid:
                return self._reject("3_binding", "TID_MISMATCH")
            if r["sid"] != rec.sid:
                return self._reject("3_binding", "SID_MISMATCH")
            if r["rho_t"] != rec.rho_t:
                return self._reject("3_binding", "RHO_MISMATCH")
            if registry.meter_station.get(r["receipt_meter_id"]) != r["receipt_station_id"]:
                return self._reject("3_binding", "METER_NOT_BOUND_TO_STATION")
            if rec.receipt_digest != r.dr_digest:
                return self._reject("3_binding", "RECEIPT_NOT_SUBMITTED")

        # 4. open private evidence
        s = time.perf_counter()
        expected_ctx = EvidenceContext(req.tid, r["sid"], r["rho_t"], r["receipt_meter_id"], r["h_priv"])
        opened = open_evidence(req.envelope, verifier_id=self.verifier_id, kem_epoch=self.kem_epoch,
                               kem_keypair=self.kem, expected=expected_ctx)
        t["private_open"] = (time.perf_counter() - s) * 1000.0
        if not opened.ok and not approve_all:
            return self._reject("4_private_open", f"PRIVATE_{opened.reason}")
        priv: dict[str, Any] = {}
        if opened.ok:
            # 5./6. recompute and compare h_priv
            if h_priv_of(opened.plaintext) != r["h_priv"] and not approve_all:  # type: ignore[arg-type]
                return self._reject("6_h_priv", "PRIVATE_DIGEST_MISMATCH")
            try:
                priv = decode_private_payload(opened.plaintext)  # type: ignore[arg-type]
            except EncodingError as exc:
                if not approve_all:
                    return self._reject("5_decode", f"PRIVATE_DECODE:{exc}")

        # 7. public/private consistency
        if not approve_all:
            for k in _CONSISTENT:
                if priv.get(k) != r[k]:
                    return self._reject("7_consistency", f"PUBLIC_PRIVATE_MISMATCH:{k}")
            conn = priv["connection_duration_s"]
            if priv["active_charging_duration_s"] > conn or priv["parking_duration_s"] > conn \
                    or conn > max(0, r["ts_end"] - r["ts_start"]):
                return self._reject("7_consistency", "DURATION_INCONSISTENT")

        # 8. PAM opening (completeness + authenticity) and Match
        s = time.perf_counter()
        pv = verify_opening(rec.rho_t, req.opening, reason="settlement", policy=self.completeness_policy)
        t["pam_verify"] = (time.perf_counter() - s) * 1000.0
        if not pv.ok and not approve_all:
            return self._reject("8_pam", f"PAM_{pv.code}")
        evidence = {
            "receipt_tid": r["receipt_tid"], "receipt_station_id": r["receipt_station_id"],
            "receipt_meter_id": r["receipt_meter_id"], "applied_tariff_id": r["applied_tariff_id"],
            "applied_tariff_version": r["applied_tariff_version"], "delivered_kwh": r["delivered_kwh"],
            "ts_start": r["ts_start"], "ts_end": r["ts_end"], "sid": r["sid"], "dr_digest": r.dr_digest,
            "connection_duration_s": priv.get("connection_duration_s", 0),
            "active_charging_duration_s": priv.get("active_charging_duration_s", 0),
            "parking_duration_s": priv.get("parking_duration_s", 0),
            "settlement_currency": rec.currency, "effective_limit": rec.effective_limit,
            "held_amount": rec.held, "payee": registry.station_beneficiary.get(r["receipt_station_id"], ""),
            "ledger_paytok": rec.paytok,
        }
        relations = dict(registry.relations())
        relations["fresh_receipt"] = lambda d: d not in ledger.used_receipts
        relations["fresh_session"] = lambda tid, sid: ledger.session_is_open(tid, sid)
        s = time.perf_counter()
        res = evaluate(predicate_for("settlement"), pv.values, evidence, relations)
        t["match"] = (time.perf_counter() - s) * 1000.0
        if not res.ok and not approve_all:
            return self._reject("8_match", f"MATCH_FAILED:{res.reason}")

        # 9. decision + attestation
        amount: Decimal = res.outputs.get("amount", Decimal(0)) if res.outputs else Decimal(0)
        if self.behavior == "inflate":
            amount = rec.held
        if self.behavior == "over_hold":  # fault injection: try to capture above the hold
            amount = rec.held + Decimal("0.000001")
        held = rec.held
        refund = held - amount if held >= amount else Decimal(0)
        rho = rec.rho_t
        if self.behavior == "wrong_root":
            rho = "f" * 64
        s = time.perf_counter()
        body = RBCBody.build(
            rbc_version=RBC_VERSION,
            settle_protocol_version=PROTOCOL_VERSION_VALUE,
            settle_tid=req.tid,
            settle_sid=r["sid"],
            settle_rho_t=rho,
            settle_meter_id=r["receipt_meter_id"],
            dr_digest=r.dr_digest,
            settle_h_priv=r["h_priv"],
            auth_digest=ledger.auth_digest(req.tid),
            captured_amount=amount,
            refund_amount=refund,
            decision="ACCEPT",
            policy_id=SETTLEMENT_POLICY_ID,
            verifier_set_epoch=registry.verifier_set_epoch,
        )
        sig = self.signer.sign(attestation_message(self.verifier_id, self.key_epoch, body.digest))
        att = VerificationAttestation.for_body(body, self.verifier_id, self.key_epoch, sig, self.signer.scheme)
        t["attest"] = (time.perf_counter() - s) * 1000.0
        return VerifierOutcome(self.verifier_id, True, "9_attested", "OK", body, att)
