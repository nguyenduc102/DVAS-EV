"""
Off-chain settlement verifier and Receipt Binding Certificate (RBC) support.

The paper protocol separates private payload decryption from on-chain payment
release.  This module implements that verifier layer for the Python simulator:

    protected envelopes -> open/verify private payloads -> Match(S_t, DR_t)
    -> signed RBC_public

SettleSC can then release funds from reserved balance by checking RBC_public,
state, replay status, and amount bounds.  This mirrors a realistic blockchain
architecture where smart contracts do not hold KEM secret keys.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from .crypto import H, H_hex, PQKEMKeypair, ecdsa_sign, ecdsa_verify
from .entities import Meter
from .payments import DeliveryReceipt, eval_tariff_amount, receipt_hash, verify_delivery_receipt
from .projections import ProjectionProof, ProjectionView, V2SlimSettlementBackend
from .protected_flow import ProtectedProtocolPayload, open_protocol_payload
from .receipt_binding import digest_record, meter_values_root
from .result import ProtocolResult, ProtocolStatus, RejectReason


@dataclass(frozen=True)
class ReceiptBindingCertificatePublic:
    """Public certificate consumed by SettleSC."""

    trade_id: str
    rho_t: str
    sid_t: str
    ar_digest: str
    dr_digest: str
    meter_values_root: str
    tariff_digest: str
    private_evidence_digest: str
    binding_digest: str
    predicate_result: bool
    failure_reason: str
    captured_amount: float
    effective_preauth_limit: float
    verifier_id: str
    issued_at: float
    verifier_signature_hex: str
    receipt_hash: str
    cert_version: str = "rbc-public-v1"

    def unsigned_record(self) -> dict[str, Any]:
        return {
            "cert_version": self.cert_version,
            "trade_id": self.trade_id,
            "rho_t": self.rho_t,
            "sid_t": self.sid_t,
            "ar_digest": self.ar_digest,
            "dr_digest": self.dr_digest,
            "meter_values_root": self.meter_values_root,
            "tariff_digest": self.tariff_digest,
            "private_evidence_digest": self.private_evidence_digest,
            "binding_digest": self.binding_digest,
            "predicate_result": self.predicate_result,
            "failure_reason": self.failure_reason,
            "captured_amount": self.captured_amount,
            "effective_preauth_limit": self.effective_preauth_limit,
            "verifier_id": self.verifier_id,
            "issued_at": self.issued_at,
            "receipt_hash": self.receipt_hash,
        }

    def to_record(self) -> dict[str, Any]:
        return asdict(self)



def recompute_rbc_public_binding_digest(rbc: ReceiptBindingCertificatePublic) -> str:
    """Recompute the domain-separated RBC public binding digest."""
    return H_hex(
        "DBAS-ET:RBC-BINDING:v1",
        {
            "trade_id": rbc.trade_id,
            "rho_t": rbc.rho_t,
            "sid_t": rbc.sid_t,
            "ar_digest": rbc.ar_digest,
            "dr_digest": rbc.dr_digest,
            "meter_values_root": rbc.meter_values_root,
            "tariff_digest": rbc.tariff_digest,
            "private_evidence_digest": rbc.private_evidence_digest,
            "receipt_hash": rbc.receipt_hash,
        },
    )


@dataclass(frozen=True)
class ReceiptBindingCertificatePrivate:
    """Private transcript intended for encrypted audit storage."""

    trade_id: str
    rho_t: str
    sid_t: str
    ar_digest: str
    dr_digest: str
    opened_private_payload_digests: dict[str, str]
    semantic_check_breakdown: dict[str, bool]
    failure_reason: str
    captured_amount: float
    refund_amount: float
    verifier_version: str = "settlement-verifier-v1"

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SettlementVerifierOutput:
    """Verifier output containing public RBC and private transcript."""

    rbc_public: ReceiptBindingCertificatePublic
    rbc_private: ReceiptBindingCertificatePrivate
    opened_payloads: dict[str, dict[str, Any]]
    open_failures: dict[str, str]

    def to_record(self) -> dict[str, Any]:
        return {
            "rbc_public": self.rbc_public.to_record(),
            "rbc_private": self.rbc_private.to_record(),
            "opened_payload_types": sorted(self.opened_payloads),
            "open_failures": dict(self.open_failures),
        }


@dataclass
class SettlementVerifier:
    """Authorized off-chain verifier that issues signed RBC_public."""

    verifier_id: str
    sign_sk: Any
    sign_pk: Any
    kem_keys: PQKEMKeypair | None = None
    verifier_version: str = "settlement-verifier-v1"

    def public_record(self) -> dict[str, Any]:
        return {
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "kem_pkid": self.kem_keys.pkid if self.kem_keys is not None else "",
        }

    def verify_and_issue_rbc(
        self,
        *,
        ar_t: Mapping[str, Any],
        receipt: DeliveryReceipt,
        meter: Meter,
        rho_t: str,
        S_view: ProjectionView,
        S_proof: ProjectionProof,
        backend: V2SlimSettlementBackend,
        meter_samples: Sequence[Mapping[str, Any]] | None = None,
        tariff_record: Mapping[str, Any] | None = None,
        protected_payloads: Sequence[ProtectedProtocolPayload | Mapping[str, Any]] | None = None,
    ) -> ProtocolResult:
        """Verify settlement semantics and issue RBC_public/RBC_private.

        Cheap-first order for attack traffic:
          1. verify S projection;
          2. verify meter signature;
          3. run public Match(S_t, DR_t) checks;
          4. open KEM-AEAD private payloads only for valid-looking requests;
          5. issue RBC_public/RBC_private.

        This preserves correctness for valid requests and avoids expensive
        private-payload opening for requests that are already invalid from
        public evidence.
        """
        meter_samples = meter_samples or []
        tariff_record = tariff_record or {}
        protected_payloads = protected_payloads or []

        opened_payloads: dict[str, dict[str, Any]] = {}
        open_failures: dict[str, str] = {}
        opened_digests: dict[str, str] = {}
        semantic_checks: dict[str, bool] = {}
        reasons: list[str] = []

        def add_reason(reason: str) -> None:
            if reason and reason not in reasons:
                reasons.append(reason)

        # 1) Cheap public proof check first.
        verification = backend.verify_projection_detailed(rho_t, S_view, S_proof)
        semantic_checks["projection_ok"] = verification.ok
        if not verification.ok:
            add_reason(f"bad_settlement_projection:{verification.reason}")

        # 2) Meter signature is also public and cheaper than decrypting private payloads.
        sig_ok = verify_delivery_receipt(meter, receipt)
        semantic_checks["meter_signature_ok"] = sig_ok
        if not sig_ok:
            add_reason("bad_meter_signature")

        # 3) Public Match fields. Do not open protected payloads yet.
        public_match_checks, public_match_reasons = evaluate_match_checks(
            ar_t=ar_t,
            receipt=receipt,
            rho_t=rho_t,
            S_view=S_view,
            meter_samples=meter_samples,
            tariff_record=tariff_record,
            opened_payloads={},
        )
        semantic_checks.update(public_match_checks)
        for reason in public_match_reasons:
            add_reason(reason)

        public_ok = bool(all(semantic_checks.values()))

        # 4) Only valid-looking requests reach KEM-AEAD private opening.
        if public_ok and protected_payloads:
            if self.kem_keys is None:
                return ProtocolResult.reject(
                    "missing_settlement_verifier_kem_key",
                    {"event": "verify_and_issue_rbc"},
                )

            for protected in protected_payloads:
                opened = open_protocol_payload(
                    protected_payload=protected,
                    recipient_kem_keypair=self.kem_keys,
                )
                if not opened.ok:
                    open_failures[opened.payload_type] = opened.reason
                else:
                    opened_payloads[opened.payload_type] = opened.payload or {}
                    opened_digests[opened.payload_type] = opened.plaintext_digest_opened

            if open_failures:
                semantic_checks["protected_payload_open_ok"] = False
                for k, v in open_failures.items():
                    add_reason(f"protected_open_failed:{k}:{v}")
            else:
                semantic_checks["protected_payload_open_ok"] = True

            # Re-run Match with opened private payloads. This adds private
            # consistency checks, while public checks remain identical.
            private_match_checks, private_match_reasons = evaluate_match_checks(
                ar_t=ar_t,
                receipt=receipt,
                rho_t=rho_t,
                S_view=S_view,
                meter_samples=meter_samples,
                tariff_record=tariff_record,
                opened_payloads=opened_payloads,
            )
            semantic_checks.update(private_match_checks)
            for reason in private_match_reasons:
                add_reason(reason)
        elif protected_payloads:
            # Do not spend KEM/AEAD work on obviously invalid requests.
            semantic_checks["protected_payload_open_skipped"] = True
            add_reason("protected_open_skipped_due_public_reject")
        else:
            semantic_checks["protected_payload_open_ok"] = True

        predicate_result = bool(all(v for k, v in semantic_checks.items() if not k.endswith("_skipped")))
        failure_reason = ";".join(reasons)

        delivered_kwh = float(receipt.delivered_kwh)
        unit_price = float(ar_t.get("unit_price", 0.0))
        tariff = eval_tariff_amount(
            delivered_kwh=delivered_kwh,
            unit_price=unit_price,
            mode=receipt.tariff_mode,
            connection_duration_s=receipt.connection_duration_s,
            active_charging_duration_s=receipt.active_charging_duration_s,
            parking_duration_s=receipt.parking_duration_s,
        )
        captured_amount = round(float(tariff.amount), 6)
        effective_limit = float(
            ar_t.get("effective_preauth_limit_t", ar_t.get("preauth_limit_t", ar_t.get("allowcap_t", 0.0)))
        )
        refund_amount = round(max(0.0, effective_limit - captured_amount), 6)

        m_root = meter_values_root(meter_samples)

        # Note:
        # RBC_public.ar_digest must be computed over the same public
        # AuthRecord representation that SettleSC recomputes from
        # AuthSC.records[trade_id].to_record().
        #
        # ar_t may contain extra verifier-only settlement fields such as
        # unit_price, tariff_id, tariff_version, tw_start, tw_end, and cap_kwh.
        # Those fields are needed for Match(S_t, DR_t), but they are not part
        # of the on-chain AuthRecord digest.
        auth_record_for_digest = canonical_auth_record_digest_input(ar_t)
        ar_digest = digest_record("DBAS-ET:AR:v1", auth_record_for_digest)

        dr_digest = digest_record("DBAS-ET:DR:v1", receipt.signed_record())

        # Receipt replay hash used by SettleSC.
        # This must use payments.receipt_hash(receipt), not dr_digest.
        # dr_digest binds the delivery-receipt record for RBC semantics;
        # rh binds the exact signed receipt submitted to SettleSC for replay prevention.
        rh = receipt_hash(receipt)

        # Tariff digest is part of RBC_public binding.
        # It must be computed before binding_digest / unsigned_public use it.
        # Prefer the explicit tariff_record when supplied; otherwise derive a
        # deterministic tariff evidence record from public authorization fields.
        tariff_digest_input = dict(tariff_record) if tariff_record else {
            "tariff_id": ar_t.get("tariff_id", ""),
            "tariff_version": ar_t.get("tariff_version", ""),
            "tariff_mode": receipt.tariff_mode,
            "unit_price": ar_t.get("unit_price", 0.0),
            "tw_start": ar_t.get("tw_start", ""),
            "tw_end": ar_t.get("tw_end", ""),
            "cap_kwh": ar_t.get("cap_kwh", ""),
        }
        tariff_digest = digest_record("DBAS-ET:TARIFF:v1", tariff_digest_input)

        _opened_payloads = locals().get("opened_payloads", {})
        _open_failures = locals().get("open_failures", {})
        _checks = locals().get("checks", {})

        opened_private_payload_digests = {
            str(k): H_hex("DBAS-ET:OPENED-PRIVATE-PAYLOAD:v1", v)
            for k, v in sorted(_opened_payloads.items(), key=lambda kv: str(kv[0]))
        }

        private_evidence_digest = H_hex(
            "DBAS-ET:RBC-PRIVATE-EVIDENCE:v1",
            {
                "trade_id": receipt.trade_id,
                "rho_t": str(rho_t),
                "sid_t": receipt.sid_t,
                "ar_digest": ar_digest,
                "dr_digest": dr_digest,
                "meter_values_root": m_root,
                "tariff_digest": tariff_digest,
                "receipt_hash": rh,
                "opened_private_payload_digests": opened_private_payload_digests,
                "open_failures": dict(sorted(_open_failures.items(), key=lambda kv: str(kv[0]))),
                "semantic_check_breakdown": dict(sorted(_checks.items(), key=lambda kv: str(kv[0]))),
                "failure_reason": failure_reason,
                "captured_amount": captured_amount,
                "refund_amount": refund_amount,
                "verifier_id": self.verifier_id,
            },
        )

        binding_digest = H_hex(
            "DBAS-ET:RBC-BINDING:v1",
            {
                "trade_id": receipt.trade_id,
                "rho_t": rho_t,
                "sid_t": receipt.sid_t,
                "ar_digest": ar_digest,
                "dr_digest": dr_digest,
                "meter_values_root": m_root,
                "tariff_digest": tariff_digest,
                "private_evidence_digest": private_evidence_digest,
                "receipt_hash": rh,
            },
        )

        unsigned_public = {
            "cert_version": "rbc-public-v1",
            "trade_id": receipt.trade_id,
            "rho_t": str(rho_t),
            "sid_t": receipt.sid_t,
            "ar_digest": ar_digest,
            "dr_digest": dr_digest,
            "meter_values_root": m_root,
            "tariff_digest": tariff_digest,
            "private_evidence_digest": private_evidence_digest,
            "binding_digest": binding_digest,
            "predicate_result": predicate_result,
            "failure_reason": failure_reason,
            "captured_amount": captured_amount,
            "effective_preauth_limit": effective_limit,
            "verifier_id": self.verifier_id,
            "issued_at": float(time.time()),
            "receipt_hash": rh,
        }
        sig = ecdsa_sign(self.sign_sk, H("DBAS-ET:RBC-PUBLIC-TO-SIGN:v1", unsigned_public))

        rbc_public = ReceiptBindingCertificatePublic(
            verifier_signature_hex=sig.hex(),
            **unsigned_public,
        )
        rbc_private = ReceiptBindingCertificatePrivate(
            trade_id=receipt.trade_id,
            rho_t=str(rho_t),
            sid_t=receipt.sid_t,
            ar_digest=ar_digest,
            dr_digest=dr_digest,
            opened_private_payload_digests=opened_digests,
            semantic_check_breakdown=semantic_checks,
            failure_reason=failure_reason,
            captured_amount=captured_amount,
            refund_amount=refund_amount,
            verifier_version=self.verifier_version,
        )

        return ProtocolResult.success(
            value=SettlementVerifierOutput(
                rbc_public=rbc_public,
                rbc_private=rbc_private,
                opened_payloads=opened_payloads,
                open_failures=open_failures,
            ),
            status=ProtocolStatus.SUCCESS if predicate_result else ProtocolStatus.REJECTED,
            metadata={
                "event": "verify_and_issue_rbc",
                "trade_id": receipt.trade_id,
                "predicate_result": predicate_result,
                "failure_reason": failure_reason,
                "captured_amount": captured_amount,
                "effective_preauth_limit": effective_limit,
                "receipt_hash": rh,
                "cheap_first": True,
            },
        )





def verify_rbc_public_signature(
    *,
    verifier: SettlementVerifier,
    rbc_public: ReceiptBindingCertificatePublic | Mapping[str, Any],
) -> bool:
    """Verify the signature over RBC_public."""
    rbc = rbc_public if isinstance(rbc_public, ReceiptBindingCertificatePublic) else ReceiptBindingCertificatePublic(**dict(rbc_public))

    if rbc.binding_digest != recompute_rbc_public_binding_digest(rbc):
        return False
    if rbc.verifier_id != verifier.verifier_id:
        return False
    return ecdsa_verify(
        verifier.sign_pk,
        H("DBAS-ET:RBC-PUBLIC-TO-SIGN:v1", rbc.unsigned_record()),
        bytes.fromhex(rbc.verifier_signature_hex),
    )

def canonical_auth_record_digest_input(ar_t: Mapping[str, Any]) -> dict[str, Any]:
    """Return the public AuthRecord fields used by SettleSC for ar_digest.

    SettlementVerifier receives an off-chain ``ar_t`` object that may include
    extra semantic fields needed for Match/TariffEval, such as unit_price,
    tariff_id, tariff_version, cap_kwh, tw_start, and tw_end.

    SettleSC cannot recompute a digest over those verifier-only fields because
    only AuthSC.records[trade_id].to_record() is contract-visible state.

    Therefore RBC_public.ar_digest MUST be computed over exactly the same
    AuthRecord representation that SettleSC later recomputes:

        digest_record("DBAS-ET:AR:v1", AuthSC.records[trade_id].to_record())

    If the caller provides an explicit "_auth_record" snapshot, use it.
    Otherwise, project ar_t down to the AuthRecord key set and ignore
    verifier-only semantic fields.
    """

    explicit = ar_t.get("_auth_record")
    if isinstance(explicit, Mapping):
        return dict(explicit)

    auth_record_keys = [
        "trade_id",
        "owner_address",
        "user_id",
        "station_id",
        "meter_id",
        "rho_t",
        "initial_preauth_limit_t",
        "effective_preauth_limit_t",
        "held_amount",
        "state",
        "captured_amount",
        "released_unused_hold",
        "topup_count",
        "topup_total",
    ]

    return {key: ar_t[key] for key in auth_record_keys if key in ar_t}

def evaluate_match_checks(
    *,
    ar_t: Mapping[str, Any],
    receipt: DeliveryReceipt,
    rho_t: str,
    S_view: ProjectionView,
    meter_samples: Sequence[Mapping[str, Any]],
    tariff_record: Mapping[str, Any],
    opened_payloads: Mapping[str, Mapping[str, Any]],
    amount_tolerance: float = 1e-5,
) -> tuple[dict[str, bool], list[str]]:
    """Evaluate Match(S_t, DR_t) style semantic checks."""
    checks: dict[str, bool] = {}
    reasons: list[str] = []

    def set_check(name: str, ok: bool, reason: str) -> None:
        checks[name] = bool(ok)
        if not ok:
            reasons.append(reason)

    set_check("trade_id_match", str(ar_t.get("trade_id", "")) == receipt.trade_id, "trade_id_mismatch")
    set_check("rho_match", str(ar_t.get("rho_t", rho_t)) == str(rho_t), "rho_mismatch")
    set_check("station_match", str(ar_t.get("station_id", "")) == receipt.station_id, "wrong_station")
    set_check("meter_match", str(ar_t.get("meter_id", "")) == receipt.meter_id, "wrong_meter")
    set_check("tariff_id_match", str(ar_t.get("tariff_id", "")) == receipt.tariff_id, "tariff_id_mismatch")
    set_check(
        "tariff_version_match",
        str(ar_t.get("tariff_version", "")) == receipt.tariff_version,
        "tariff_version_mismatch",
    )

    tw_start = int(ar_t.get("tw_start", ar_t.get("start_time", receipt.ts_start)))
    tw_end = int(ar_t.get("tw_end", ar_t.get("end_time", receipt.ts_end)))
    set_check("time_window_start_ok", receipt.ts_start >= tw_start, "start_before_time_window")
    set_check("time_window_end_ok", receipt.ts_end <= tw_end, "end_after_time_window")

    cap_kwh = float(ar_t.get("cap_kwh", ar_t.get("energy_cap", receipt.delivered_kwh)))
    set_check("energy_nonnegative", receipt.delivered_kwh >= -amount_tolerance, "negative_energy")
    set_check("energy_cap_ok", receipt.delivered_kwh <= cap_kwh + amount_tolerance, "over_cap")

    unit_price = float(ar_t.get("unit_price", 0.0))
    tariff = eval_tariff_amount(
        delivered_kwh=receipt.delivered_kwh,
        unit_price=unit_price,
        mode=receipt.tariff_mode,
        connection_duration_s=receipt.connection_duration_s,
        active_charging_duration_s=receipt.active_charging_duration_s,
        parking_duration_s=receipt.parking_duration_s,
    )
    captured_amount = float(tariff.amount)
    effective_limit = float(ar_t.get("effective_preauth_limit_t", ar_t.get("preauth_limit_t", 0.0)))
    set_check(
        "amount_within_effective_limit",
        captured_amount <= effective_limit + amount_tolerance,
        "amount_exceeds_effective_limit",
    )

    # If the private DeliveryReceipt payload was provided, enforce digest-level
    # consistency for fields that overlap with the public receipt.
    dr_private = opened_payloads.get("DeliveryReceiptPrivate")
    if dr_private:
        set_check(
            "private_delivered_kwh_match",
            abs(float(dr_private.get("delivered_kwh", receipt.delivered_kwh)) - float(receipt.delivered_kwh)) <= amount_tolerance,
            "private_delivered_kwh_mismatch",
        )
        set_check(
            "private_time_match",
            int(dr_private.get("start_time", receipt.ts_start)) == receipt.ts_start
            and int(dr_private.get("end_time", receipt.ts_end)) == receipt.ts_end,
            "private_time_mismatch",
        )

    # S_view must be the settlement projection by construction.
    set_check("settlement_phase", S_view.phase == "S", "wrong_projection_phase")

    # Optional meter-values consistency: if samples exist, the root is at least
    # deterministic and becomes part of RBC binding_digest.
    if meter_samples:
        set_check("meter_values_root_present", bool(meter_values_root(meter_samples)), "missing_meter_values_root")
    else:
        checks["meter_values_root_present"] = True

    return checks, reasons
