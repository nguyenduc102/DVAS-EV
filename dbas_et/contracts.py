"""
Python contract-state simulation for DBAS-ET.

These classes simulate the logical state transitions of registry,
authorization, settlement, and dispute contracts.

They are not production smart contracts. The Solidity contracts and gas
measurements are in foundry/.

Numeric note
------------
The Python simulator uses float values rounded to 6 decimal places for
protocol-level monetary amounts. Therefore settlement cap comparisons use
MONEY_EPS to avoid false blocks caused only by floating-point roundoff.
This tolerance is not a security relaxation. It is a simulation accounting
tolerance for 6-decimal deterministic tariff outputs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .receipt_binding import digest_record
from .capsule import CanonicalCapsule
from .admission import AdmissionCertificate, verify_admission_certificate
from .entities import Meter, Station, User, ValidatorNode
from .payments import (
    DeliveryReceipt,
    TopUpAuthorizationEvent,
    eval_tariff_amount,
    receipt_hash,
    topup_hash,
    verify_delivery_receipt,
    verify_topup_event,
)
from .projections import ProjectionProof, ProjectionView, V2SlimSettlementBackend
from .result import ProtocolResult, ProtocolStatus, RejectReason
from .settlement_verifier import (
    ReceiptBindingCertificatePublic,
    SettlementVerifier,
    verify_rbc_public_signature,
)
from .station_hybrid_auth import verify_station_session_binding_certificate


MONEY_EPS = 1e-5


@dataclass
class AuthRecord:
    """Authorization state for one trade."""

    trade_id: str
    owner_address: str
    user_id: str
    station_id: str
    meter_id: str
    rho_t: str
    initial_preauth_limit_t: float
    effective_preauth_limit_t: float
    held_amount: float
    state: ProtocolStatus = ProtocolStatus.AUTHORIZED
    captured_amount: float = 0.0
    released_unused_hold: float = 0.0
    topup_count: int = 0
    topup_total: float = 0.0

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["state"] = str(self.state)
        return record


@dataclass
class SessionRecord:
    """Charging session state."""

    trade_id: str
    sid_t: str
    state: ProtocolStatus
    nonce_u: str = ""
    nonce_s: str = ""

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["state"] = str(self.state)
        return record


@dataclass
class SettlementOutput:
    """Settlement output returned after successful release."""

    trade_id: str
    captured_amount: float
    released_unused_hold: float
    held_amount_after: float
    user_balance_after: float
    station_ledger_after: float
    receipt_hash: str

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


class RegSC:
    """
    Registry contract simulation.

    Stores active users, stations, meters, and validators.
    """

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.stations: dict[str, Station] = {}
        self.meters: dict[str, Meter] = {}
        self.validators: dict[str, ValidatorNode] = {}

    def register_user(self, user: User) -> ProtocolResult:
        self.users[user.user_id] = user
        return ProtocolResult.success(
            status=ProtocolStatus.SUCCESS,
            metadata={"event": "register_user", "user_id": user.user_id},
        )

    def register_station(self, station: Station) -> ProtocolResult:
        self.stations[station.station_id] = station
        return ProtocolResult.success(
            status=ProtocolStatus.SUCCESS,
            metadata={"event": "register_station", "station_id": station.station_id},
        )

    def register_meter(self, meter: Meter) -> ProtocolResult:
        station = self.stations.get(meter.station_id)
        if station is None:
            return ProtocolResult.reject(
                RejectReason.WRONG_STATION,
                {"event": "register_meter", "meter_id": meter.meter_id},
            )

        self.meters[meter.meter_id] = meter

        if meter.meter_id not in station.meter_ids:
            station.meter_ids.append(meter.meter_id)

        return ProtocolResult.success(
            status=ProtocolStatus.SUCCESS,
            metadata={"event": "register_meter", "meter_id": meter.meter_id},
        )

    def register_validator(self, validator: ValidatorNode) -> ProtocolResult:
        self.validators[validator.validator_id] = validator
        return ProtocolResult.success(
            status=ProtocolStatus.SUCCESS,
            metadata={"event": "register_validator", "validator_id": validator.validator_id},
        )

    def check_station_meter(self, station_id: str, meter_id: str) -> bool:
        station = self.stations.get(station_id)
        meter = self.meters.get(meter_id)

        if station is None or meter is None:
            return False

        return meter.station_id == station_id and meter_id in station.meter_ids


class AuthSC:
    """
    Authorization contract simulation.

    Reserves preauth_limit_t as held_amount.
    This is not final payment capture.
    """

    def __init__(self, regsc: RegSC) -> None:
        self.regsc = regsc
        self.records: dict[str, AuthRecord] = {}
        self.topup_events: dict[str, list[TopUpAuthorizationEvent]] = {}

    def authorize_trade(
        self,
        user: User,
        capsule: CanonicalCapsule,
        rho_t: str,
        A_view: ProjectionView,
        A_proof: ProjectionProof,
        backend: V2SlimSettlementBackend,
        adm_cert: AdmissionCertificate | dict[str, Any] | None = None,
        validator: ValidatorNode | None = None,
        admission_policy_record: dict[str, Any] | None = None,
    ) -> ProtocolResult:
        """Verify A projection, optional admission certificate, and reserve hold.

        adm_cert and validator are optional. With both, AuthSC also checks the
        validator's admission certificate, not only the projection proof.
        """
        if user.user_id not in self.regsc.users:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "authorize_trade", "detail": "user not registered"},
            )

        if capsule.station_id not in self.regsc.stations:
            return ProtocolResult.reject(
                RejectReason.WRONG_STATION,
                {"event": "authorize_trade", "station_id": capsule.station_id},
            )

        if not self.regsc.check_station_meter(capsule.station_id, capsule.meter_id):
            return ProtocolResult.reject(
                RejectReason.WRONG_METER,
                {"event": "authorize_trade", "meter_id": capsule.meter_id},
            )

        verification = backend.verify_projection_detailed(rho_t, A_view, A_proof)
        if not verification.ok:
            return ProtocolResult.reject(
                RejectReason.INVALID_AUTHORIZATION_PROJECTION,
                {"event": "authorize_trade", "projection_reason": verification.reason},
            )

        if (adm_cert is None) != (validator is None):
            return ProtocolResult.reject(
                RejectReason.INVALID_ADMISSION_CERTIFICATE,
                {"event": "authorize_trade", "detail": "adm_cert and validator must be provided together"},
            )

        if adm_cert is not None and validator is not None:
            if validator.validator_id not in self.regsc.validators:
                return ProtocolResult.reject(
                    RejectReason.INVALID_ADMISSION_CERTIFICATE,
                    {"event": "authorize_trade", "detail": "validator not registered"},
                )

            if not verify_admission_certificate(
                validator=validator,
                certificate=adm_cert,
                trade_id=capsule.trade_id,
                rho_t=rho_t,
                A_view=A_view,
                policy_record=admission_policy_record or {},
            ):
                return ProtocolResult.reject(
                    RejectReason.INVALID_ADMISSION_CERTIFICATE,
                    {"event": "authorize_trade", "detail": "admission certificate invalid"},
                )

        if capsule.user_address != user.address:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "authorize_trade", "detail": "user address mismatch"},
            )

        preauth_limit_t = float(capsule.preauth_limit_t)

        if user.balance + MONEY_EPS < preauth_limit_t:
            return ProtocolResult.reject(
                RejectReason.INSUFFICIENT_BALANCE,
                {
                    "event": "authorize_trade",
                    "balance": float(user.balance),
                    "preauth_limit_t": preauth_limit_t,
                    "money_eps": MONEY_EPS,
                },
            )

        user.balance = round(user.balance - preauth_limit_t, 6)

        record = AuthRecord(
            trade_id=capsule.trade_id,
            owner_address=user.address,
            user_id=user.user_id,
            station_id=capsule.station_id,
            meter_id=capsule.meter_id,
            rho_t=rho_t,
            initial_preauth_limit_t=preauth_limit_t,
            effective_preauth_limit_t=preauth_limit_t,
            held_amount=preauth_limit_t,
            state=ProtocolStatus.AUTHORIZED,
        )

        self.records[capsule.trade_id] = record

        return ProtocolResult.success(
            value=record,
            status=ProtocolStatus.AUTHORIZED,
            metadata={
                "event": "authorize_trade",
                "trade_id": capsule.trade_id,
                "preauth_limit_t": preauth_limit_t,
                "held_amount": preauth_limit_t,
                "user_balance_after_hold": float(user.balance),
                "adm_cert_verified": bool(adm_cert is not None),
            },
        )

    def apply_topup(
        self,
        user: User,
        event: TopUpAuthorizationEvent,
    ) -> ProtocolResult:
        """
        Apply a signed top-up event.

        Top-up increases effective_preauth_limit_t and held_amount without
        recommitting rho_t.
        """
        record = self.records.get(event.trade_id)
        if record is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "apply_topup", "detail": "trade not found"},
            )

        if record.owner_address != user.address:
            return ProtocolResult.reject(
                RejectReason.TOPUP_SIGNATURE_INVALID,
                {"event": "apply_topup", "detail": "owner mismatch"},
            )

        if record.rho_t != event.rho_t:
            return ProtocolResult.reject(
                RejectReason.TOPUP_SIGNATURE_INVALID,
                {"event": "apply_topup", "detail": "rho mismatch"},
            )

        if not verify_topup_event(user, event):
            return ProtocolResult.reject(
                RejectReason.TOPUP_SIGNATURE_INVALID,
                {"event": "apply_topup"},
            )

        if record.state not in {
            ProtocolStatus.AUTHORIZED,
            ProtocolStatus.DELIVERING,
            ProtocolStatus.RECEIPT_SUBMITTED,
        }:
            return ProtocolResult.reject(
                RejectReason.TOPUP_NOT_ENABLED,
                {"event": "apply_topup", "state": str(record.state)},
            )

        if abs(record.effective_preauth_limit_t - event.old_limit) > MONEY_EPS:
            return ProtocolResult.reject(
                RejectReason.TOPUP_OLD_LIMIT_MISMATCH,
                {
                    "event": "apply_topup",
                    "record_limit": record.effective_preauth_limit_t,
                    "event_old_limit": event.old_limit,
                    "money_eps": MONEY_EPS,
                },
            )

        if user.balance + MONEY_EPS < event.delta_limit:
            return ProtocolResult.reject(
                RejectReason.INSUFFICIENT_BALANCE_FOR_TOPUP,
                {
                    "event": "apply_topup",
                    "balance": float(user.balance),
                    "delta_limit": float(event.delta_limit),
                    "money_eps": MONEY_EPS,
                },
            )

        user.balance = round(user.balance - event.delta_limit, 6)

        record.effective_preauth_limit_t = round(event.new_limit, 6)
        record.held_amount = round(record.held_amount + event.delta_limit, 6)
        record.topup_count += 1
        record.topup_total = round(record.topup_total + event.delta_limit, 6)

        self.topup_events.setdefault(event.trade_id, []).append(event)

        return ProtocolResult.success(
            value=record,
            status=record.state,
            metadata={
                "event": "apply_topup",
                "trade_id": event.trade_id,
                "rho_t_unchanged": True,
                "old_limit": float(event.old_limit),
                "delta_limit": float(event.delta_limit),
                "new_limit": float(event.new_limit),
                "held_amount_after_topup": float(record.held_amount),
                "topup_hash": topup_hash(event),
            },
        )


class SettleSC:
    """
    Settlement contract simulation.

    Settlement captures actual amount only after a valid receipt and S projection.
    """

    def __init__(self, regsc: RegSC, authsc: AuthSC) -> None:
        self.regsc = regsc
        self.authsc = authsc
        self.sessions: dict[str, SessionRecord] = {}
        self.receipts: dict[str, DeliveryReceipt] = {}
        self.used_receipts: set[str] = set()
        self.station_ledger: dict[str, float] = {}

    def open_session(
        self,
        trade_id: str,
        sid_t: str,
        nonce_u: str = "",
        nonce_s: str = "",
        station_cert: Any | None = None,
    ) -> ProtocolResult:
        record = self.authsc.records.get(trade_id)
        if record is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "open_session", "detail": "auth record not found"},
            )

        if record.state != ProtocolStatus.AUTHORIZED:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "open_session", "state": str(record.state)},
            )

        station = self.regsc.stations.get(record.station_id)
        if station is None:
            return ProtocolResult.reject(
                RejectReason.WRONG_STATION,
                {"event": "open_session", "station_id": record.station_id},
            )

        station_auth_mode = "legacy-no-station-certificate"
        if station_cert is not None:
            ok, reason = verify_station_session_binding_certificate(
                station=station,
                cert=station_cert,
                expected_trade_id=trade_id,
                expected_rho_t=record.rho_t,
                expected_sid_t=sid_t,
                expected_meter_id=record.meter_id,
            )
            if not ok:
                reject_reason = (
                    RejectReason.INVALID_PQ_SIGNATURE
                    if "pq" in reason
                    else RejectReason.INVALID_CLASSICAL_SIGNATURE
                    if "classical" in reason
                    else RejectReason.WRONG_STATION
                )
                return ProtocolResult.reject(
                    reject_reason,
                    {
                        "event": "open_session",
                        "station_id": record.station_id,
                        "station_auth_mode": "hybrid-classical-pq",
                        "station_auth_reason": reason,
                    },
                )
            station_auth_mode = "hybrid-classical-pq"

        record.state = ProtocolStatus.DELIVERING

        session = SessionRecord(
            trade_id=trade_id,
            sid_t=sid_t,
            state=ProtocolStatus.DELIVERING,
            nonce_u=nonce_u,
            nonce_s=nonce_s,
        )

        self.sessions[trade_id] = session

        return ProtocolResult.success(
            value=session,
            status=ProtocolStatus.DELIVERING,
            metadata={
                "event": "open_session",
                "trade_id": trade_id,
                "sid_t": sid_t,
                "station_auth_mode": station_auth_mode,
            },
        )

    def submit_receipt(self, receipt: DeliveryReceipt) -> ProtocolResult:
        """Submit a meter-signed delivery receipt.

        Replays are checked here and again in release_settlement, so a settled
        receipt cannot move the authorization record from SETTLED back to
        RECEIPT_SUBMITTED.
        """
        record = self.authsc.records.get(receipt.trade_id)
        if record is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "submit_receipt", "detail": "auth record not found"},
            )

        session = self.sessions.get(receipt.trade_id)
        if session is None or session.sid_t != receipt.sid_t:
            return ProtocolResult.reject(
                RejectReason.WRONG_SESSION,
                {"event": "submit_receipt", "sid_t": receipt.sid_t},
            )

        if record.state == ProtocolStatus.SETTLED:
            return ProtocolResult.block(
                RejectReason.REPLAY_DETECTED,
                {
                    "event": "submit_receipt",
                    "trade_id": receipt.trade_id,
                    "detail": "receipt submitted after settlement",
                },
            )

        if record.state not in {ProtocolStatus.DELIVERING, ProtocolStatus.RECEIPT_SUBMITTED}:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "submit_receipt", "state": str(record.state)},
            )

        if not self.regsc.check_station_meter(receipt.station_id, receipt.meter_id):
            return ProtocolResult.reject(
                RejectReason.WRONG_METER,
                {"event": "submit_receipt", "meter_id": receipt.meter_id},
            )

        meter = self.regsc.meters.get(receipt.meter_id)
        if meter is None:
            return ProtocolResult.reject(
                RejectReason.WRONG_METER,
                {"event": "submit_receipt", "meter_id": receipt.meter_id},
            )

        if not verify_delivery_receipt(meter, receipt):
            return ProtocolResult.reject(
                RejectReason.INVALID_METER_SIGNATURE,
                {"event": "submit_receipt", "meter_id": receipt.meter_id},
            )

        rh = receipt_hash(receipt)
        if rh in self.used_receipts:
            return ProtocolResult.block(
                RejectReason.REPLAY_DETECTED,
                {"event": "submit_receipt", "receipt_hash": rh},
            )

        record.state = ProtocolStatus.RECEIPT_SUBMITTED
        session.state = ProtocolStatus.RECEIPT_SUBMITTED
        self.receipts[receipt.trade_id] = receipt

        return ProtocolResult.success(
            value=receipt,
            status=ProtocolStatus.RECEIPT_SUBMITTED,
            metadata={
                "event": "submit_receipt",
                "trade_id": receipt.trade_id,
                "receipt_hash": rh,
                "delivered_kwh": float(receipt.delivered_kwh),
            },
        )

    def release_settlement(
        self,
        capsule: CanonicalCapsule,
        rho_t: str,
        S_view: ProjectionView,
        S_proof: ProjectionProof,
        backend: V2SlimSettlementBackend,
        user: User,
    ) -> ProtocolResult:
        """Release settlement if receipt and projection match committed capsule."""
        record = self.authsc.records.get(capsule.trade_id)
        if record is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "release_settlement", "detail": "auth record not found"},
            )

        if record.state != ProtocolStatus.RECEIPT_SUBMITTED:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "release_settlement", "state": str(record.state)},
            )

        if record.rho_t != rho_t:
            return ProtocolResult.reject(
                RejectReason.INVALID_SETTLEMENT_PROJECTION,
                {"event": "release_settlement", "detail": "rho mismatch"},
            )

        verification = backend.verify_projection_detailed(rho_t, S_view, S_proof)
        if not verification.ok:
            return ProtocolResult.reject(
                RejectReason.INVALID_SETTLEMENT_PROJECTION,
                {"event": "release_settlement", "projection_reason": verification.reason},
            )

        receipt = self.receipts.get(capsule.trade_id)
        if receipt is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {"event": "release_settlement", "detail": "receipt missing"},
            )

        rh = receipt_hash(receipt)
        if rh in self.used_receipts:
            return ProtocolResult.block(
                RejectReason.REPLAY_DETECTED,
                {"event": "release_settlement", "receipt_hash": rh},
            )

        match_result = self._match_receipt_to_capsule(capsule, receipt)
        if not match_result.ok:
            return match_result

        tariff = eval_tariff_amount(
            delivered_kwh=receipt.delivered_kwh,
            unit_price=capsule.unit_price,
            mode=receipt.tariff_mode,
            connection_duration_s=receipt.connection_duration_s,
            active_charging_duration_s=receipt.active_charging_duration_s,
            parking_duration_s=receipt.parking_duration_s,
        )

        captured_amount = round(float(tariff.amount), 6)

        if captured_amount > record.effective_preauth_limit_t + MONEY_EPS:
            return ProtocolResult.block(
                RejectReason.AMOUNT_EXCEEDS_PREAUTH_LIMIT,
                {
                    "event": "release_settlement",
                    "captured_amount": captured_amount,
                    "effective_preauth_limit_t": float(record.effective_preauth_limit_t),
                    "money_eps": MONEY_EPS,
                },
            )

        if captured_amount > record.held_amount + MONEY_EPS:
            return ProtocolResult.block(
                RejectReason.AMOUNT_EXCEEDS_HELD_AMOUNT,
                {
                    "event": "release_settlement",
                    "captured_amount": captured_amount,
                    "held_amount": float(record.held_amount),
                    "money_eps": MONEY_EPS,
                },
            )

        released_unused_hold = round(max(0.0, record.held_amount - captured_amount), 6)

        record.held_amount = 0.0
        record.captured_amount = captured_amount
        record.released_unused_hold = released_unused_hold
        record.state = ProtocolStatus.SETTLED

        self.used_receipts.add(rh)

        user.balance = round(user.balance + released_unused_hold, 6)

        self.station_ledger[capsule.station_id] = round(
            self.station_ledger.get(capsule.station_id, 0.0) + captured_amount,
            6,
        )

        output = SettlementOutput(
            trade_id=capsule.trade_id,
            captured_amount=captured_amount,
            released_unused_hold=released_unused_hold,
            held_amount_after=0.0,
            user_balance_after=float(user.balance),
            station_ledger_after=float(self.station_ledger[capsule.station_id]),
            receipt_hash=rh,
        )

        return ProtocolResult.success(
            value=output,
            status=ProtocolStatus.SETTLED,
            metadata={
                "event": "release_settlement",
                **output.to_record(),
                "tariff_mode": tariff.mode,
                "money_eps": MONEY_EPS,
            },
        )

    def release_settlement_with_certificate(
        self,
        rbc_public: ReceiptBindingCertificatePublic | dict[str, Any],
        verifier: SettlementVerifier,
        user: User,
    ) -> ProtocolResult:
        """Release settlement using a signed RBC_public.

        Security checks performed by this contract-state simulator:

        1. Verify the verifier signature over RBC_public.
        2. Require an existing AuthRecord in RECEIPT_SUBMITTED state.
        3. Bind RBC_public.rho_t to the AuthRecord root.
        4. Bind RBC_public.sid_t to the opened session.
        5. Bind RBC_public.receipt_hash to the receipt submitted to SettleSC.
        6. Bind RBC_public.ar_digest to the current AuthRecord digest.
        7. Require RBC_public.predicate_result == True.
        8. Reject replayed receipts.
        9. Enforce captured_amount <= effective preauthorization limit.
        10. Enforce captured_amount <= held amount.
        11. Release captured amount and refund unused hold.

        The off-chain SettlementVerifier decrypts the private payloads and
        evaluates Match. SettleSC only checks public roots, digests, certificate
        state, replay state and reserved-fund bounds.
        """
        rbc = (
            rbc_public
            if isinstance(rbc_public, ReceiptBindingCertificatePublic)
            else ReceiptBindingCertificatePublic(**dict(rbc_public))
        )

        # 1. Verifier signature must be valid.
        if not verify_rbc_public_signature(verifier=verifier, rbc_public=rbc):
            return ProtocolResult.reject(
                "invalid_rbc_signature",
                {
                    "event": "release_settlement_with_certificate",
                    "trade_id": rbc.trade_id,
                    "verifier_id": rbc.verifier_id,
                },
            )

        # 2. AuthRecord must exist.
        record = self.authsc.records.get(rbc.trade_id)
        if record is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "auth record not found",
                    "trade_id": rbc.trade_id,
                },
            )

        # 3. Settlement must happen only after a receipt was submitted.
        if record.state != ProtocolStatus.RECEIPT_SUBMITTED:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "trade is not in receipt_submitted state",
                    "state": str(record.state),
                    "trade_id": rbc.trade_id,
                },
            )

        # 4. RBC root must match the root held by AuthSC.
        if record.rho_t != rbc.rho_t:
            return ProtocolResult.reject(
                RejectReason.INVALID_SETTLEMENT_PROJECTION,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "rho mismatch",
                    "record_rho_t": record.rho_t,
                    "rbc_rho_t": rbc.rho_t,
                    "trade_id": rbc.trade_id,
                },
            )

        # 5. RBC session ID must match the opened session in SettleSC.
        session = self.sessions.get(rbc.trade_id)
        if session is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "session not found",
                    "trade_id": rbc.trade_id,
                },
            )

        if session.sid_t != rbc.sid_t:
            return ProtocolResult.reject(
                RejectReason.WRONG_SESSION,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "rbc sid_t does not match opened session",
                    "record_sid_t": session.sid_t,
                    "rbc_sid_t": rbc.sid_t,
                    "trade_id": rbc.trade_id,
                },
            )

        # 6. RBC receipt hash must match the receipt already submitted to SettleSC.
        submitted_receipt = self.receipts.get(rbc.trade_id)
        if submitted_receipt is None:
            return ProtocolResult.reject(
                RejectReason.UNKNOWN_ERROR,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "submitted receipt not found",
                    "trade_id": rbc.trade_id,
                },
            )

        submitted_receipt_hash = receipt_hash(submitted_receipt)
        if submitted_receipt_hash != rbc.receipt_hash:
            return ProtocolResult.reject(
                RejectReason.REPLAY_DETECTED,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "rbc receipt_hash does not match submitted receipt",
                    "submitted_receipt_hash": submitted_receipt_hash,
                    "rbc_receipt_hash": rbc.receipt_hash,
                    "trade_id": rbc.trade_id,
                },
            )

        # 7. RBC authorization digest must match the current AuthRecord digest.
        #
        # SettlementVerifier computes rbc.ar_digest from the same public
        # AuthRecord representation:
        #
        #     digest_record("DBAS-ET:AR:v1", record.to_record())
        #
        # not from an extended off-chain ar_t object containing extra fields.
        expected_ar_digest = digest_record("DBAS-ET:AR:v1", record.to_record())
        if expected_ar_digest != rbc.ar_digest:
            return ProtocolResult.reject(
                RejectReason.INVALID_SETTLEMENT_PROJECTION,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "rbc ar_digest does not match current AuthRecord",
                    "expected_ar_digest": expected_ar_digest,
                    "rbc_ar_digest": rbc.ar_digest,
                    "trade_id": rbc.trade_id,
                },
            )

        # 8. RBC predicate must be true (false means the verifier's Match failed).
        if not rbc.predicate_result:
            return ProtocolResult.block(
                "rbc_predicate_failed",
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "RBC predicate_result is false",
                    "failure_reason": rbc.failure_reason,
                    "trade_id": rbc.trade_id,
                },
            )

        # 9. Receipt replay check.
        if rbc.receipt_hash in self.used_receipts:
            return ProtocolResult.block(
                RejectReason.REPLAY_DETECTED,
                {
                    "event": "release_settlement_with_certificate",
                    "detail": "receipt hash already consumed",
                    "receipt_hash": rbc.receipt_hash,
                    "trade_id": rbc.trade_id,
                },
            )

        # 10. Payment bound checks.
        captured_amount = round(float(rbc.captured_amount), 6)

        if captured_amount > record.effective_preauth_limit_t + MONEY_EPS:
            return ProtocolResult.block(
                RejectReason.AMOUNT_EXCEEDS_PREAUTH_LIMIT,
                {
                    "event": "release_settlement_with_certificate",
                    "captured_amount": captured_amount,
                    "effective_preauth_limit_t": float(record.effective_preauth_limit_t),
                    "money_eps": MONEY_EPS,
                    "trade_id": rbc.trade_id,
                },
            )

        if captured_amount > record.held_amount + MONEY_EPS:
            return ProtocolResult.block(
                RejectReason.AMOUNT_EXCEEDS_HELD_AMOUNT,
                {
                    "event": "release_settlement_with_certificate",
                    "captured_amount": captured_amount,
                    "held_amount": float(record.held_amount),
                    "money_eps": MONEY_EPS,
                    "trade_id": rbc.trade_id,
                },
            )

        # 11. Release captured amount and refund unused hold.
        released_unused_hold = round(max(0.0, record.held_amount - captured_amount), 6)

        record.held_amount = 0.0
        record.captured_amount = captured_amount
        record.released_unused_hold = released_unused_hold
        record.state = ProtocolStatus.SETTLED

        self.used_receipts.add(rbc.receipt_hash)

        user.balance = round(user.balance + released_unused_hold, 6)
        self.station_ledger[record.station_id] = round(
            self.station_ledger.get(record.station_id, 0.0) + captured_amount,
            6,
        )

        output = SettlementOutput(
            trade_id=rbc.trade_id,
            captured_amount=captured_amount,
            released_unused_hold=released_unused_hold,
            held_amount_after=0.0,
            user_balance_after=float(user.balance),
            station_ledger_after=float(self.station_ledger[record.station_id]),
            receipt_hash=rbc.receipt_hash,
        )

        return ProtocolResult.success(
            value=output,
            status=ProtocolStatus.SETTLED,
            metadata={
                "event": "release_settlement_with_certificate",
                **output.to_record(),
                "verifier_id": rbc.verifier_id,
                "rbc_binding_digest": rbc.binding_digest,
                "rbc_private_evidence_digest": getattr(rbc, "private_evidence_digest", ""),
                "money_eps": MONEY_EPS,
            },
        )

    def _match_receipt_to_capsule(
        self,
        capsule: CanonicalCapsule,
        receipt: DeliveryReceipt,
    ) -> ProtocolResult:
        """Check delivery receipt against committed capsule semantics."""
        if receipt.trade_id != capsule.trade_id:
            return ProtocolResult.reject(
                RejectReason.WRONG_SESSION,
                {"event": "match_receipt"},
            )

        if receipt.station_id != capsule.station_id:
            return ProtocolResult.reject(
                RejectReason.WRONG_STATION,
                {"event": "match_receipt"},
            )

        if receipt.meter_id != capsule.meter_id:
            return ProtocolResult.reject(
                RejectReason.WRONG_METER,
                {"event": "match_receipt"},
            )

        if receipt.tariff_id != capsule.tariff_id or receipt.tariff_version != capsule.tariff_version:
            return ProtocolResult.block(
                RejectReason.TARIFF_MISMATCH,
                {
                    "event": "match_receipt",
                    "receipt_tariff_id": receipt.tariff_id,
                    "capsule_tariff_id": capsule.tariff_id,
                },
            )

        if receipt.ts_start < capsule.tw_start or receipt.ts_end > capsule.tw_end:
            return ProtocolResult.block(
                RejectReason.TIME_WINDOW_MISMATCH,
                {
                    "event": "match_receipt",
                    "receipt_ts_start": receipt.ts_start,
                    "receipt_ts_end": receipt.ts_end,
                    "tw_start": capsule.tw_start,
                    "tw_end": capsule.tw_end,
                },
            )

        if receipt.delivered_kwh > capsule.cap_kwh + MONEY_EPS:
            return ProtocolResult.block(
                RejectReason.ENERGY_CAP_EXCEEDED,
                {
                    "event": "match_receipt",
                    "delivered_kwh": float(receipt.delivered_kwh),
                    "cap_kwh": float(capsule.cap_kwh),
                    "money_eps": MONEY_EPS,
                },
            )

        return ProtocolResult.success(
            status=ProtocolStatus.SUCCESS,
            metadata={"event": "match_receipt", "trade_id": capsule.trade_id},
        )


class DisputeSC:
    """Minimal dispute contract simulation."""

    def __init__(self) -> None:
        self.disputes: dict[str, dict[str, Any]] = {}

    def open_dispute(
        self,
        trade_id: str,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> ProtocolResult:
        evidence = evidence or {}
        self.disputes[trade_id] = {
            "trade_id": trade_id,
            "reason": reason,
            "evidence": evidence,
        }

        return ProtocolResult.success(
            status=ProtocolStatus.DISPUTED,
            metadata={
                "event": "open_dispute",
                "trade_id": trade_id,
                "reason": reason,
            },
        )