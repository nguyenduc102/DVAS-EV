"""
Result and protocol status types for DBAS-ET.

Protocol-level failures such as invalid signatures, bad proofs, wrong meters,
replayed receipts, or cap violations must be represented as explicit reject or
blocked results. Normal protocol rejection must not crash the simulator through
AssertionError.

Assertions should be reserved for tests and developer invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, Optional, TypeVar, Union

T = TypeVar("T")
E = TypeVar("E")


@dataclass(frozen=True)
class Ok(Generic[T]):
    """Success result containing a value."""

    value: T

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value


@dataclass(frozen=True)
class Err(Generic[E]):
    """Error result containing an error value."""

    error: E

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def unwrap(self) -> T:
        raise ValueError(f"called unwrap() on Err: {self.error}")

    def unwrap_or(self, default: T) -> T:
        return default


Result = Union[Ok[T], Err[E]]


class ProtocolStatus(StrEnum):
    """Stable protocol status values for CSV/JSONL output."""

    SUCCESS = "success"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    ERROR = "error"
    PENDING = "pending"
    AUTHORIZED = "authorized"
    DELIVERING = "delivering"
    RECEIPT_SUBMITTED = "receipt_submitted"
    SETTLED = "settled"
    DISPUTED = "disputed"
    CANCELLED = "cancelled"


class RejectReason(StrEnum):
    """Stable rejection reason codes."""

    # Authorization rejections
    INSUFFICIENT_BALANCE = "insufficient_balance"
    INVALID_CLASSICAL_SIGNATURE = "invalid_classical_signature"
    INVALID_PQ_SIGNATURE = "invalid_pq_signature"
    INVALID_ADMISSION_CERTIFICATE = "invalid_admission_certificate"
    INVALID_AUTHORIZATION_PROJECTION = "invalid_authorization_projection"

    # Delivery / receipt rejections
    INVALID_METER_SIGNATURE = "invalid_meter_signature"
    WRONG_METER = "wrong_meter"
    WRONG_STATION = "wrong_station"
    WRONG_SESSION = "wrong_session"

    # Settlement rejections
    AMOUNT_EXCEEDS_PREAUTH_LIMIT = "amount_exceeds_preauth_limit"
    AMOUNT_EXCEEDS_HELD_AMOUNT = "amount_exceeds_held_amount"
    INVALID_SETTLEMENT_PROJECTION = "invalid_settlement_projection"
    TARIFF_MISMATCH = "tariff_mismatch"
    TIME_WINDOW_MISMATCH = "time_window_mismatch"
    ENERGY_CAP_EXCEEDED = "energy_cap_exceeded"
    REPLAY_DETECTED = "replay_detected"

    # Top-up rejections
    TOPUP_NOT_ENABLED = "topup_not_enabled"
    TOPUP_SIGNATURE_INVALID = "topup_signature_invalid"
    TOPUP_OLD_LIMIT_MISMATCH = "topup_old_limit_mismatch"
    INSUFFICIENT_BALANCE_FOR_TOPUP = "insufficient_balance_for_topup"

    # Dispute
    DISPUTE_PROOF_INVALID = "dispute_proof_invalid"

    # Generic
    UNKNOWN_ERROR = "unknown_error"


@dataclass(frozen=True)
class ProtocolResult:
    """
    Structured protocol operation result.

    Attributes
    ----------
    ok:
        True when the operation is accepted.
    status:
        Stable status code.
    reason:
        Stable reject/block/error reason when ok is False.
    value:
        Optional success value.
    metadata:
        Stable dictionary for CSV/JSONL output.
    """

    ok: bool
    status: ProtocolStatus
    reason: str = ""
    value: Any | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def success(
        value: Any | None = None,
        status: ProtocolStatus = ProtocolStatus.SUCCESS,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "ProtocolResult":
        return ProtocolResult(
            ok=True,
            status=status,
            value=value,
            metadata=metadata or {},
        )

    @staticmethod
    def reject(
        reason: RejectReason | str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "ProtocolResult":
        return ProtocolResult(
            ok=False,
            status=ProtocolStatus.REJECTED,
            reason=str(reason),
            metadata=metadata or {},
        )

    @staticmethod
    def block(
        reason: RejectReason | str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "ProtocolResult":
        return ProtocolResult(
            ok=False,
            status=ProtocolStatus.BLOCKED,
            reason=str(reason),
            metadata=metadata or {},
        )

    @staticmethod
    def error(
        reason: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "ProtocolResult":
        return ProtocolResult(
            ok=False,
            status=ProtocolStatus.ERROR,
            reason=reason,
            metadata=metadata or {},
        )

    def to_record(self) -> dict[str, Any]:
        """Return a stable CSV/JSONL-friendly record."""
        return {
            "ok": self.ok,
            "status": str(self.status),
            "reason": self.reason,
            **self.metadata,
        }