"""
DVAS-EV field registry, committed layout schema and record types.

Every semantic field has a stable u16 ID, a type, and a lifecycle class:

PRE_SERVICE_COMMITTED  fixed before charging; the only fields allowed in the
                       transaction commitment rho_t.
POST_SERVICE_EVIDENCE  produced by the meter/station after charging
                       (public delivery receipt, private delivery payload).
SETTLEMENT_OUTPUT      produced by verifiers/settlement (decision, amounts,
                       attestations).

Field IDs are never reused or renumbered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import (
    EncodingError,
    FieldRegistry,
    FieldSpec,
    Lifecycle,
    RecordType,
    TypeTag,
    encode_field,
    tagged_hash,
)

PRE = Lifecycle.PRE_SERVICE_COMMITTED
POST = Lifecycle.POST_SERVICE_EVIDENCE
OUT = Lifecycle.SETTLEMENT_OUTPUT

_S = TypeTag.STRING
_F6 = TypeTag.FIXED6
_TS = TypeTag.TIMESTAMP
_U = TypeTag.UINT
_D = TypeTag.DIGEST32
_E = TypeTag.ENUM

FIELD_SPECS: tuple[FieldSpec, ...] = (
    # --- PRE_SERVICE_COMMITTED: transaction capsule C_t -------------------
    FieldSpec(0x0001, "protocol_version", _S, PRE, "meta"),
    FieldSpec(0x0002, "schema_version", _S, PRE, "meta"),
    FieldSpec(0x0003, "tid", _S, PRE, "meta", description="transaction identifier"),
    FieldSpec(0x0004, "created_at", _TS, PRE, "meta", unit="unix_s_utc"),
    FieldSpec(0x0010, "user_id", _S, PRE, "parties"),
    FieldSpec(0x0011, "user_account", _S, PRE, "parties", description="payer account/address"),
    FieldSpec(0x0012, "home_operator", _S, PRE, "parties", description="eMSP / home domain"),
    FieldSpec(0x0013, "station_id", _S, PRE, "parties"),
    FieldSpec(0x0014, "meter_id", _S, PRE, "parties"),
    FieldSpec(0x0015, "foreign_operator", _S, PRE, "parties", description="CPO / foreign domain"),
    FieldSpec(0x0016, "beneficiary", _S, PRE, "parties"),
    FieldSpec(0x0017, "evse_id", _S, PRE, "parties", optional=True),
    FieldSpec(0x0020, "tariff_id", _S, PRE, "tariff"),
    FieldSpec(0x0021, "tariff_version", _S, PRE, "tariff"),
    FieldSpec(0x0022, "tariff_mode", _E, PRE, "tariff", enum_table="tariff_mode"),
    FieldSpec(0x0023, "unit_price", _F6, PRE, "tariff", unit="currency_per_kwh"),
    FieldSpec(0x0024, "currency", _S, PRE, "tariff"),
    FieldSpec(0x0030, "requested_kwh", _F6, PRE, "limits", unit="kwh"),
    FieldSpec(0x0031, "cap_kwh", _F6, PRE, "limits", unit="kwh"),
    FieldSpec(0x0032, "preauth_limit", _F6, PRE, "limits", unit="currency"),
    FieldSpec(0x0040, "tw_start", _TS, PRE, "window", unit="unix_s_utc"),
    FieldSpec(0x0041, "tw_end", _TS, PRE, "window", unit="unix_s_utc"),
    FieldSpec(0x0050, "paytok", _S, PRE, "payment"),
    FieldSpec(0x0051, "payment_semantics", _E, PRE, "payment", enum_table="payment_semantics"),
    FieldSpec(0x0060, "nonce_u", _S, PRE, "nonces"),
    FieldSpec(0x0061, "nonce_s", _S, PRE, "nonces"),
    # --- POST_SERVICE_EVIDENCE: delivery receipt (public + private) -------
    FieldSpec(0x0100, "sid", _S, POST, "receipt"),
    FieldSpec(0x0101, "rho_t", _D, POST, "receipt", description="commitment root referenced by the receipt"),
    FieldSpec(0x0102, "delivered_kwh", _F6, POST, "receipt", unit="kwh"),
    FieldSpec(0x0103, "ts_start", _TS, POST, "receipt", unit="unix_s_utc"),
    FieldSpec(0x0104, "ts_end", _TS, POST, "receipt", unit="unix_s_utc"),
    FieldSpec(0x0105, "applied_tariff_id", _S, POST, "receipt"),
    FieldSpec(0x0106, "applied_tariff_version", _S, POST, "receipt"),
    FieldSpec(0x0107, "nonce_m", _S, POST, "receipt"),
    FieldSpec(0x0108, "h_priv", _D, POST, "receipt", description="digest of canonical DR_private"),
    FieldSpec(0x0109, "meter_key_epoch", _U, POST, "receipt"),
    FieldSpec(0x010A, "receipt_version", _S, POST, "receipt"),
    FieldSpec(0x010B, "receipt_station_id", _S, POST, "receipt"),
    FieldSpec(0x010C, "receipt_meter_id", _S, POST, "receipt"),
    FieldSpec(0x010D, "receipt_tid", _S, POST, "receipt"),
    FieldSpec(0x0120, "connection_duration_s", _U, POST, "private"),
    FieldSpec(0x0121, "active_charging_duration_s", _U, POST, "private"),
    FieldSpec(0x0122, "parking_duration_s", _U, POST, "private"),
    FieldSpec(0x0123, "session_ref", _S, POST, "private", description="source dataset session reference"),
    FieldSpec(0x0124, "meter_values_digest", _D, POST, "private", optional=True),
    # --- SETTLEMENT_OUTPUT ------------------------------------------------
    FieldSpec(0x0200, "decision", _E, OUT, "decision", enum_table="decision"),
    FieldSpec(0x0201, "captured_amount", _F6, OUT, "decision", unit="currency"),
    FieldSpec(0x0202, "refund_amount", _F6, OUT, "decision", unit="currency"),
    FieldSpec(0x0203, "policy_id", _S, OUT, "decision"),
    FieldSpec(0x0204, "dr_digest", _D, OUT, "decision"),
    FieldSpec(0x0205, "auth_digest", _D, OUT, "decision"),
    FieldSpec(0x0206, "decision_digest", _D, OUT, "attestation"),
    FieldSpec(0x0207, "verifier_id", _S, OUT, "attestation"),
    FieldSpec(0x0208, "verifier_key_epoch", _U, OUT, "attestation"),
    FieldSpec(0x0209, "rbc_version", _S, OUT, "decision"),
    FieldSpec(0x020A, "verifier_set_epoch", _U, OUT, "decision"),
    FieldSpec(0x020B, "settle_tid", _S, OUT, "decision"),
    FieldSpec(0x020C, "settle_sid", _S, OUT, "decision"),
    FieldSpec(0x020D, "settle_rho_t", _D, OUT, "decision"),
    FieldSpec(0x020E, "settle_meter_id", _S, OUT, "decision"),
    FieldSpec(0x020F, "settle_h_priv", _D, OUT, "decision"),
    FieldSpec(0x0210, "settle_protocol_version", _S, OUT, "decision"),
    # --- dynamic authorization events (never committed) -------------------
    FieldSpec(0x0300, "old_limit", _F6, POST, "topup", unit="currency"),
    FieldSpec(0x0301, "delta_limit", _F6, POST, "topup", unit="currency"),
    FieldSpec(0x0302, "new_limit", _F6, POST, "topup", unit="currency"),
    FieldSpec(0x0303, "event_nonce", _S, POST, "topup"),
)

REGISTRY = FieldRegistry(FIELD_SPECS)

LAYOUT_SCHEMA_ID = "dvas-ev-layout-v1"
PROTOCOL_VERSION_VALUE = "DVAS-EV/2.0"


_INDEX_CACHE: dict["LayoutSchema", dict[str, int]] = {}
_DIGEST_CACHE: dict["LayoutSchema", bytes] = {}


@dataclass(frozen=True)
class LayoutSchema:
    """Ordered list of committed fields.  Leaf index = position in field_names."""

    schema_id: str
    field_names: tuple[str, ...]

    def __post_init__(self) -> None:
        ids = [REGISTRY.spec(n).field_id for n in self.field_names]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise ValueError("layout fields must be unique and ordered by field id")
        for n in self.field_names:
            if REGISTRY.spec(n).lifecycle != PRE:
                raise ValueError(f"layout field {n} is not PRE_SERVICE_COMMITTED")

    @property
    def field_ids(self) -> tuple[int, ...]:
        return tuple(REGISTRY.spec(n).field_id for n in self.field_names)

    def index_of(self, field: int | str) -> int:
        name = REGISTRY.spec(field).name
        idx = _INDEX_CACHE.get(self)
        if idx is None:
            idx = _INDEX_CACHE[self] = {n: i for i, n in enumerate(self.field_names)}
        try:
            return idx[name]
        except KeyError as exc:
            raise EncodingError(f"field {name} is not in layout {self.schema_id}") from exc

    def groups(self) -> dict[str, tuple[str, ...]]:
        out: dict[str, list[str]] = {}
        for n in self.field_names:
            out.setdefault(REGISTRY.spec(n).group, []).append(n)
        return {g: tuple(v) for g, v in out.items()}

    def digest(self) -> bytes:
        """Binds schema id, ordered field list and the field registry definition (cached)."""
        d = _DIGEST_CACHE.get(self)
        if d is None:
            d = _DIGEST_CACHE[self] = self._compute_digest()
        return d

    def _compute_digest(self) -> bytes:
        return tagged_hash(
            "DVAS-EV/layout-schema/v1",
            self.schema_id.encode("utf-8"),
            b"".join(fid.to_bytes(2, "big") for fid in self.field_ids),
            REGISTRY.digest(),
        )


LAYOUT_V1 = LayoutSchema(
    LAYOUT_SCHEMA_ID,
    tuple(s.name for s in sorted(FIELD_SPECS, key=lambda s: s.field_id) if s.lifecycle == PRE),
)


def check_layout_values(schema: LayoutSchema, values: Mapping[str, Any]) -> None:
    """Reject missing fields and any field that is not PRE_SERVICE_COMMITTED."""
    for name in values:
        spec = REGISTRY.spec(name)
        if spec.lifecycle != PRE:
            raise EncodingError(
                f"field {name} has lifecycle {spec.lifecycle.name}; post-service values cannot "
                "enter the pre-service commitment"
            )
        if name not in schema.field_names:
            raise EncodingError(f"field {name} is not part of layout {schema.schema_id}")
    missing = [n for n in schema.field_names if n not in values and not REGISTRY.spec(n).optional]
    if missing:
        raise EncodingError(f"layout missing required fields {missing}")


def encode_leaf(schema: LayoutSchema, name: str, value: Any) -> bytes:
    """Canonical leaf pre-image: schema digest | leaf index | encoded field."""
    idx = schema.index_of(name)
    return schema.digest() + idx.to_bytes(2, "big") + encode_field(REGISTRY.spec(name), value)


# ---------------------------------------------------------------------------
# Record types (all hashed/signed objects)
# ---------------------------------------------------------------------------

_POST_OR_PRE = frozenset({PRE, POST})

PUBLIC_RECEIPT = RecordType(
    0x0101,
    "public_delivery_receipt",
    (
        "receipt_version", "receipt_tid", "sid", "rho_t", "receipt_station_id", "receipt_meter_id",
        "delivered_kwh", "ts_start", "ts_end", "applied_tariff_id", "applied_tariff_version",
        "nonce_m", "h_priv", "meter_key_epoch",
    ),
    _POST_OR_PRE,
)

PRIVATE_RECEIPT = RecordType(
    0x0102,
    "private_delivery_payload",
    (
        "receipt_version", "receipt_tid", "sid", "rho_t", "receipt_meter_id", "delivered_kwh",
        "ts_start", "ts_end", "connection_duration_s", "active_charging_duration_s",
        "parking_duration_s", "session_ref", "meter_values_digest", "nonce_m",
    ),
    _POST_OR_PRE,
)

SETTLEMENT_DECISION = RecordType(
    0x0201,
    "settlement_decision",
    (
        "rbc_version", "settle_protocol_version", "settle_tid", "settle_sid", "settle_rho_t",
        "settle_meter_id", "dr_digest", "settle_h_priv", "auth_digest", "captured_amount",
        "refund_amount", "decision", "policy_id", "verifier_set_epoch",
    ),
    frozenset({OUT}),
)

ATTESTATION_MESSAGE = RecordType(
    0x0202,
    "verification_attestation",
    ("settle_protocol_version", "verifier_id", "verifier_key_epoch", "decision_digest"),
    frozenset({OUT}),
)

AUTH_REQUEST = RecordType(
    0x0301,
    "authorization_request",
    ("protocol_version", "tid", "rho_t", "user_id", "user_account", "preauth_limit", "paytok", "event_nonce"),
)

SESSION_OPEN = RecordType(
    0x0302,
    "session_open",
    ("protocol_version", "tid", "sid", "rho_t", "station_id", "meter_id", "nonce_s"),
)

TOPUP_EVENT = RecordType(
    0x0303,
    "topup_authorization",
    ("protocol_version", "tid", "rho_t", "sid", "user_account", "old_limit", "delta_limit", "new_limit", "event_nonce"),
)
