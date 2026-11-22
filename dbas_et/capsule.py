"""
Capsule and semantic layout definitions for DBAS-ET.

A CanonicalCapsule C_t contains the transaction semantics committed before
service delivery. It is converted into a 2D semantic layout M_t. Later modules
commit M_t into rho_t and open phase-specific projections A_t, S_t, and D_t.

Payment terminology
-------------------
preauth_limit_t is the pre-authorized payment limit. It is not the final
captured payment. Settlement captures only the verified actual amount after a
valid delivery receipt is checked.

Security note
-------------
This module only builds canonical semantic objects. It does not implement ZK
proofs, vector commitments, or on-chain verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from .crypto import H_hex
from .entities import Meter, Station, User


PhaseName = Literal["A", "S", "D", "META"]


@dataclass(frozen=True)
class CanonicalCapsule:
    """
    Canonical transaction capsule C_t.

    The capsule binds authorization, delivery constraints, tariff metadata,
    and settlement-relevant identifiers before charging starts.
    """

    trade_id: str

    user_id: str
    user_address: str
    home_domain: str

    station_id: str
    meter_id: str
    foreign_domain: str
    beneficiary: str

    tariff_id: str
    tariff_version: str
    unit_price: float
    tariff_mode: str

    requested_kwh: float
    cap_kwh: float
    preauth_limit_t: float

    tw_start: int
    tw_end: int

    paytok_t: str
    nonce_u: str
    nonce_s: str
    created_at: int

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowcap_t(self) -> float:
        """
        Backward-compatible alias.

        Important:
            allowcap_t means pre-authorized payment limit, not captured amount.
        """
        return self.preauth_limit_t

    def to_public_record(self) -> dict[str, Any]:
        """Return canonical public record used for layout construction."""
        return asdict(self)


@dataclass(frozen=True)
class SemanticRow:
    """
    One row in the 2D semantic capsule layout M_t.

    phase:
        A    authorization/admission row
        S    settlement row
        D    dispute/audit row
        META non-phase metadata row
    """

    row_id: str
    phase: PhaseName
    description: str
    fields: dict[str, Any]

    def to_record(self) -> dict[str, Any]:
        """Return stable row record."""
        return {
            "row_id": self.row_id,
            "phase": self.phase,
            "description": self.description,
            "fields": self.fields,
        }


@dataclass(frozen=True)
class SemanticLayout:
    """2D semantic layout M_t built from a CanonicalCapsule."""

    layout_version: str
    trade_id: str
    rows: list[SemanticRow]

    def rows_for_phase(self, phase: str) -> list[SemanticRow]:
        """
        Return rows required for a projection phase.

        A projection may include META rows when needed for domain separation.
        """
        if phase not in {"A", "S", "D"}:
            raise ValueError(f"unsupported projection phase: {phase}")

        selected = [
            row
            for row in self.rows
            if row.phase == phase or row.phase == "META"
        ]
        return selected

    def to_record(self) -> dict[str, Any]:
        """Return stable layout record."""
        return {
            "layout_version": self.layout_version,
            "trade_id": self.trade_id,
            "rows": [row.to_record() for row in self.rows],
        }


def build_trade_id(
    user_id: str,
    station_id: str,
    meter_id: str,
    nonce_u: str,
    nonce_s: str,
) -> str:
    """Build deterministic trade identifier from core parties and nonces."""
    return H_hex(
        "H_TRADE_ID",
        {
            "user_id": user_id,
            "station_id": station_id,
            "meter_id": meter_id,
            "nonce_u": nonce_u,
            "nonce_s": nonce_s,
        },
    )[:40]


def build_payment_token(trade_id: str, user_address: str, station_id: str) -> str:
    """
    Build a simulation payment token identifier.

    This is not a real payment provider token. It is a protocol artifact used
    to bind reserve-release settlement to the committed capsule.
    """
    return H_hex(
        "H_PAYTOK",
        {
            "trade_id": trade_id,
            "user_address": user_address,
            "station_id": station_id,
        },
    )[:40]


def build_demo_capsule(
    user: User,
    station: Station,
    meter: Meter,
    requested_kwh: float = 10.0,
    delivered_cap_kwh: float = 10.0,
    preauth_limit_t: float = 15.0,
    unit_price: float = 0.50,
    tariff_id: str = "DEMO_TARIFF",
    tariff_version: str = "v1",
    tariff_mode: str = "ENERGY_ONLY",
    tw_start: int = 1_700_000_000,
    tw_end: int = 1_700_007_200,
    nonce_u: str = "nonce-user-demo",
    nonce_s: str = "nonce-station-demo",
    created_at: int = 1_700_000_000,
) -> CanonicalCapsule:
    """
    Build a deterministic demo capsule for smoke tests.

    The key material may be random, but the capsule fields themselves are
    deterministic for the same entities.
    """
    if meter.station_id != station.station_id:
        raise ValueError("meter must be bound to station")

    trade_id = build_trade_id(
        user_id=user.user_id,
        station_id=station.station_id,
        meter_id=meter.meter_id,
        nonce_u=nonce_u,
        nonce_s=nonce_s,
    )

    paytok_t = build_payment_token(
        trade_id=trade_id,
        user_address=user.address,
        station_id=station.station_id,
    )

    return CanonicalCapsule(
        trade_id=trade_id,
        user_id=user.user_id,
        user_address=user.address,
        home_domain=user.home_domain,
        station_id=station.station_id,
        meter_id=meter.meter_id,
        foreign_domain=station.foreign_domain,
        beneficiary=station.beneficiary,
        tariff_id=tariff_id,
        tariff_version=tariff_version,
        unit_price=float(unit_price),
        tariff_mode=tariff_mode,
        requested_kwh=float(requested_kwh),
        cap_kwh=float(delivered_cap_kwh),
        preauth_limit_t=float(preauth_limit_t),
        tw_start=int(tw_start),
        tw_end=int(tw_end),
        paytok_t=paytok_t,
        nonce_u=nonce_u,
        nonce_s=nonce_s,
        created_at=int(created_at),
        metadata={
            "source": "smoke_test_demo",
            "payment_semantics": "preauthorized_limit_not_captured_payment",
        },
    )


def capsule_to_semantic_layout(capsule: CanonicalCapsule) -> SemanticLayout:
    """
    Convert CanonicalCapsule C_t into a 2D semantic layout M_t.

    Layout design
    -------------
    A-plane rows expose fields required for authorization/admission.
    S-plane rows expose fields required for settlement after delivery.
    D-plane rows expose fields for reason-aware dispute opening.

    Written out by hand because it defines the semantic capsule layout.
    """
    rows = [
        SemanticRow(
            row_id="meta.trade",
            phase="META",
            description="Common transaction identity and layout metadata",
            fields={
                "trade_id": capsule.trade_id,
                "layout_version": "dbas-et-semantic-layout-v1",
                "created_at": capsule.created_at,
            },
        ),
        SemanticRow(
            row_id="A.user_station_binding",
            phase="A",
            description="Authorization identity binding",
            fields={
                "trade_id": capsule.trade_id,
                "user_id": capsule.user_id,
                "user_address": capsule.user_address,
                "home_domain": capsule.home_domain,
                "station_id": capsule.station_id,
                "foreign_domain": capsule.foreign_domain,
            },
        ),
        SemanticRow(
            row_id="A.authorization_terms",
            phase="A",
            description="Pre-authorization cap and energy/time admission terms",
            fields={
                "trade_id": capsule.trade_id,
                "meter_id": capsule.meter_id,
                "requested_kwh": capsule.requested_kwh,
                "cap_kwh": capsule.cap_kwh,
                "preauth_limit_t": capsule.preauth_limit_t,
                "tariff_id": capsule.tariff_id,
                "tariff_version": capsule.tariff_version,
                "tw_start": capsule.tw_start,
                "tw_end": capsule.tw_end,
            },
        ),
        SemanticRow(
            row_id="A.payment_token",
            phase="A",
            description="Payment reserve token binding",
            fields={
                "trade_id": capsule.trade_id,
                "paytok_t": capsule.paytok_t,
                "beneficiary": capsule.beneficiary,
                "payment_semantics": "reserve_release",
            },
        ),
        SemanticRow(
            row_id="S.settlement_binding",
            phase="S",
            description="Minimal settlement identifiers and meter binding",
            fields={
                "trade_id": capsule.trade_id,
                "station_id": capsule.station_id,
                "meter_id": capsule.meter_id,
                "beneficiary": capsule.beneficiary,
            },
        ),
        SemanticRow(
            row_id="S.settlement_terms",
            phase="S",
            description="Settlement cap, tariff and time constraints",
            fields={
                "trade_id": capsule.trade_id,
                "cap_kwh": capsule.cap_kwh,
                "preauth_limit_t": capsule.preauth_limit_t,
                "tariff_id": capsule.tariff_id,
                "tariff_version": capsule.tariff_version,
                "unit_price": capsule.unit_price,
                "tariff_mode": capsule.tariff_mode,
                "tw_start": capsule.tw_start,
                "tw_end": capsule.tw_end,
            },
        ),
        SemanticRow(
            row_id="D.dispute_context",
            phase="D",
            description="Reason-aware dispute context",
            fields={
                "trade_id": capsule.trade_id,
                "user_id": capsule.user_id,
                "station_id": capsule.station_id,
                "meter_id": capsule.meter_id,
                "tariff_id": capsule.tariff_id,
                "tariff_version": capsule.tariff_version,
                "preauth_limit_t": capsule.preauth_limit_t,
                "cap_kwh": capsule.cap_kwh,
                "tw_start": capsule.tw_start,
                "tw_end": capsule.tw_end,
            },
        ),
    ]

    return SemanticLayout(
        layout_version="dbas-et-semantic-layout-v1",
        trade_id=capsule.trade_id,
        rows=rows,
    )