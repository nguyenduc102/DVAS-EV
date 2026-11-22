"""
Projection compiler of the earlier DBAS-ET prototype (``mspc``).

It guarantees sufficiency only: the selected units cover the declared predicate
dependencies.  The DVAS-EV selector is in ``dbas_et.dvas.predicates``.

MSP-C compiles semantic capsule layouts into phase-specific projection plans.

Input
-----
SemanticLayout M_t
phase p in {A, S, D}
optional dispute reason r
candidate opening units
cost weights

Output
------
ProjectionPlan containing:
- opened rows
- disclosed semantic fields
- estimated proof bytes
- estimated verify cost
- sufficiency certificate

Security and scope note
-----------------------
This module is a compiler-level artifact. It does not implement a real PCS,
KZG, Verkle proof, lattice VC, or ZK proof. Proof-size and verification-cost
values are deterministic estimates used to compare projection layouts in the
protocol simulator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from .capsule import SemanticLayout


ProjectionPhase = Literal["A", "S", "D"]
CandidateMode = Literal["row", "field", "hybrid"]
ObjectiveName = Literal["proof_size", "disclosure", "verify_latency", "balanced"]


@dataclass(frozen=True)
class MSPCWeights:
    """Cost weights for MSP-C candidate selection."""

    proof_bytes: float = 1.0
    disclosed_fields: float = 10.0
    verify_ms: float = 100.0
    opened_rows: float = 20.0

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PredicateSpec:
    """Predicate dependency specification for one phase/reason."""

    phase: ProjectionPhase
    reason: str
    required_fields: set[str]
    description: str

    def to_record(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "reason": self.reason,
            "required_fields": sorted(self.required_fields),
            "description": self.description,
        }


@dataclass(frozen=True)
class CandidateUnit:
    """
    Candidate opening unit.

    semantic_fields use the format:
        row_id.field_name
    """

    unit_id: str
    mode: str
    row_ids: tuple[str, ...]
    semantic_fields: frozenset[str]
    proof_bytes_est: int
    verify_ms_est: float
    backend_compatible: bool

    def score(self, weights: MSPCWeights) -> float:
        return (
            weights.proof_bytes * float(self.proof_bytes_est)
            + weights.disclosed_fields * float(len(self.semantic_fields))
            + weights.verify_ms * float(self.verify_ms_est)
            + weights.opened_rows * float(len(set(self.row_ids)))
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "mode": self.mode,
            "row_ids": ",".join(self.row_ids),
            "semantic_fields": ",".join(sorted(self.semantic_fields)),
            "proof_bytes_est": self.proof_bytes_est,
            "verify_ms_est": round(float(self.verify_ms_est), 6),
            "backend_compatible": self.backend_compatible,
        }


@dataclass(frozen=True)
class ProjectionCertificate:
    """MSP-C sufficiency certificate."""

    cert_version: str
    phase: ProjectionPhase
    reason: str
    required_fields: tuple[str, ...]
    disclosed_fields: tuple[str, ...]
    missing_fields: tuple[str, ...]
    sufficient: bool
    minimality_claim: str
    security_claim: str

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProjectionPlan:
    """Compiled MSP-C projection plan."""

    plan_version: str
    phase: ProjectionPhase
    reason: str
    objective: ObjectiveName
    candidate_mode: CandidateMode
    selected_units: tuple[CandidateUnit, ...]
    opened_row_ids: tuple[str, ...]
    disclosed_fields: tuple[str, ...]
    proof_bytes_est: int
    verify_ms_est: float
    score: float
    certificate: ProjectionCertificate
    backend_compatible: bool
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_record(self) -> dict[str, Any]:
        return {
            "plan_version": self.plan_version,
            "phase": self.phase,
            "reason": self.reason,
            "objective": self.objective,
            "candidate_mode": self.candidate_mode,
            "selected_units": ",".join(unit.unit_id for unit in self.selected_units),
            "opened_row_ids": ",".join(self.opened_row_ids),
            "disclosed_fields": ",".join(self.disclosed_fields),
            "opened_rows": len(self.opened_row_ids),
            "disclosed_field_count": len(self.disclosed_fields),
            "proof_bytes_est": self.proof_bytes_est,
            "verify_ms_est": round(float(self.verify_ms_est), 6),
            "score": round(float(self.score), 6),
            "sufficient": self.certificate.sufficient,
            "missing_fields": ",".join(self.certificate.missing_fields),
            "backend_compatible": self.backend_compatible,
            "minimality_claim": self.certificate.minimality_claim,
            "security_claim": self.certificate.security_claim,
            "notes": " | ".join(self.notes),
        }


def semantic_field_id(row_id: str, field_name: str) -> str:
    """Return canonical semantic field identifier."""
    return f"{row_id}.{field_name}"


def layout_field_map(layout: SemanticLayout) -> dict[str, Any]:
    """Return map of semantic_field_id -> value."""
    out: dict[str, Any] = {}

    for row in layout.rows:
        for field_name, value in row.fields.items():
            out[semantic_field_id(row.row_id, field_name)] = value

    return out


def layout_rows_by_id(layout: SemanticLayout) -> dict[str, Any]:
    """Return row_id -> SemanticRow map."""
    return {row.row_id: row for row in layout.rows}


def default_predicate_spec(
    layout: SemanticLayout,
    phase: ProjectionPhase,
    reason: str = "",
) -> PredicateSpec:
    """
    Return default DBAS-ET predicate dependency specification.

    The dependency map is intentionally explicit because it is part of the
    semantic projection design.
    """
    rows = layout_rows_by_id(layout)

    if phase == "A":
        row_ids = [
            "meta.trade",
            "A.user_station_binding",
            "A.authorization_terms",
            "A.payment_token",
        ]
        return PredicateSpec(
            phase="A",
            reason="authorize",
            required_fields=_fields_from_rows(rows, row_ids),
            description="Admission requires user/station/domain identity, authorization terms, and payment reserve token.",
        )

    if phase == "S":
        row_ids = [
            "meta.trade",
            "S.settlement_binding",
            "S.settlement_terms",
        ]
        return PredicateSpec(
            phase="S",
            reason="settle",
            required_fields=_fields_from_rows(rows, row_ids),
            description="Settlement requires meter/station/payment binding and tariff/cap/time constraints.",
        )

    if phase == "D":
        return _dispute_predicate_spec(rows, reason)

    raise ValueError(f"unsupported MSP-C phase: {phase}")


def _fields_from_rows(rows: dict[str, Any], row_ids: list[str]) -> set[str]:
    """Collect all semantic fields from selected rows."""
    out: set[str] = set()

    for row_id in row_ids:
        row = rows.get(row_id)
        if row is None:
            continue

        for field_name in row.fields:
            out.add(semantic_field_id(row_id, field_name))

    return out


def _dispute_predicate_spec(rows: dict[str, Any], reason: str) -> PredicateSpec:
    """Build reason-aware dispute dependency spec."""
    row_id = "D.dispute_context"
    row = rows.get(row_id)

    if row is None:
        return PredicateSpec(
            phase="D",
            reason=reason or "generic_dispute",
            required_fields=set(),
            description="Missing dispute row.",
        )

    base = {
        semantic_field_id(row_id, "trade_id"),
        semantic_field_id(row_id, "station_id"),
        semantic_field_id(row_id, "meter_id"),
    }

    if reason in {"tariff_mismatch", "bad_tariff"}:
        needed = base | {
            semantic_field_id(row_id, "tariff_id"),
            semantic_field_id(row_id, "tariff_version"),
        }
        desc = "Dispute opening for tariff mismatch."

    elif reason in {"time_window_mismatch", "bad_time_window"}:
        needed = base | {
            semantic_field_id(row_id, "tw_start"),
            semantic_field_id(row_id, "tw_end"),
        }
        desc = "Dispute opening for time-window mismatch."

    elif reason in {"over_cap", "energy_cap_exceeded"}:
        needed = base | {
            semantic_field_id(row_id, "cap_kwh"),
        }
        desc = "Dispute opening for delivered energy exceeding committed cap."

    elif reason in {"amount_exceeds_preauth_limit", "payment_cap"}:
        needed = base | {
            semantic_field_id(row_id, "preauth_limit_t"),
            semantic_field_id(row_id, "tariff_id"),
            semantic_field_id(row_id, "tariff_version"),
        }
        desc = "Dispute opening for settlement amount exceeding pre-authorized limit."

    elif reason in {"replay", "replay_detected"}:
        needed = base
        desc = "Dispute opening for replayed receipt/session evidence."

    else:
        needed = _fields_from_rows(rows, [row_id])
        desc = "Generic dispute opening."

    return PredicateSpec(
        phase="D",
        reason=reason or "generic_dispute",
        required_fields=needed,
        description=desc,
    )


def build_candidate_units(
    layout: SemanticLayout,
    phase: ProjectionPhase,
    mode: CandidateMode = "hybrid",
) -> list[CandidateUnit]:
    """
    Build candidate opening units for one phase.

    row mode:
        one unit opens all fields in a semantic row.
        compatible with current row-hash projection backend.

    field mode:
        one unit opens one semantic field.
        compiler estimate only; not directly verified by current row-hash backend.

    hybrid mode:
        includes both row and field units.
    """
    if mode not in {"row", "field", "hybrid"}:
        raise ValueError(f"unsupported candidate mode: {mode}")

    selected_rows = layout.rows_for_phase(phase)

    units: list[CandidateUnit] = []

    if mode in {"row", "hybrid"}:
        for row in selected_rows:
            fields = frozenset(
                semantic_field_id(row.row_id, field_name)
                for field_name in row.fields
            )
            units.append(
                CandidateUnit(
                    unit_id=f"row::{row.row_id}",
                    mode="row",
                    row_ids=(row.row_id,),
                    semantic_fields=fields,
                    proof_bytes_est=estimate_row_proof_bytes(len(fields)),
                    verify_ms_est=estimate_row_verify_ms(len(fields)),
                    backend_compatible=True,
                )
            )

    if mode in {"field", "hybrid"}:
        for row in selected_rows:
            for field_name in row.fields:
                field_id = semantic_field_id(row.row_id, field_name)
                units.append(
                    CandidateUnit(
                        unit_id=f"field::{field_id}",
                        mode="field",
                        row_ids=(row.row_id,),
                        semantic_fields=frozenset({field_id}),
                        proof_bytes_est=estimate_field_proof_bytes(),
                        verify_ms_est=estimate_field_verify_ms(),
                        backend_compatible=False,
                    )
                )

    return units


def estimate_row_proof_bytes(field_count: int) -> int:
    """Deterministic proof-size estimate for row opening."""
    return int(160 + 48 * int(field_count))


def estimate_field_proof_bytes() -> int:
    """Deterministic proof-size estimate for field opening."""
    return 180


def estimate_row_verify_ms(field_count: int) -> float:
    """Deterministic verification-cost estimate for row opening."""
    return round(0.035 + 0.004 * int(field_count), 6)


def estimate_field_verify_ms() -> float:
    """Deterministic verification-cost estimate for field opening."""
    return 0.025


def weights_for_objective(objective: ObjectiveName) -> MSPCWeights:
    """Return default weights for common objectives."""
    if objective == "proof_size":
        return MSPCWeights(
            proof_bytes=1.0,
            disclosed_fields=1.0,
            verify_ms=10.0,
            opened_rows=5.0,
        )

    if objective == "disclosure":
        return MSPCWeights(
            proof_bytes=0.2,
            disclosed_fields=100.0,
            verify_ms=5.0,
            opened_rows=10.0,
        )

    if objective == "verify_latency":
        return MSPCWeights(
            proof_bytes=0.2,
            disclosed_fields=2.0,
            verify_ms=1000.0,
            opened_rows=20.0,
        )

    if objective == "balanced":
        return MSPCWeights()

    raise ValueError(f"unsupported objective: {objective}")


def compile_projection(
    layout: SemanticLayout,
    phase: ProjectionPhase,
    reason: str = "",
    candidate_mode: CandidateMode = "row",
    objective: ObjectiveName = "balanced",
    weights: MSPCWeights | None = None,
) -> ProjectionPlan:
    """
    Compile a predicate-sufficient projection plan (greedy weighted cover).

    The current implementation uses greedy weighted set cover. The certificate
    states sufficiency only; no minimality or optimality is claimed.
    """
    pred = default_predicate_spec(layout, phase, reason)
    candidate_units = build_candidate_units(layout, phase, candidate_mode)

    weights = weights or weights_for_objective(objective)

    required = set(pred.required_fields)
    covered: set[str] = set()
    selected: list[CandidateUnit] = []
    remaining = list(candidate_units)

    while not required.issubset(covered):
        uncovered = required - covered

        best_unit: CandidateUnit | None = None
        best_ratio = float("inf")

        for unit in remaining:
            gain = len(unit.semantic_fields & uncovered)
            if gain <= 0:
                continue

            ratio = unit.score(weights) / float(gain)

            if ratio < best_ratio:
                best_ratio = ratio
                best_unit = unit
            elif ratio == best_ratio and best_unit is not None:
                if unit.unit_id < best_unit.unit_id:
                    best_unit = unit

        if best_unit is None:
            break

        selected.append(best_unit)
        covered |= set(best_unit.semantic_fields)
        remaining = [u for u in remaining if u.unit_id != best_unit.unit_id]

    disclosed = sorted(covered)
    missing = sorted(required - covered)
    opened_rows = tuple(sorted({rid for unit in selected for rid in unit.row_ids}))

    proof_bytes = sum(unit.proof_bytes_est for unit in selected)
    verify_ms = sum(unit.verify_ms_est for unit in selected)
    score = sum(unit.score(weights) for unit in selected)
    backend_compatible = all(unit.backend_compatible for unit in selected)

    certificate = ProjectionCertificate(
        cert_version="mspc-cert-v1",
        phase=phase,
        reason=pred.reason,
        required_fields=tuple(sorted(required)),
        disclosed_fields=tuple(disclosed),
        missing_fields=tuple(missing),
        sufficient=len(missing) == 0,
        minimality_claim="greedy_cover_sufficiency_only_no_minimality_claim",
        security_claim="compiler certificate only; not ZK/PCS proof",
    )

    notes = [
        pred.description,
        "row mode is compatible with current row-hash projection backend"
        if candidate_mode == "row"
        else "field/hybrid modes are compiler estimates unless paired with a compatible backend",
    ]

    return ProjectionPlan(
        plan_version="mspc-plan-v1",
        phase=phase,
        reason=pred.reason,
        objective=objective,
        candidate_mode=candidate_mode,
        selected_units=tuple(selected),
        opened_row_ids=opened_rows,
        disclosed_fields=tuple(disclosed),
        proof_bytes_est=proof_bytes,
        verify_ms_est=round(float(verify_ms), 6),
        score=round(float(score), 6),
        certificate=certificate,
        backend_compatible=backend_compatible,
        notes=tuple(notes),
    )


def compile_standard_plans(layout: SemanticLayout) -> list[ProjectionPlan]:
    """Compile standard A/S/D MSP-C plans used by the artifact smoke test."""
    plans = [
        compile_projection(layout, "A", candidate_mode="row", objective="balanced"),
        compile_projection(layout, "S", candidate_mode="row", objective="balanced"),
        compile_projection(layout, "D", reason="tariff_mismatch", candidate_mode="field", objective="disclosure"),
        compile_projection(layout, "D", reason="time_window_mismatch", candidate_mode="field", objective="disclosure"),
        compile_projection(layout, "D", reason="over_cap", candidate_mode="field", objective="disclosure"),
        compile_projection(layout, "D", reason="amount_exceeds_preauth_limit", candidate_mode="field", objective="disclosure"),
        compile_projection(layout, "D", reason="replay", candidate_mode="field", objective="disclosure"),
    ]
    return plans


def compare_plans(plan_a: ProjectionPlan, plan_b: ProjectionPlan) -> dict[str, Any]:
    """Compare two projection plans."""
    return {
        "left_phase": plan_a.phase,
        "left_reason": plan_a.reason,
        "left_mode": plan_a.candidate_mode,
        "left_disclosed_fields": len(plan_a.disclosed_fields),
        "left_opened_rows": len(plan_a.opened_row_ids),
        "left_proof_bytes_est": plan_a.proof_bytes_est,
        "right_phase": plan_b.phase,
        "right_reason": plan_b.reason,
        "right_mode": plan_b.candidate_mode,
        "right_disclosed_fields": len(plan_b.disclosed_fields),
        "right_opened_rows": len(plan_b.opened_row_ids),
        "right_proof_bytes_est": plan_b.proof_bytes_est,
        "field_reduction": len(plan_a.disclosed_fields) - len(plan_b.disclosed_fields),
        "proof_byte_delta": plan_a.proof_bytes_est - plan_b.proof_bytes_est,
    }