"""
Projection commitment and opening utilities for DBAS-ET.

This module implements a simulated commitment-opening backend:

    SemanticLayout M_t -> row hashes -> rho_t
    open phase-specific projection A_t / S_t / D_t
    verify projection proof against rho_t

Security note
-------------
ProjectionProof is a simulated algebraic/Merkle-style opening proof using
canonical serialization and row hashes. It is not a ZK proof, not a Verkle
proof, and not a KZG/PCS proof. Benchmark outputs must label it as simulated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from .capsule import SemanticLayout, SemanticRow
from .crypto import H_hex, canonical_dumps


ProjectionPhase = Literal["A", "S", "D"]


@dataclass(frozen=True)
class ProjectionView:
    """
    Phase-specific projection view.

    Contains only the rows opened for a given phase.
    """

    phase: ProjectionPhase
    trade_id: str
    rows: list[dict[str, Any]]

    def to_record(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "trade_id": self.trade_id,
            "rows": self.rows,
        }


@dataclass(frozen=True)
class ProjectionProof:
    """
    Simulated projection opening proof.

    row_hashes:
        Hashes for opened rows.
    layout_row_hashes:
        Hashes for all committed rows. This is larger than a true Merkle proof
        but makes the simulated opening fully auditable and deterministic.
    """

    proof_version: str
    backend_name: str
    security_claim: str
    phase: ProjectionPhase
    trade_id: str
    rho_t: str
    opened_row_ids: list[str]
    row_hashes: dict[str, str]
    layout_row_hashes: dict[str, str]

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CommittedCapsuleArtifact:
    """
    Committed semantic layout artifact.

    rho_t is the compact on-chain-style commitment root.
    """

    rho_t: str
    trade_id: str
    layout: SemanticLayout
    row_hashes: dict[str, str]
    backend_name: str
    security_claim: str

    def to_record(self) -> dict[str, Any]:
        return {
            "rho_t": self.rho_t,
            "trade_id": self.trade_id,
            "layout_version": self.layout.layout_version,
            "n_rows": len(self.layout.rows),
            "backend_name": self.backend_name,
            "security_claim": self.security_claim,
        }


@dataclass(frozen=True)
class ProjectionVerificationResult:
    """Detailed verification result for trace/debug output."""

    ok: bool
    reason: str
    phase: str
    trade_id: str
    rho_t: str
    opened_rows: int
    disclosed_fields: int

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def row_to_hash(row: SemanticRow | dict[str, Any]) -> str:
    """Hash one semantic row using canonical serialization."""
    if isinstance(row, SemanticRow):
        record = row.to_record()
    else:
        record = row

    return H_hex("H_SEMANTIC_ROW_V1", record)


def compute_layout_row_hashes(layout: SemanticLayout) -> dict[str, str]:
    """Compute row hash map for all rows in a layout."""
    return {
        row.row_id: row_to_hash(row)
        for row in layout.rows
    }


def compute_layout_root(row_hashes: dict[str, str]) -> str:
    """
    Compute compact layout root rho_t from all row hashes.

    This is a deterministic root over sorted row_id/hash pairs.
    """
    ordered = [
        {"row_id": row_id, "row_hash": row_hashes[row_id]}
        for row_id in sorted(row_hashes)
    ]
    return H_hex("H_LAYOUT_ROOT_V1", ordered)


def proof_bytesize(obj: Any) -> int:
    """
    Return canonical serialized size in bytes.

    This is an artifact-level measurement, not wire-compressed size.
    """
    return len(canonical_dumps(obj))


class V2SlimSettlementBackend:
    """
    Simulated V2 backend with slim settlement projection.

    The backend commits the full semantic layout but opens phase-specific rows.
    Settlement projection S is intentionally smaller than authorization A.
    """

    backend_name = "V2SlimSettlementBackend"
    security_claim = (
        "simulated commitment-opening proof with canonical serialization; "
        "not ZK, not Verkle/KZG/PCS"
    )

    def commit_layout(self, layout: SemanticLayout) -> CommittedCapsuleArtifact:
        """Commit semantic layout and return artifact containing rho_t."""
        row_hashes = compute_layout_row_hashes(layout)
        rho_t = compute_layout_root(row_hashes)

        return CommittedCapsuleArtifact(
            rho_t=rho_t,
            trade_id=layout.trade_id,
            layout=layout,
            row_hashes=row_hashes,
            backend_name=self.backend_name,
            security_claim=self.security_claim,
        )

    def open_projection(
        self,
        artifact: CommittedCapsuleArtifact,
        phase: ProjectionPhase,
    ) -> tuple[ProjectionView, ProjectionProof]:
        """Open a phase-specific projection view and proof."""
        if phase not in {"A", "S", "D"}:
            raise ValueError(f"unsupported projection phase: {phase}")

        selected_rows = artifact.layout.rows_for_phase(phase)
        opened_records = [row.to_record() for row in selected_rows]
        opened_row_ids = [row.row_id for row in selected_rows]

        row_hashes = {
            row_id: artifact.row_hashes[row_id]
            for row_id in opened_row_ids
        }

        view = ProjectionView(
            phase=phase,
            trade_id=artifact.trade_id,
            rows=opened_records,
        )

        proof = ProjectionProof(
            proof_version="projection-proof-v1",
            backend_name=self.backend_name,
            security_claim=self.security_claim,
            phase=phase,
            trade_id=artifact.trade_id,
            rho_t=artifact.rho_t,
            opened_row_ids=opened_row_ids,
            row_hashes=row_hashes,
            layout_row_hashes=dict(artifact.row_hashes),
        )

        return view, proof

    def verify_projection_detailed(
        self,
        rho_t: str,
        view: ProjectionView,
        proof: ProjectionProof,
    ) -> ProjectionVerificationResult:
        """Verify projection proof and return detailed result."""
        if proof.backend_name != self.backend_name:
            return _verification_result(
                False,
                "backend mismatch",
                rho_t,
                view,
                proof,
            )

        if proof.rho_t != rho_t:
            return _verification_result(
                False,
                "rho_t mismatch",
                rho_t,
                view,
                proof,
            )

        if proof.phase != view.phase:
            return _verification_result(
                False,
                "phase mismatch",
                rho_t,
                view,
                proof,
            )

        if proof.trade_id != view.trade_id:
            return _verification_result(
                False,
                "trade_id mismatch",
                rho_t,
                view,
                proof,
            )

        view_row_ids = [row.get("row_id") for row in view.rows]
        if view_row_ids != proof.opened_row_ids:
            return _verification_result(
                False,
                "opened row order/id mismatch",
                rho_t,
                view,
                proof,
            )

        for row in view.rows:
            row_id = row.get("row_id")
            if not isinstance(row_id, str):
                return _verification_result(
                    False,
                    "row without row_id",
                    rho_t,
                    view,
                    proof,
                )

            recomputed = row_to_hash(row)
            claimed = proof.row_hashes.get(row_id)
            committed = proof.layout_row_hashes.get(row_id)

            if claimed is None or committed is None:
                return _verification_result(
                    False,
                    f"missing row hash for {row_id}",
                    rho_t,
                    view,
                    proof,
                )

            if recomputed != claimed:
                return _verification_result(
                    False,
                    f"opened row hash mismatch for {row_id}",
                    rho_t,
                    view,
                    proof,
                )

            if claimed != committed:
                return _verification_result(
                    False,
                    f"opened row not consistent with committed layout for {row_id}",
                    rho_t,
                    view,
                    proof,
                )

        recomputed_root = compute_layout_root(proof.layout_row_hashes)
        if recomputed_root != rho_t:
            return _verification_result(
                False,
                "layout root mismatch",
                rho_t,
                view,
                proof,
            )

        return _verification_result(
            True,
            "ok",
            rho_t,
            view,
            proof,
        )

    def verify_projection(
        self,
        rho_t: str,
        view: ProjectionView,
        proof: ProjectionProof,
    ) -> bool:
        """Boolean projection verification wrapper."""
        return self.verify_projection_detailed(rho_t, view, proof).ok


def _verification_result(
    ok: bool,
    reason: str,
    rho_t: str,
    view: ProjectionView,
    proof: ProjectionProof,
) -> ProjectionVerificationResult:
    disclosed_fields = 0

    for row in view.rows:
        fields = row.get("fields", {})
        if isinstance(fields, dict):
            disclosed_fields += len(fields)

    return ProjectionVerificationResult(
        ok=ok,
        reason=reason,
        phase=str(view.phase),
        trade_id=view.trade_id,
        rho_t=rho_t,
        opened_rows=len(view.rows),
        disclosed_fields=disclosed_fields,
    )