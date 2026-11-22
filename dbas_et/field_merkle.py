"""
Field-sensitive Merkle opening backend for DBAS-ET.

Field-level Merkle openings over the SemanticLayout M_t, phase aware and
compatible with MSP-C.  Not ZK, not a vector/polynomial commitment, not hiding.

The root is built in two layers:
    field values -> field leaf hashes -> row roots -> layout root rho_t

An opening proof discloses only selected field values in the ProjectionView.
For every opened row, the proof carries only the hashes of unopened fields in
that row. For rows that are not opened at all, the proof carries only the row
root as a sibling. The verifier recomputes row roots and then rho_t.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .capsule import SemanticLayout
from .crypto import H_hex
from .mspc import ProjectionPlan, compile_projection, semantic_field_id
from .projections import (
    ProjectionPhase,
    ProjectionVerificationResult,
    ProjectionView,
)


@dataclass(frozen=True)
class FieldMerkleCommittedCapsuleArtifact:
    """Committed field-level semantic layout artifact."""

    rho_t: str
    trade_id: str
    layout: SemanticLayout
    row_roots: dict[str, str]
    field_leaf_hashes: dict[str, dict[str, str]]
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
class FieldMerkleProjectionProof:
    """Concrete field-level Merkle-style multiproof.

    opened_fields uses semantic field IDs: ``row_id.field_name``.

    unopened_field_hashes_by_row carries hashes of hidden fields in rows that
    are partially opened. This lets the verifier recompute each opened row root
    without receiving the hidden values.

    sibling_row_roots carries row roots for rows not opened at all. This lets
    the verifier recompute the layout root rho_t.
    """

    proof_version: str
    backend_name: str
    security_claim: str
    phase: ProjectionPhase
    trade_id: str
    rho_t: str
    opened_fields_digest: str
    opened_row_ids: list[str]
    unopened_field_hashes_by_row: dict[str, dict[str, str]]
    sibling_row_roots: dict[str, str]

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


class V2FieldMerkleSettlementBackend:
    """Field-sensitive Merkle backend for DBAS-ET projections.

    This backend is intended as a stronger prototype than the row-level
    simulated projection backend. It still uses hashes only. It is not a
    vector commitment, not a polynomial commitment, and not a zero-knowledge
    proof. Its purpose is to make proof size and disclosure depend on the
    selected fields rather than only on selected rows.
    """

    backend_name = "V2FieldMerkleSettlementBackend"
    security_claim = (
        "concrete field-level Merkle-style opening over semantic fields; "
        "not ZK, not VC/Verkle/KZG/PCS, not hiding"
    )

    def commit_layout(self, layout: SemanticLayout) -> FieldMerkleCommittedCapsuleArtifact:
        field_leaf_hashes = compute_layout_field_leaf_hashes(layout)
        row_roots = {
            row_id: compute_field_merkle_row_root(row_id, leaves)
            for row_id, leaves in field_leaf_hashes.items()
        }
        rho_t = compute_field_merkle_layout_root(row_roots)

        return FieldMerkleCommittedCapsuleArtifact(
            rho_t=rho_t,
            trade_id=layout.trade_id,
            layout=layout,
            row_roots=row_roots,
            field_leaf_hashes=field_leaf_hashes,
            backend_name=self.backend_name,
            security_claim=self.security_claim,
        )

    def open_projection(
        self,
        artifact: FieldMerkleCommittedCapsuleArtifact,
        phase: ProjectionPhase,
        plan: ProjectionPlan | None = None,
        reason: str = "",
        objective: str = "proof_size",
    ) -> tuple[ProjectionView, FieldMerkleProjectionProof, ProjectionPlan]:
        """Open a field-sensitive phase projection.

        If no MSP-C plan is supplied, the backend compiles a field-mode plan
        for the requested phase. For A/S this opens the fields required by the
        phase predicate. For D this can be reason-aware.
        """
        if phase not in {"A", "S", "D"}:
            raise ValueError(f"unsupported projection phase: {phase}")

        if plan is None:
            plan = compile_projection(
                artifact.layout,
                phase=phase,
                reason=reason,
                candidate_mode="field",
                objective=objective,  # type: ignore[arg-type]
            )

        opened_fields = sorted(plan.disclosed_fields)
        opened_by_row = _group_semantic_fields_by_row(opened_fields)
        rows_by_id = {row.row_id: row for row in artifact.layout.rows}

        view_rows: list[dict[str, Any]] = []
        for row_id in sorted(opened_by_row):
            row = rows_by_id[row_id]
            selected_names = opened_by_row[row_id]
            selected_fields = {
                name: row.fields[name]
                for name in selected_names
                if name in row.fields
            }
            view_rows.append(
                {
                    "row_id": row_id,
                    "fields": selected_fields,
                }
            )

        opened_row_ids = [row["row_id"] for row in view_rows]

        unopened_field_hashes_by_row: dict[str, dict[str, str]] = {}
        for row_id in opened_row_ids:
            opened_names = set(opened_by_row[row_id])
            row_leaf_hashes = artifact.field_leaf_hashes[row_id]
            hidden = {
                field_name: leaf_hash
                for field_name, leaf_hash in row_leaf_hashes.items()
                if field_name not in opened_names
            }
            if hidden:
                unopened_field_hashes_by_row[row_id] = hidden

        sibling_row_roots = {
            row_id: row_root
            for row_id, row_root in artifact.row_roots.items()
            if row_id not in set(opened_row_ids)
        }

        view = ProjectionView(
            phase=phase,
            trade_id=artifact.trade_id,
            rows=view_rows,
        )
        proof = FieldMerkleProjectionProof(
            proof_version="field-merkle-proof-v1",
            backend_name=self.backend_name,
            security_claim=self.security_claim,
            phase=phase,
            trade_id=artifact.trade_id,
            rho_t=artifact.rho_t,
            opened_fields_digest=H_hex("H_FIELD_MERKLE_OPENED_FIELDS_V1", opened_fields),
            opened_row_ids=opened_row_ids,
            unopened_field_hashes_by_row=unopened_field_hashes_by_row,
            sibling_row_roots=sibling_row_roots,
        )
        return view, proof, plan

    def verify_projection_detailed(
        self,
        rho_t: str,
        view: ProjectionView,
        proof: FieldMerkleProjectionProof,
    ) -> ProjectionVerificationResult:
        """Verify a field-sensitive projection opening."""
        if proof.backend_name != self.backend_name:
            return _field_verification_result(False, "backend mismatch", rho_t, view, proof)

        if proof.rho_t != rho_t:
            return _field_verification_result(False, "rho_t mismatch", rho_t, view, proof)

        if proof.phase != view.phase:
            return _field_verification_result(False, "phase mismatch", rho_t, view, proof)

        if proof.trade_id != view.trade_id:
            return _field_verification_result(False, "trade_id mismatch", rho_t, view, proof)

        view_opened_fields = sorted(_semantic_fields_from_view(view))
        view_opened_digest = H_hex("H_FIELD_MERKLE_OPENED_FIELDS_V1", view_opened_fields)
        if view_opened_digest != proof.opened_fields_digest:
            return _field_verification_result(
                False,
                "opened field digest mismatch",
                rho_t,
                view,
                proof,
            )

        view_row_ids = [str(row.get("row_id", "")) for row in view.rows]
        if view_row_ids != proof.opened_row_ids:
            return _field_verification_result(
                False,
                "opened row order/id mismatch",
                rho_t,
                view,
                proof,
            )

        reconstructed_row_roots: dict[str, str] = {}

        for row in view.rows:
            row_id = str(row.get("row_id", ""))
            fields = row.get("fields", {})
            if not row_id or not isinstance(fields, Mapping):
                return _field_verification_result(False, "malformed opened row", rho_t, view, proof)

            leaf_hashes: dict[str, str] = {}
            for field_name, field_value in fields.items():
                leaf_hashes[str(field_name)] = field_leaf_hash(row_id, str(field_name), field_value)

            hidden_hashes = proof.unopened_field_hashes_by_row.get(row_id, {})
            for field_name, leaf_hash in hidden_hashes.items():
                if field_name in leaf_hashes:
                    return _field_verification_result(
                        False,
                        f"duplicate opened/hidden field {row_id}.{field_name}",
                        rho_t,
                        view,
                        proof,
                    )
                leaf_hashes[field_name] = leaf_hash

            reconstructed_row_roots[row_id] = compute_field_merkle_row_root(row_id, leaf_hashes)

        full_row_roots = dict(proof.sibling_row_roots)
        for row_id, row_root in reconstructed_row_roots.items():
            if row_id in full_row_roots:
                return _field_verification_result(
                    False,
                    f"duplicate opened/sibling row {row_id}",
                    rho_t,
                    view,
                    proof,
                )
            full_row_roots[row_id] = row_root

        recomputed_root = compute_field_merkle_layout_root(full_row_roots)
        if recomputed_root != rho_t:
            return _field_verification_result(False, "layout root mismatch", rho_t, view, proof)

        return _field_verification_result(True, "ok", rho_t, view, proof)

    def verify_projection(
        self,
        rho_t: str,
        view: ProjectionView,
        proof: FieldMerkleProjectionProof,
    ) -> bool:
        return self.verify_projection_detailed(rho_t, view, proof).ok


def field_leaf_hash(row_id: str, field_name: str, value: Any) -> str:
    """Hash one semantic field leaf."""
    return H_hex(
        "H_FIELD_MERKLE_LEAF_V1",
        {
            "row_id": row_id,
            "field_name": field_name,
            "field_value": value,
        },
    )


def compute_layout_field_leaf_hashes(layout: SemanticLayout) -> dict[str, dict[str, str]]:
    """Return row_id -> field_name -> leaf hash."""
    out: dict[str, dict[str, str]] = {}
    for row in layout.rows:
        out[row.row_id] = {
            field_name: field_leaf_hash(row.row_id, field_name, value)
            for field_name, value in row.fields.items()
        }
    return out


def compute_field_merkle_row_root(row_id: str, leaf_hashes: Mapping[str, str]) -> str:
    """Compute deterministic row root over sorted field leaf hashes."""
    ordered = [
        {"field_name": name, "leaf_hash": leaf_hashes[name]}
        for name in sorted(leaf_hashes)
    ]
    return H_hex("H_FIELD_MERKLE_ROW_ROOT_V1", {"row_id": row_id, "fields": ordered})


def compute_field_merkle_layout_root(row_roots: Mapping[str, str]) -> str:
    """Compute deterministic layout root over sorted row roots."""
    ordered = [
        {"row_id": row_id, "row_root": row_roots[row_id]}
        for row_id in sorted(row_roots)
    ]
    return H_hex("H_FIELD_MERKLE_LAYOUT_ROOT_V1", ordered)


def _group_semantic_fields_by_row(field_ids: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for field_id in field_ids:
        if "." not in field_id:
            continue
        row_id, field_name = field_id.rsplit(".", 1)
        grouped.setdefault(row_id, []).append(field_name)
    for row_id in grouped:
        grouped[row_id] = sorted(set(grouped[row_id]))
    return grouped


def _semantic_fields_from_view(view: ProjectionView) -> list[str]:
    out: list[str] = []
    for row in view.rows:
        row_id = str(row.get("row_id", ""))
        fields = row.get("fields", {})
        if isinstance(fields, Mapping):
            for field_name in fields:
                out.append(semantic_field_id(row_id, str(field_name)))
    return out


def _field_verification_result(
    ok: bool,
    reason: str,
    rho_t: str,
    view: ProjectionView,
    proof: FieldMerkleProjectionProof,
) -> ProjectionVerificationResult:
    disclosed_fields = len(_semantic_fields_from_view(view))
    return ProjectionVerificationResult(
        ok=ok,
        reason=reason,
        phase=str(view.phase),
        trade_id=view.trade_id,
        rho_t=rho_t,
        opened_rows=len(view.rows),
        disclosed_fields=disclosed_fields,
    )
