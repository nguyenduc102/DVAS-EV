"""
Formal-style interface to PAM-Proof.

PAM-Proof is a predicate-complete authenticated opening on top of a standard
Merkle multiproof.  Commit/Open are an ordinary SHA-256 binary Merkle tree and
packed multiproof; Verify additionally recomputes the required operand set of
the predicate and checks it before Merkle authenticity.

    pp  <- Setup(L)                      public parameters, no trusted setup
    rho <- Commit(pp, C)                 domain-separated Merkle root over enc(C)
    F_r <- Select(pp, r)                 committed operands of predicate r
    pi  <- Open(pp, C, F)                values of F + packed multiproof
    b   <- Verify(pp, rho, r, pi)        (A) F_r subset of F(pi)  [or == under EXACT]
                                         (B) Merkle authenticity against rho

This module only wraps ``pam``/``predicates``; AuthSC and the settlement
verifiers go through the same code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .pam import (
    Commitment,
    CompletenessPolicy,
    PAMOpening,
    PAMVerifyResult,
    ProofKind,
    commit,
    open_fields,
    verify_opening,
)
from .predicates import PREDICATES, required_fields
from .schema import LAYOUT_V1, LayoutSchema

HASH_CONFIG = {
    "hash": "SHA-256",
    "leaf": "SHA256(0x00 | schema_digest | index:u16 | enc_field)",
    "node": "SHA256(0x01 | left | right)",
    "pad": "SHA256(0x02 | schema_digest | index:u16)",
    "root": "tagged_hash('DVAS-EV/root/v1', schema_digest, merkle_root)",
    "encoding": "DVAS-EV canonical TLV v1",
}


@dataclass(frozen=True)
class PublicParams:
    schema: LayoutSchema
    schema_digest: str
    hash_config: tuple[tuple[str, str], ...]
    policy: CompletenessPolicy = CompletenessPolicy.SUPERSET
    proof_kind: ProofKind = ProofKind.MULTIPROOF
    trusted_setup: bool = False

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(PREDICATES)


def Setup(L: LayoutSchema = LAYOUT_V1, *, policy: CompletenessPolicy = CompletenessPolicy.SUPERSET,
          proof_kind: ProofKind = ProofKind.MULTIPROOF) -> PublicParams:
    """Public parameters derived from the layout schema only (no trusted setup)."""
    return PublicParams(L, L.digest().hex(), tuple(sorted(HASH_CONFIG.items())), policy, proof_kind)


def Commit(pp: PublicParams, C: Mapping[str, Any]) -> tuple[str, Commitment]:
    """Canonical-encode C, build the domain-separated tree; return (rho, opening state)."""
    c = commit(C, pp.schema)
    return c.rho_t, c


def Select(pp: PublicParams, r: str) -> tuple[str, ...]:
    """Deterministic committed-operand set F_r of predicate r (sufficient, not necessarily minimal)."""
    return required_fields(pp.schema, r)


def Open(pp: PublicParams, state: Commitment, F: Iterable[str], *, r: str) -> PAMOpening:
    """Selected values, field identifiers and packed multiproof (or independent paths)."""
    return open_fields(state, F, reason=r, proof_kind=pp.proof_kind)


def Verify(pp: PublicParams, rho: str, r: str, pi: PAMOpening) -> PAMVerifyResult:
    """(A) predicate completeness w.r.t. Select(pp, r), then (B) Merkle authenticity."""
    return verify_opening(rho, pi, reason=r, policy=pp.policy, check_completeness=True, schema=pp.schema)
