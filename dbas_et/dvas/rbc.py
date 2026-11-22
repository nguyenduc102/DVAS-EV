"""
Quorum Receipt Binding Certificate: RBC = RBC_body + verifier attestations.

RBC_body is the canonical SETTLEMENT_DECISION record.  Every accepting
verifier signs the SAME decision digest

    decision_digest = H(encode(RBC_body))

inside an ATTESTATION_MESSAGE that additionally binds its verifier_id and key
epoch.  No threshold-signature scheme is used: SettleSC counts independent
signatures from distinct registered verifiers.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .canonical import encode_record, normalize_value, tagged_hash
from .schema import ATTESTATION_MESSAGE, PROTOCOL_VERSION_VALUE, REGISTRY, SETTLEMENT_DECISION

RBC_VERSION = "dvas-ev-rbc-v1"
SETTLEMENT_POLICY_ID = "P.settlement/dvas-ev-layout-v1/v1"


@dataclass(frozen=True)
class RBCBody:
    values: dict[str, Any]

    @staticmethod
    def build(**kw: Any) -> "RBCBody":
        vals = {k: normalize_value(REGISTRY.spec(k), v) for k, v in kw.items()}
        body = RBCBody(vals)
        body.encoded()  # validates the field set
        return body

    def encoded(self) -> bytes:
        return encode_record(REGISTRY, SETTLEMENT_DECISION, self.values)

    @property
    def digest(self) -> str:
        return tagged_hash("DVAS-EV/decision/v1", self.encoded()).hex()

    def __getitem__(self, k: str) -> Any:
        return self.values[k]

    @property
    def tid(self) -> str:
        return self.values["settle_tid"]

    @property
    def captured(self) -> Decimal:
        return self.values["captured_amount"]


def attestation_message(verifier_id: str, key_epoch: int, decision_digest: str) -> bytes:
    rec = encode_record(REGISTRY, ATTESTATION_MESSAGE, {
        "settle_protocol_version": PROTOCOL_VERSION_VALUE,
        "verifier_id": verifier_id,
        "verifier_key_epoch": int(key_epoch),
        "decision_digest": decision_digest,
    })
    return tagged_hash("DVAS-EV/attestation-sig/v1", rec)


@dataclass(frozen=True)
class VerificationAttestation:
    protocol_version: str
    verifier_id: str
    verifier_key_epoch: int
    tid: str
    sid: str
    rho_t: str
    dr_digest: str
    h_priv: str
    captured_amount: Decimal
    decision: str
    policy_id: str
    decision_digest: str
    signature: bytes
    scheme: str

    @staticmethod
    def for_body(body: RBCBody, verifier_id: str, key_epoch: int, signature: bytes, scheme: str) -> "VerificationAttestation":
        return VerificationAttestation(
            PROTOCOL_VERSION_VALUE, verifier_id, key_epoch, body["settle_tid"], body["settle_sid"],
            body["settle_rho_t"], body["dr_digest"], body["settle_h_priv"], body["captured_amount"],
            body["decision"], body["policy_id"], body.digest, signature, scheme,
        )

    def size_bytes(self) -> int:
        return len(self.verifier_id) + 4 + 32 + len(self.signature)


@dataclass(frozen=True)
class QuorumRBC:
    body: RBCBody
    attestations: tuple[VerificationAttestation, ...]

    def size_bytes(self) -> int:
        return len(self.body.encoded()) + sum(a.size_bytes() for a in self.attestations)


def aggregate(
    attestations: Iterable[VerificationAttestation],
    bodies: Mapping[str, RBCBody],
    threshold: int,
) -> QuorumRBC | None:
    """Aggregator (untrusted, e.g. the station): keep only attestations over the
    most-supported ACCEPT decision digest; return an RBC if it reaches t."""
    groups: dict[str, list[VerificationAttestation]] = defaultdict(list)
    for a in attestations:
        if a.decision == "ACCEPT" and a.decision_digest in bodies:
            groups[a.decision_digest].append(a)
    if not groups:
        return None
    digest, group = max(groups.items(), key=lambda kv: (len({a.verifier_id for a in kv[1]}), kv[0]))
    uniq: dict[str, VerificationAttestation] = {}
    for a in sorted(group, key=lambda a: a.verifier_id):
        uniq.setdefault(a.verifier_id, a)
    if len(uniq) < threshold:
        return None
    return QuorumRBC(bodies[digest], tuple(uniq.values()))
