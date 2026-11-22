"""
Meter-authenticated delivery evidence.

h_priv = H(canonical_encode(DR_private))

The registered meter signs the canonical public receipt DR_t, which binds
tid, sid, rho_t, station and meter identity, delivered energy, timestamps,
the applied tariff reference, the meter key epoch and h_priv.  The private
payload is then encrypted for the verifier cluster (``evidence``).  Because
h_priv is inside the meter signature, a substituted private payload, even
one inside a perfectly valid KEM/AEAD envelope, is detected by recomputing
H(DR_private).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence

from .canonical import decode_record, encode_record, normalize_value, tagged_hash
from .evidence import EvidenceContext, EvidenceEnvelope, RecipientKey, seal_evidence
from .profiles import Signer
from .schema import PRIVATE_RECEIPT, PUBLIC_RECEIPT, REGISTRY

RECEIPT_VERSION = "dvas-ev-receipt-v1"


def private_payload_bytes(values: Mapping[str, Any]) -> bytes:
    return encode_record(REGISTRY, PRIVATE_RECEIPT, values)


def h_priv_of(values_or_bytes: Mapping[str, Any] | bytes) -> str:
    data = values_or_bytes if isinstance(values_or_bytes, bytes) else private_payload_bytes(values_or_bytes)
    return tagged_hash("DVAS-EV/h_priv/v1", data).hex()


def decode_private_payload(data: bytes) -> dict[str, Any]:
    return decode_record(REGISTRY, PRIVATE_RECEIPT, data)


@dataclass(frozen=True)
class PublicReceipt:
    values: dict[str, Any]
    signature: bytes = b""

    def encoded(self) -> bytes:
        return encode_record(REGISTRY, PUBLIC_RECEIPT, self.values)

    def message(self) -> bytes:
        return tagged_hash("DVAS-EV/receipt-sig/v1", self.encoded())

    @property
    def dr_digest(self) -> str:
        """Replay key: digest of the unsigned canonical receipt (signature-malleability safe)."""
        return tagged_hash("DVAS-EV/dr-digest/v1", self.encoded()).hex()

    def __getitem__(self, k: str) -> Any:
        return self.values[k]

    def with_values(self, **kw: Any) -> "PublicReceipt":
        v = dict(self.values)
        v.update(kw)
        return replace(self, values=v)


@dataclass
class MeterDevice:
    meter_id: str
    station_id: str
    signer: Signer
    key_epoch: int = 1
    last_timings: dict[str, float] = field(default_factory=dict)

    def issue(
        self,
        *,
        tid: str,
        sid: str,
        rho_t: str,
        delivered_kwh: Any,
        ts_start: int,
        ts_end: int,
        applied_tariff_id: str,
        applied_tariff_version: str,
        connection_duration_s: int,
        active_charging_duration_s: int,
        parking_duration_s: int,
        session_ref: str,
        nonce_m: str,
        recipients: Sequence[RecipientKey],
        meter_values_digest: str | None = None,
    ) -> tuple[PublicReceipt, EvidenceEnvelope, dict[str, Any]]:
        """Produce (signed DR_t, encrypted DR_private, DR_private values)."""
        priv = {
            "receipt_version": RECEIPT_VERSION,
            "receipt_tid": tid,
            "sid": sid,
            "rho_t": rho_t,
            "receipt_meter_id": self.meter_id,
            "delivered_kwh": delivered_kwh,
            "ts_start": int(ts_start),
            "ts_end": int(ts_end),
            "connection_duration_s": int(connection_duration_s),
            "active_charging_duration_s": int(active_charging_duration_s),
            "parking_duration_s": int(parking_duration_s),
            "session_ref": session_ref,
            "meter_values_digest": meter_values_digest,
            "nonce_m": nonce_m,
        }
        t0 = time.perf_counter()
        priv = {k: normalize_value(REGISTRY.spec(k), v) for k, v in priv.items()}
        priv_bytes = private_payload_bytes(priv)
        hp = h_priv_of(priv_bytes)
        pub = {
            "receipt_version": RECEIPT_VERSION,
            "receipt_tid": tid,
            "sid": sid,
            "rho_t": rho_t,
            "receipt_station_id": self.station_id,
            "receipt_meter_id": self.meter_id,
            "delivered_kwh": priv["delivered_kwh"],
            "ts_start": priv["ts_start"],
            "ts_end": priv["ts_end"],
            "applied_tariff_id": applied_tariff_id,
            "applied_tariff_version": applied_tariff_version,
            "nonce_m": nonce_m,
            "h_priv": hp,
            "meter_key_epoch": int(self.key_epoch),
        }
        receipt = PublicReceipt(pub)
        receipt = replace(receipt, signature=self.signer.sign(receipt.message()))
        t1 = time.perf_counter()
        env = seal_evidence(priv_bytes, EvidenceContext(tid, sid, rho_t, self.meter_id, hp), recipients)
        t2 = time.perf_counter()
        self.last_timings = {"receipt_sign": (t1 - t0) * 1000.0, "private_protect": (t2 - t1) * 1000.0}
        return receipt, env, priv


def resign(receipt: PublicReceipt, signer: Signer) -> PublicReceipt:
    """Sign arbitrary receipt values with ``signer`` (used by attack generators)."""
    return replace(receipt, signature=signer.sign(receipt.message()))
