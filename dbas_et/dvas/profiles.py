"""
Cryptographic profiles, signature schemes and KEMs for DVAS-EV.

Profiles (PQ ablation)
------------------------------
C0  CLASSICAL       ECDSA everywhere, X25519 KEM for private evidence.
C1  PQ-AUTH-ONLY    ML-DSA-65 user/station authorization; rest classical.
C2  PQ-KEM-ONLY     ML-KEM-768 private evidence; signatures classical.
C3  HYBRID          ECDSA+ML-DSA-65 hybrid authorization, ML-KEM-768 private
                    evidence, ECDSA meter receipts and ECDSA verifier
                    attestations (EVM ecrecover-compatible settlement path).
                    Labelled HYBRID: meter and RBC paths are classical.
C4  HYBRID-PQ-ATTEST  as C3 but verifier attestations use ML-DSA-65
                    (off-chain/contract-simulation only; not EVM-verifiable).

No profile is "fully post-quantum": meter receipts remain ECDSA in all of
them because deployed meters sign classically.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from ..crypto import OQS_AVAILABLE, oqs
from .instrumentation import count

ECDSA = "ecdsa-secp256k1-sha256"
MLDSA65 = "ml-dsa-65"
HYBRID_SIG = "hybrid-ecdsa-secp256k1+ml-dsa-65"
X25519 = "x25519"
MLKEM768 = "ml-kem-768"

_OQS_SIG = {MLDSA65: "ML-DSA-65"}
_OQS_KEM = {MLKEM768: "ML-KEM-768"}


@dataclass(frozen=True)
class CryptoProfile:
    name: str
    label: str
    auth_sig: str
    station_sig: str
    meter_sig: str
    verifier_sig: str
    kem: str
    pq_status: str

    def to_record(self) -> dict[str, str]:
        return dict(self.__dict__)


PROFILES: dict[str, CryptoProfile] = {
    "C0": CryptoProfile("C0", "classical", ECDSA, ECDSA, ECDSA, ECDSA, X25519, "CLASSICAL"),
    "C1": CryptoProfile("C1", "ml-dsa-authorization-only", MLDSA65, MLDSA65, ECDSA, ECDSA, X25519, "PARTIAL-PQ"),
    "C2": CryptoProfile("C2", "ml-kem-private-receipt-only", ECDSA, ECDSA, ECDSA, ECDSA, MLKEM768, "PARTIAL-PQ"),
    "C3": CryptoProfile("C3", "hybrid", HYBRID_SIG, HYBRID_SIG, ECDSA, ECDSA, MLKEM768, "HYBRID"),
    "C4": CryptoProfile("C4", "hybrid-pq-attestations", HYBRID_SIG, HYBRID_SIG, ECDSA, MLDSA65, MLKEM768, "HYBRID"),
}

DEFAULT_PROFILE = PROFILES["C3"]


def _require_oqs() -> None:
    if not OQS_AVAILABLE:
        raise RuntimeError("liboqs/oqs is required for ML-DSA/ML-KEM profiles")


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

def _lp(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">H", len(p)) + p for p in parts)


def _split_lp(data: bytes) -> list[bytes]:
    out, off = [], 0
    while off < len(data):
        (n,) = struct.unpack(">H", data[off:off + 2]); off += 2
        out.append(data[off:off + n]); off += n
    return out


class Signer:
    """Holds a private key for one signature scheme."""

    def __init__(self, scheme: str) -> None:
        self.scheme = scheme
        self._ec: ec.EllipticCurvePrivateKey | None = None
        self._oqs: Any = None
        if scheme in (ECDSA, HYBRID_SIG):
            self._ec = ec.generate_private_key(ec.SECP256K1())
        if scheme in (MLDSA65, HYBRID_SIG):
            _require_oqs()
            self._oqs = oqs.Signature("ML-DSA-65")
            self._oqs_pk = self._oqs.generate_keypair()
        if scheme not in (ECDSA, MLDSA65, HYBRID_SIG):
            raise ValueError(f"unsupported signature scheme {scheme}")
        self.public_key = self._public_key()

    def _ec_pk(self) -> bytes:
        assert self._ec is not None
        return self._ec.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

    def _public_key(self) -> bytes:
        if self.scheme == ECDSA:
            return self._ec_pk()
        if self.scheme == MLDSA65:
            return bytes(self._oqs_pk)
        return _lp(self._ec_pk(), bytes(self._oqs_pk))

    def sign(self, msg: bytes) -> bytes:
        count("sig_gen")
        if self.scheme == ECDSA:
            return self._ec.sign(msg, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
        if self.scheme == MLDSA65:
            return bytes(self._oqs.sign(msg))
        return _lp(self._ec.sign(msg, ec.ECDSA(hashes.SHA256())), bytes(self._oqs.sign(msg)))  # type: ignore[union-attr]


@lru_cache(maxsize=65536)
def _load_ec(pk: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk)


_OQS_VERIFIERS: dict[str, Any] = {}


def _oqs_verifier(alg: str) -> Any:
    v = _OQS_VERIFIERS.get(alg)
    if v is None:
        _require_oqs()
        v = oqs.Signature(alg)
        _OQS_VERIFIERS[alg] = v
    return v


def _ec_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        _load_ec(pk).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_signature(scheme: str, public_key: bytes, msg: bytes, sig: bytes) -> bool:
    count("sig_verify")
    if not isinstance(sig, (bytes, bytearray)) or not isinstance(msg, (bytes, bytearray)):
        return False
    try:
        if scheme == ECDSA:
            return _ec_verify(public_key, msg, sig)
        if scheme == MLDSA65:
            return bool(_oqs_verifier("ML-DSA-65").verify(msg, sig, public_key))
        if scheme == HYBRID_SIG:
            pks, sigs = _split_lp(public_key), _split_lp(sig)
            if len(pks) != 2 or len(sigs) != 2:
                return False
            return _ec_verify(pks[0], msg, sigs[0]) and bool(_oqs_verifier("ML-DSA-65").verify(msg, sigs[1], pks[1]))
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# KEMs
# ---------------------------------------------------------------------------

class KEMKeypair:
    def __init__(self, scheme: str) -> None:
        self.scheme = scheme
        if scheme == X25519:
            self._sk = x25519.X25519PrivateKey.generate()
            self.public_key = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        elif scheme == MLKEM768:
            _require_oqs()
            self._kem = oqs.KeyEncapsulation("ML-KEM-768")
            self.public_key = bytes(self._kem.generate_keypair())
        else:
            raise ValueError(f"unsupported KEM {scheme}")
        self.pkid = hashlib.sha256(scheme.encode() + b"|" + self.public_key).hexdigest()

    def decapsulate(self, ct: bytes) -> bytes:
        count("kem_decap")
        if self.scheme == X25519:
            peer = x25519.X25519PublicKey.from_public_bytes(ct)
            return self._sk.exchange(peer)
        return bytes(self._kem.decap_secret(ct))


_OQS_KEMS: dict[str, Any] = {}


def kem_encapsulate(scheme: str, public_key: bytes) -> tuple[bytes, bytes]:
    count("kem_encap")
    if scheme == X25519:
        eph = x25519.X25519PrivateKey.generate()
        ct = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return ct, eph.exchange(x25519.X25519PublicKey.from_public_bytes(public_key))
    if scheme == MLKEM768:
        k = _OQS_KEMS.get(scheme)
        if k is None:
            _require_oqs()
            k = oqs.KeyEncapsulation("ML-KEM-768")
            _OQS_KEMS[scheme] = k
        ct, ss = k.encap_secret(public_key)
        return bytes(ct), bytes(ss)
    raise ValueError(f"unsupported KEM {scheme}")


def backend_metadata() -> dict[str, Any]:
    md: dict[str, Any] = {"oqs_available": bool(OQS_AVAILABLE)}
    if OQS_AVAILABLE:
        md["liboqs_version"] = str(oqs.oqs_version())
        md["liboqs_python_version"] = str(oqs.oqs_python_version())
        md["ml_dsa_65_enabled"] = "ML-DSA-65" in oqs.get_enabled_sig_mechanisms()
        md["ml_kem_768_enabled"] = "ML-KEM-768" in oqs.get_enabled_kem_mechanisms()
    return md
