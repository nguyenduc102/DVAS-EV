"""
Cryptographic utilities for DBAS-ET.

Notes
-----
1. Classical signatures use ECDSA-SHA256 from the `cryptography` package.
2. PQ signatures use liboqs ML-DSA when OQS is available.
3. PQ KEM uses liboqs ML-KEM when OQS is available.
4. The mock fallback is only for debugging and is disabled in the strict
   smoke test.
5. Benchmark outputs record the backend, algorithm names and OQS version.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import secrets
import warnings
from dataclasses import dataclass
from typing import Any, Literal, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

try:
    from Crypto.Hash import keccak

    KECCAK_AVAILABLE = True
except Exception:
    keccak = None
    KECCAK_AVAILABLE = False

try:
    warnings.filterwarnings(
        "default",
        message=".*liboqs version.*differs from liboqs-python version.*",
    )
    import oqs  # type: ignore

    OQS_AVAILABLE = True
except Exception:
    oqs = None
    OQS_AVAILABLE = False


PQBackend = Literal["oqs", "mock-ed25519", "mock-sha256"]


# ---------------------------------------------------------------------------
# Canonical serialization and hashing
# ---------------------------------------------------------------------------

def _normalize_for_json(obj: Any) -> Any:
    """Convert object into a deterministic JSON-safe representation."""
    if dataclasses.is_dataclass(obj):
        return _normalize_for_json(dataclasses.asdict(obj))

    if isinstance(obj, bytes):
        return {"__bytes_hex__": obj.hex()}

    if isinstance(obj, bytearray):
        return {"__bytes_hex__": bytes(obj).hex()}

    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj

    if isinstance(obj, float):
        # Stable enough for traces. Payment modules can later use Decimal/int units.
        return format(obj, ".12g")

    if isinstance(obj, dict):
        return {
            str(k): _normalize_for_json(v)
            for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
        }

    if isinstance(obj, (list, tuple)):
        return [_normalize_for_json(v) for v in obj]

    if hasattr(obj, "public_bytes"):
        try:
            return {
                "__public_key_der_b64__": base64.b64encode(
                    obj.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ).decode("ascii")
            }
        except Exception:
            pass

    raise TypeError(f"object of type {type(obj).__name__} is not canonical-serializable")


def canonical_dumps(obj: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes."""
    return json.dumps(
        _normalize_for_json(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def H(label: str, payload: Any) -> bytes:
    """Domain-separated SHA-256 hash."""
    if not isinstance(label, str) or not label:
        raise ValueError("hash label must be a non-empty string")

    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    h.update(canonical_dumps(payload))
    return h.digest()


def H_hex(label: str, payload: Any) -> str:
    """Return domain-separated SHA-256 digest as lowercase hex."""
    return H(label, payload).hex()


# ---------------------------------------------------------------------------
# Classical ECDSA
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ECKeypair:
    """Classical ECDSA keypair."""

    sk: ec.EllipticCurvePrivateKey
    pk: ec.EllipticCurvePublicKey
    curve_name: str
    pk_bytes: bytes
    sk_bytes: bytes


def _curve_from_name(curve_name: str) -> ec.EllipticCurve:
    name = curve_name.lower()

    if name in {"secp256k1", "k256"}:
        return ec.SECP256K1()

    if name in {"secp256r1", "p-256", "prime256v1"}:
        return ec.SECP256R1()

    raise ValueError(f"unsupported EC curve: {curve_name}")


def gen_ec_keypair(curve_name: str = "secp256k1") -> ECKeypair:
    """Generate a real ECDSA keypair."""
    curve = _curve_from_name(curve_name)
    sk = ec.generate_private_key(curve)
    pk = sk.public_key()

    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    return ECKeypair(
        sk=sk,
        pk=pk,
        curve_name=curve_name,
        pk_bytes=pk_bytes,
        sk_bytes=sk_bytes,
    )


def ecdsa_sign(sk: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    """Sign bytes with real ECDSA-SHA256."""
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("ecdsa_sign expects msg as bytes")
    return sk.sign(bytes(msg), ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(pk: ec.EllipticCurvePublicKey, msg: bytes, sig: bytes) -> bool:
    """Verify real ECDSA-SHA256 signature. Return False instead of raising."""
    if not isinstance(msg, (bytes, bytearray)):
        return False
    if not isinstance(sig, (bytes, bytearray)):
        return False

    try:
        pk.verify(bytes(sig), bytes(msg), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def serialize_ec_public_key(pk: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize EC public key as compressed point."""
    return pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def _address_digest(data: bytes) -> Tuple[str, bytes]:
    """Return address hash backend and digest."""
    if KECCAK_AVAILABLE:
        k = keccak.new(digest_bits=256)
        k.update(data)
        return "keccak256", k.digest()

    return "sha256-fallback", hashlib.sha256(data).digest()


def make_address_from_cls_pk(pk_or_bytes: ec.EllipticCurvePublicKey | bytes) -> str:
    """
    Derive a blockchain-style simulation address.

    Stable within the simulator; this is not full EVM account derivation.
    """
    if isinstance(pk_or_bytes, bytes):
        pk_bytes = pk_or_bytes
    else:
        pk_bytes = serialize_ec_public_key(pk_or_bytes)

    _, digest = _address_digest(pk_bytes)
    return "0x" + digest[-20:].hex()


def derive_pkid_from_public_key(pk_or_bytes: ec.EllipticCurvePublicKey | bytes) -> str:
    """Derive stable public-key identifier."""
    if isinstance(pk_or_bytes, bytes):
        pk_bytes = pk_or_bytes
    else:
        pk_bytes = serialize_ec_public_key(pk_or_bytes)

    return H_hex("H_PKID_CLASSICAL", pk_bytes)


def current_pkid(pk_or_bytes: ec.EllipticCurvePublicKey | bytes) -> str:
    """Backward-compatible alias for derive_pkid_from_public_key."""
    return derive_pkid_from_public_key(pk_or_bytes)


# ---------------------------------------------------------------------------
# OQS helpers
# ---------------------------------------------------------------------------

def _oqs_versions() -> dict[str, str]:
    if not OQS_AVAILABLE:
        return {
            "liboqs_version": "",
            "liboqs_python_version": "",
        }

    out = {}
    try:
        out["liboqs_version"] = str(oqs.oqs_version())
    except Exception:
        out["liboqs_version"] = "unknown"

    try:
        out["liboqs_python_version"] = str(oqs.oqs_python_version())
    except Exception:
        out["liboqs_python_version"] = "unknown"

    return out


def _enabled_sig_mechanisms() -> list[str]:
    if not OQS_AVAILABLE:
        return []
    try:
        return list(oqs.get_enabled_sig_mechanisms())
    except Exception:
        return []


def _enabled_kem_mechanisms() -> list[str]:
    if not OQS_AVAILABLE:
        return []
    try:
        return list(oqs.get_enabled_kem_mechanisms())
    except Exception:
        return []


def require_oqs_sig_algorithm(algorithm: str) -> None:
    """Raise a clear error if OQS signature algorithm is unavailable."""
    if not OQS_AVAILABLE:
        raise RuntimeError("OQS is not available; cannot use real PQ signature backend.")

    enabled = _enabled_sig_mechanisms()
    if algorithm not in enabled:
        raise RuntimeError(
            f"OQS signature algorithm {algorithm!r} is not enabled. "
            f"Available examples: {enabled[:20]}"
        )


def require_oqs_kem_algorithm(algorithm: str) -> None:
    """Raise a clear error if OQS KEM algorithm is unavailable."""
    if not OQS_AVAILABLE:
        raise RuntimeError("OQS is not available; cannot use real PQ KEM backend.")

    enabled = _enabled_kem_mechanisms()
    if algorithm not in enabled:
        raise RuntimeError(
            f"OQS KEM algorithm {algorithm!r} is not enabled. "
            f"Available examples: {enabled[:20]}"
        )


# ---------------------------------------------------------------------------
# PQ signature interface
# ---------------------------------------------------------------------------

@dataclass
class PQSigKeypair:
    """
    PQ-signature interface keypair.

    backend="oqs" uses real liboqs ML-DSA.
    backend="mock-ed25519" is only a fallback for portability/debugging.
    """

    pk: bytes
    sk: bytes
    backend: PQBackend
    algorithm: str
    pkid: str

    def sign(self, msg: bytes) -> bytes:
        """Sign message bytes."""
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("PQSigKeypair.sign expects msg as bytes")

        if self.backend == "oqs":
            require_oqs_sig_algorithm(self.algorithm)
            with oqs.Signature(self.algorithm, self.sk) as signer:
                return signer.sign(bytes(msg))

        if self.backend == "mock-ed25519":
            sk_obj = ed25519.Ed25519PrivateKey.from_private_bytes(self.sk)
            return sk_obj.sign(bytes(msg))

        raise ValueError(f"unsupported PQ signature backend: {self.backend}")

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """Verify signature. Return False instead of raising."""
        if not isinstance(msg, (bytes, bytearray)):
            return False
        if not isinstance(sig, (bytes, bytearray)):
            return False

        if self.backend == "oqs":
            try:
                require_oqs_sig_algorithm(self.algorithm)
                with oqs.Signature(self.algorithm) as verifier:
                    return bool(verifier.verify(bytes(msg), bytes(sig), self.pk))
            except Exception:
                return False

        if self.backend == "mock-ed25519":
            try:
                pk_obj = ed25519.Ed25519PublicKey.from_public_bytes(self.pk)
                pk_obj.verify(bytes(sig), bytes(msg))
                return True
            except Exception:
                return False

        return False

    def public_record(self) -> dict[str, Any]:
        warning = "" if self.backend == "oqs" else "not_pq_secure_mock_backend"
        return {
            "backend": self.backend,
            "algorithm": self.algorithm,
            "pkid": self.pkid,
            "pk_hex": self.pk.hex(),
            "warning": warning,
        }


def gen_pq_sig_keypair(
    algorithm: str = "ML-DSA-65",
    backend: Literal["oqs", "mock-ed25519", "auto"] = "oqs",
    strict: bool = True,
) -> PQSigKeypair:
    """
    Generate PQ-signature interface keypair.

    Default is real OQS ML-DSA-65. If strict=True, failure to use OQS raises.
    """
    if backend in {"oqs", "auto"}:
        try:
            require_oqs_sig_algorithm(algorithm)
            with oqs.Signature(algorithm) as signer:
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()

            pkid = H_hex(
                "H_PQ_SIG_PKID",
                {"backend": "oqs", "algorithm": algorithm, "pk": pk},
            )

            return PQSigKeypair(
                pk=pk,
                sk=sk,
                backend="oqs",
                algorithm=algorithm,
                pkid=pkid,
            )
        except Exception:
            if backend == "oqs" or strict:
                raise

    # Fallback only when explicitly allowed.
    sk_obj = ed25519.Ed25519PrivateKey.generate()
    pk_obj = sk_obj.public_key()

    sk = sk_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk = pk_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    algorithm_mock = "MOCK-PQ-SIG-ED25519"
    pkid = H_hex(
        "H_PQ_SIG_PKID",
        {"backend": "mock-ed25519", "algorithm": algorithm_mock, "pk": pk},
    )

    return PQSigKeypair(
        pk=pk,
        sk=sk,
        backend="mock-ed25519",
        algorithm=algorithm_mock,
        pkid=pkid,
    )


# ---------------------------------------------------------------------------
# PQ KEM interface
# ---------------------------------------------------------------------------

@dataclass
class PQKEMKeypair:
    """
    PQ-KEM interface keypair.

    backend="oqs" uses real liboqs ML-KEM.
    backend="mock-sha256" is only fallback/debug plumbing.
    """

    pk: bytes
    sk: bytes
    backend: PQBackend
    algorithm: str
    pkid: str

    def encapsulate(self) -> tuple[bytes, bytes]:
        """Return ciphertext and shared secret."""
        if self.backend == "oqs":
            require_oqs_kem_algorithm(self.algorithm)
            with oqs.KeyEncapsulation(self.algorithm) as server:
                ciphertext, shared_secret = server.encap_secret(self.pk)
            return ciphertext, shared_secret

        if self.backend == "mock-sha256":
            nonce = secrets.token_bytes(32)
            ciphertext = hashlib.sha256(b"mock-ct|" + self.pk + nonce).digest()
            shared_secret = hashlib.sha256(b"mock-ss|" + self.sk + ciphertext).digest()
            return ciphertext, shared_secret

        raise ValueError(f"unsupported KEM backend: {self.backend}")

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate ciphertext and return shared secret."""
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")

        if self.backend == "oqs":
            require_oqs_kem_algorithm(self.algorithm)
            with oqs.KeyEncapsulation(self.algorithm, self.sk) as client:
                return client.decap_secret(bytes(ciphertext))

        if self.backend == "mock-sha256":
            return hashlib.sha256(b"mock-ss|" + self.sk + bytes(ciphertext)).digest()

        raise ValueError(f"unsupported KEM backend: {self.backend}")

    def public_record(self) -> dict[str, Any]:
        warning = "" if self.backend == "oqs" else "not_pq_secure_mock_backend"
        return {
            "backend": self.backend,
            "algorithm": self.algorithm,
            "pkid": self.pkid,
            "pk_hex": self.pk.hex(),
            "warning": warning,
        }


def gen_pq_kem_keypair(
    algorithm: str = "ML-KEM-768",
    backend: Literal["oqs", "mock-sha256", "auto"] = "oqs",
    strict: bool = True,
) -> PQKEMKeypair:
    """
    Generate PQ-KEM interface keypair.

    Default is real OQS ML-KEM-768. If strict=True, failure to use OQS raises.
    """
    if backend in {"oqs", "auto"}:
        try:
            require_oqs_kem_algorithm(algorithm)
            with oqs.KeyEncapsulation(algorithm) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()

            pkid = H_hex(
                "H_PQ_KEM_PKID",
                {"backend": "oqs", "algorithm": algorithm, "pk": pk},
            )

            return PQKEMKeypair(
                pk=pk,
                sk=sk,
                backend="oqs",
                algorithm=algorithm,
                pkid=pkid,
            )
        except Exception:
            if backend == "oqs" or strict:
                raise

    sk = secrets.token_bytes(32)
    pk = hashlib.sha256(b"mock-kem-pk|" + sk).digest()
    algorithm_mock = "MOCK-PQ-KEM-SHA256"

    pkid = H_hex(
        "H_PQ_KEM_PKID",
        {"backend": "mock-sha256", "algorithm": algorithm_mock, "pk": pk},
    )

    return PQKEMKeypair(
        pk=pk,
        sk=sk,
        backend="mock-sha256",
        algorithm=algorithm_mock,
        pkid=pkid,
    )


def get_crypto_backend_info() -> dict[str, Any]:
    """Return backend metadata for benchmark tables."""
    versions = _oqs_versions()

    return {
        "classical_signature": "ECDSA-SHA256",
        "default_ec_curve": "secp256k1",
        "hash_function": "SHA-256 with canonical JSON and domain separation",
        "address_hash": "keccak256" if KECCAK_AVAILABLE else "sha256-fallback",
        "keccak_available": bool(KECCAK_AVAILABLE),
        "oqs_available": bool(OQS_AVAILABLE),
        "liboqs_version": versions["liboqs_version"],
        "liboqs_python_version": versions["liboqs_python_version"],
        "pq_signature_backend_default": "oqs",
        "pq_signature_algorithm_default": "ML-DSA-65",
        "pq_kem_backend_default": "oqs",
        "pq_kem_algorithm_default": "ML-KEM-768",
        "enabled_sig_contains_mldsa65": "ML-DSA-65" in _enabled_sig_mechanisms(),
        "enabled_kem_contains_mlkem768": "ML-KEM-768" in _enabled_kem_mechanisms(),
        "warning": (
            "Real OQS backend is used when backend='oqs'. "
            "Record liboqs/liboqs-python versions in all benchmark outputs. "
            "Version mismatch warnings should be disclosed in artifact notes."
        ),
    }