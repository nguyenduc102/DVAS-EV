from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .crypto import H, H_hex, ecdsa_sign, ecdsa_verify
from .entities import Station


STATION_SESSION_DOMAIN = "DBAS-ET:STATION-SESSION-BINDING:v1"


@dataclass(frozen=True)
class StationSessionBindingCertificate:
    """
    Hybrid station certificate for opening a charging session.

    This certificate binds the station to:
      - trade_id
      - committed transaction root rho_t
      - session id sid_t
      - meter_id
      - station nonce nonce_s

    It intentionally does NOT include tariff_digest because tariff/session/payment
    fields are already committed under rho_t and checked by projection proofs.
    """

    station_id: str
    trade_id: str
    rho_t: str
    sid_t: str
    meter_id: str
    nonce_s: str
    classical_sig_hex: str
    pq_sig_hex: str
    classical_sig_algorithm: str = "ECDSA-SHA256"
    pq_backend: str = ""
    pq_algorithm: str = ""
    pq_pkid: str = ""
    cert_version: str = "station-session-binding-hybrid-v1"

    def unsigned_record(self) -> dict[str, Any]:
        return {
            "cert_version": self.cert_version,
            "station_id": str(self.station_id),
            "trade_id": str(self.trade_id),
            "rho_t": str(self.rho_t),
            "sid_t": str(self.sid_t),
            "meter_id": str(self.meter_id),
            "nonce_s": str(self.nonce_s),
        }

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def build_station_session_binding_message(unsigned_record: Mapping[str, Any]) -> bytes:
    """Canonical message signed by both ECDSA and ML-DSA."""
    return H(STATION_SESSION_DOMAIN, dict(unsigned_record))


def station_session_binding_digest(unsigned_record: Mapping[str, Any]) -> str:
    return H_hex(STATION_SESSION_DOMAIN + ":digest", dict(unsigned_record))


def _get_station_pq_sig_keys(station: Station) -> Any:
    pq_keys = getattr(station, "pq_sig_keys", None)
    if pq_keys is None:
        raise ValueError(
            "station has no pq_sig_keys. "
            "Create station with create_station(..., sig_backend='oqs', sig_algorithm='ML-DSA-65')."
        )
    return pq_keys


def issue_station_session_binding_certificate(
    *,
    station: Station,
    trade_id: str,
    rho_t: str,
    sid_t: str,
    meter_id: str,
    nonce_s: str = "",
    **unused_legacy_kwargs: Any,
) -> StationSessionBindingCertificate:
    """
    Issue hybrid ECDSA + ML-DSA station certificate.

    The same canonical unsigned message is signed by:
      - station.cls_sk using ECDSA-SHA256
      - station.pq_sig_keys using ML-DSA
    """
    # Backward-compatibility guard:
    # Older local patch attempts may still pass tariff_digest=... into this function.
    # Station session binding intentionally ignores it because tariff/payment fields
    # are already committed under rho_t and checked by projection proofs.
    allowed_legacy = {
        "tariff_digest",
        "tariff_record_digest",
        "station_tariff_digest",
    }
    unexpected = set(unused_legacy_kwargs) - allowed_legacy
    if unexpected:
        raise TypeError(f"unexpected station certificate kwargs: {sorted(unexpected)}")

    pq_keys = _get_station_pq_sig_keys(station)

    unsigned = {
        "cert_version": "station-session-binding-hybrid-v1",
        "station_id": str(station.station_id),
        "trade_id": str(trade_id),
        "rho_t": str(rho_t),
        "sid_t": str(sid_t),
        "meter_id": str(meter_id),
        "nonce_s": str(nonce_s),
    }

    msg = build_station_session_binding_message(unsigned)

    classical_sig = ecdsa_sign(station.cls_sk, msg)
    pq_sig = pq_keys.sign(msg)

    if not isinstance(classical_sig, (bytes, bytearray)):
        raise TypeError(f"ecdsa_sign returned {type(classical_sig).__name__}, expected bytes")

    if not isinstance(pq_sig, (bytes, bytearray)):
        raise TypeError(f"pq_keys.sign returned {type(pq_sig).__name__}, expected bytes")

    return StationSessionBindingCertificate(
        station_id=unsigned["station_id"],
        trade_id=unsigned["trade_id"],
        rho_t=unsigned["rho_t"],
        sid_t=unsigned["sid_t"],
        meter_id=unsigned["meter_id"],
        nonce_s=unsigned["nonce_s"],
        classical_sig_hex=bytes(classical_sig).hex(),
        pq_sig_hex=bytes(pq_sig).hex(),
        classical_sig_algorithm="ECDSA-SHA256",
        pq_backend=str(pq_keys.backend),
        pq_algorithm=str(pq_keys.algorithm),
        pq_pkid=str(pq_keys.pkid),
        cert_version=unsigned["cert_version"],
    )


def _as_cert(cert: StationSessionBindingCertificate | Mapping[str, Any]) -> StationSessionBindingCertificate:
    if isinstance(cert, StationSessionBindingCertificate):
        return cert

    if isinstance(cert, Mapping):
        allowed = {
            "station_id",
            "trade_id",
            "rho_t",
            "sid_t",
            "meter_id",
            "nonce_s",
            "classical_sig_hex",
            "pq_sig_hex",
            "classical_sig_algorithm",
            "pq_backend",
            "pq_algorithm",
            "pq_pkid",
            "cert_version",
        }
        clean = {k: v for k, v in dict(cert).items() if k in allowed}
        return StationSessionBindingCertificate(**clean)

    raise TypeError(f"unsupported station certificate type: {type(cert).__name__}")


def verify_station_session_binding_certificate(
    *,
    station: Station,
    cert: StationSessionBindingCertificate | Mapping[str, Any],
    expected_trade_id: str,
    expected_rho_t: str,
    expected_sid_t: str,
    expected_meter_id: str,
) -> tuple[bool, str]:
    """
    Verify hybrid station session certificate.

    Accept only if:
      - all expected binding fields match;
      - ECDSA signature verifies;
      - ML-DSA signature verifies.
    """
    try:
        c = _as_cert(cert)
    except Exception as exc:
        return False, f"station_certificate_malformed:{type(exc).__name__}"

    if str(c.station_id) != str(station.station_id):
        return False, "station_id_mismatch"

    if str(c.trade_id) != str(expected_trade_id):
        return False, "trade_id_mismatch"

    if str(c.rho_t) != str(expected_rho_t):
        return False, "rho_t_mismatch"

    if str(c.sid_t) != str(expected_sid_t):
        return False, "sid_t_mismatch"

    if str(c.meter_id) != str(expected_meter_id):
        return False, "meter_id_mismatch"

    try:
        pq_keys = _get_station_pq_sig_keys(station)
    except Exception:
        return False, "station_pq_key_missing"

    if str(c.pq_backend) != str(pq_keys.backend):
        return False, "station_pq_backend_mismatch"

    if str(c.pq_algorithm) != str(pq_keys.algorithm):
        return False, "station_pq_algorithm_mismatch"

    if str(c.pq_pkid) != str(pq_keys.pkid):
        return False, "station_pq_pkid_mismatch"

    unsigned = c.unsigned_record()
    msg = build_station_session_binding_message(unsigned)

    try:
        classical_sig = bytes.fromhex(str(c.classical_sig_hex))
    except Exception:
        return False, "station_classical_signature_malformed"

    if not ecdsa_verify(station.cls_pk, msg, classical_sig):
        return False, "station_classical_signature_invalid"

    try:
        pq_sig = bytes.fromhex(str(c.pq_sig_hex))
    except Exception:
        return False, "station_pq_signature_malformed"

    if not pq_keys.verify(msg, pq_sig):
        return False, "station_pq_signature_invalid"

    return True, "ok"
