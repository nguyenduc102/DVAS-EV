"""Section 1: canonical encoding, test vectors and field lifecycle."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from dbas_et.dvas.canonical import (
    ENCODING_VERSION,
    EncodingError,
    FieldSpec,
    Lifecycle,
    TypeTag,
    decode_record,
    encode_field,
    encode_record,
    to_fixed6,
)
from dbas_et.dvas.pam import commit, leaf_hash, open_for_reason, verify_opening
from dbas_et.dvas.schema import (
    LAYOUT_V1,
    PRIVATE_RECEIPT,
    PUBLIC_RECEIPT,
    REGISTRY,
    LayoutSchema,
)

VECTORS = Path(__file__).parent / "vectors" / "canonical_v1.json"


def sample_layout() -> dict:
    return {
        "protocol_version": "DVAS-EV/2.0", "schema_version": "dvas-ev-layout-v1",
        "tid": "8d0c8d1a4f7a8a8a5f3e0f1e2d3c4b5a69788766", "created_at": 1571025528,
        "user_id": "U_736df8cf15", "user_account": "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
        "home_operator": "OH_ACN", "station_id": "S_244e78f033", "meter_id": "M_dc8ade7afe",
        "foreign_operator": "OF_CALTECH", "beneficiary": "BEN_S_244e78f033", "evse_id": None,
        "tariff_id": "CALTECH_OFFPEAK_ENERGY_ACTIVE_TIME", "tariff_version": "acn-derived-v1",
        "tariff_mode": "ENERGY_ACTIVE_TIME", "unit_price": Decimal("0.32"), "currency": "TOKEN",
        "requested_kwh": Decimal("20.0"), "cap_kwh": Decimal("20.0"), "preauth_limit": Decimal("6.4"),
        "tw_start": 1571025528, "tw_end": 1571061160, "paytok": "f2c1a0b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3",
        "payment_semantics": "RESERVE_RELEASE", "nonce_u": "acn-user-0-5db8d98ef9af8b52c8402841",
        "nonce_s": "acn-station-0-2-39-139-28",
    }


def sample_public_receipt() -> dict:
    return {
        "receipt_version": "dvas-ev-receipt-v1", "receipt_tid": "t-1", "sid": "s-1", "rho_t": "11" * 32,
        "receipt_station_id": "S_1", "receipt_meter_id": "M_1", "delivered_kwh": Decimal("14.083"),
        "ts_start": 1571025528, "ts_end": 1571061160, "applied_tariff_id": "T", "applied_tariff_version": "v1",
        "nonce_m": "m-1", "h_priv": "22" * 32, "meter_key_epoch": 1,
    }


def _vector_payload() -> dict:
    c = commit(sample_layout())
    return {
        "encoding_version": ENCODING_VERSION,
        "layout_schema_digest": LAYOUT_V1.digest().hex(),
        "public_receipt_bytes": encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt()).hex(),
        "leaf_hashes": {n: leaf_hash(LAYOUT_V1, n, c.values[n]).hex() for n in LAYOUT_V1.field_names},
        "rho_t": c.rho_t,
    }


def test_golden_vectors_are_stable():
    """Same semantic object -> same bytes, leaf hashes and root (pinned on disk)."""
    current = _vector_payload()
    assert VECTORS.exists(), "generate with: python scripts/dvas/make_test_vectors.py"
    pinned = json.loads(VECTORS.read_text())
    assert current == pinned


def test_determinism_under_insertion_order():
    base = sample_layout()
    roots = set()
    rng = random.Random(7)  # seeds only the test-case permutation
    for _ in range(20):
        items = list(base.items())
        rng.shuffle(items)
        roots.add(commit(dict(items)).rho_t)
    assert len(roots) == 1
    r = sample_public_receipt()
    b1 = encode_record(REGISTRY, PUBLIC_RECEIPT, r)
    b2 = encode_record(REGISTRY, PUBLIC_RECEIPT, dict(reversed(list(r.items()))))
    assert b1 == b2


def test_ordering_change_in_wire_is_rejected():
    b = bytearray(encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt()))
    # swap the first two field ids in place -> not strictly ascending
    off = 7 + 5
    fid1 = bytes(b[off:off + 2])
    ln1 = int.from_bytes(b[off + 3:off + 7], "big")
    off2 = off + 7 + ln1
    b[off:off + 2], b[off2:off2 + 2] = b[off2:off2 + 2], fid1
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, bytes(b))


def test_round_trip():
    r = sample_public_receipt()
    dec = decode_record(REGISTRY, PUBLIC_RECEIPT, encode_record(REGISTRY, PUBLIC_RECEIPT, r))
    assert dec == r


@pytest.mark.parametrize("bad", [True, "five", 5.0000001, float("nan"), None, b"5"])
def test_type_ambiguity_fixed6_rejected(bad):
    spec = REGISTRY.spec("cap_kwh")
    with pytest.raises(EncodingError):
        encode_field(spec, bad)


def test_fixed6_equivalent_representations_and_explicit_rounding():
    spec = REGISTRY.spec("cap_kwh")
    assert encode_field(spec, 5) == encode_field(spec, Decimal("5")) == encode_field(spec, "5.000000") == encode_field(spec, 5.0)
    assert to_fixed6(8.49089254366486) == Decimal("8.490893")
    assert to_fixed6("0.0000005") == Decimal("0.000000")  # half-even
    assert to_fixed6("0.0000015") == Decimal("0.000002")


@pytest.mark.parametrize("name,bad", [("meter_key_epoch", True), ("meter_key_epoch", "1"), ("meter_key_epoch", -1),
                                      ("sid", 5), ("tariff_mode", "energy_only"), ("h_priv", "ab"), ("rho_t", b"x" * 31)])
def test_type_ambiguity_other_types(name, bad):
    with pytest.raises(EncodingError):
        encode_field(REGISTRY.spec(name), bad)


def test_type_tag_mismatch_rejected_on_decode():
    b = bytearray(encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt()))
    b[7 + 5 + 2] = int(TypeTag.BYTES)  # retag first field
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, bytes(b))


def test_timestamp_ambiguity():
    spec = REGISTRY.spec("tw_start")
    with pytest.raises(EncodingError):
        encode_field(spec, datetime(2019, 10, 14, 3, 58, 48))  # naive
    with pytest.raises(EncodingError):
        encode_field(spec, "2019-10-14T03:58:48+00:00")
    utc = datetime(2019, 10, 14, 3, 58, 48, tzinfo=timezone.utc)
    kst = utc.astimezone(timezone(timedelta(hours=9)))
    assert encode_field(spec, utc) == encode_field(spec, kst) == encode_field(spec, int(utc.timestamp()))


def test_string_normalisation_and_utf8():
    spec = REGISTRY.spec("station_id")
    with pytest.raises(EncodingError):
        encode_field(spec, "Café")  # NFD form rejected, not silently normalised
    assert encode_field(spec, "Café").endswith("Café".encode("utf-8"))


def test_wrong_field_id():
    c = commit(sample_layout())
    # same value hashed as a different field id gives a different leaf
    assert leaf_hash(LAYOUT_V1, "station_id", "X") != leaf_hash(LAYOUT_V1, "meter_id", "X")
    b = bytearray(encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt()))
    b[7 + 5:7 + 5 + 2] = (0x0999).to_bytes(2, "big")
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, bytes(b))
    assert c.rho_t


def test_serialization_mismatch_trailing_and_truncated():
    b = encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt())
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, b + b"\x00")
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, b[:-3])
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PRIVATE_RECEIPT, b)  # wrong record type
    with pytest.raises(EncodingError):
        encode_record(REGISTRY, PUBLIC_RECEIPT, {**sample_public_receipt(), "cap_kwh": Decimal(1)})  # undeclared
    r = sample_public_receipt()
    r.pop("nonce_m")
    with pytest.raises(EncodingError):
        encode_record(REGISTRY, PUBLIC_RECEIPT, r)  # missing


def test_legacy_json_float_ambiguity_is_removed():
    """Legacy canonical JSON encodes floats as '%.12g'; distinct values can collide.
    The new encoder either encodes them exactly or rejects them."""
    from dbas_et.crypto import canonical_dumps

    a, b = 0.1234567890123, 0.1234567890124
    assert canonical_dumps({"v": a}) == canonical_dumps({"v": b})  # legacy collision
    spec = REGISTRY.spec("cap_kwh")
    with pytest.raises(EncodingError):
        encode_field(spec, a)  # more than 6 decimals: must be normalised explicitly
    assert encode_field(spec, to_fixed6(a)) == encode_field(spec, to_fixed6(b))  # explicit, documented rounding


def test_version_mismatch():
    b = bytearray(encode_record(REGISTRY, PUBLIC_RECEIPT, sample_public_receipt()))
    b[7] = ENCODING_VERSION + 1
    with pytest.raises(EncodingError):
        decode_record(REGISTRY, PUBLIC_RECEIPT, bytes(b))
    c1 = commit(sample_layout())
    other = LayoutSchema("dvas-ev-layout-v1-alt", LAYOUT_V1.field_names)
    c2 = commit(sample_layout(), schema=other)
    assert c1.rho_t != c2.rho_t  # schema id bound into the root
    op = open_for_reason(c2, "settlement")
    assert verify_opening(c1.rho_t, op, reason="settlement").code == "SCHEMA_MISMATCH"


def test_lifecycle_post_service_cannot_enter_commitment():
    vals = sample_layout()
    with pytest.raises(EncodingError, match="post-service"):
        commit({**vals, "delivered_kwh": Decimal("3")})
    with pytest.raises(EncodingError):
        commit({**vals, "captured_amount": Decimal("1")})
    with pytest.raises(ValueError):
        LayoutSchema("bad", LAYOUT_V1.field_names + ("delivered_kwh",))
    lifecycles = {REGISTRY.spec(n).lifecycle for n in LAYOUT_V1.field_names}
    assert lifecycles == {Lifecycle.PRE_SERVICE_COMMITTED}
    assert REGISTRY.spec("delivered_kwh").lifecycle == Lifecycle.POST_SERVICE_EVIDENCE
    assert REGISTRY.spec("captured_amount").lifecycle == Lifecycle.SETTLEMENT_OUTPUT


def test_record_lifecycle_restrictions():
    from dbas_et.dvas.canonical import RecordType

    rt = RecordType(0x7777, "only_pre", ("tid",), frozenset({Lifecycle.POST_SERVICE_EVIDENCE}))
    with pytest.raises(EncodingError):
        encode_record(REGISTRY, rt, {"tid": "x"})


def test_field_spec_validation():
    with pytest.raises(ValueError):
        FieldSpec(0, "x", TypeTag.UINT, Lifecycle.PRE_SERVICE_COMMITTED)
    with pytest.raises(ValueError):
        FieldSpec(1, "x", TypeTag.ENUM, Lifecycle.PRE_SERVICE_COMMITTED)
