from __future__ import annotations


def _dbas_truthy_bool(v):
    """Bool parser for Python bool, numpy.bool_, pandas bool, int and string."""
    if v is True:
        return True
    if v is False or v is None:
        return False

    try:
        # NaN check without importing pandas.
        if v != v:
            return False
    except Exception:
        pass

    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes", "y", "t"}

    try:
        return bool(v)
    except Exception:
        return False


import csv
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dbas_et.capsule import (  # noqa: E402
    CanonicalCapsule,
    build_payment_token,
    build_trade_id,
    capsule_to_semantic_layout,
)
from dbas_et.contracts import AuthSC, DisputeSC, RegSC, SettleSC  # noqa: E402
from dbas_et.entities import (  # noqa: E402
    Meter,
    Station,
    User,
    create_meter,
    create_station,
    create_user,
    create_validator,
)
from dbas_et.payments import (  # noqa: E402
    build_delivery_receipt,
    build_session_id,
    make_topup_event,
)
from dbas_et.projections import V2SlimSettlementBackend, proof_bytesize  # noqa: E402
from dbas_et.result import RejectReason  # noqa: E402
from dbas_et.station_hybrid_auth import issue_station_session_binding_certificate  # noqa: E402


ProcessedFlow = Literal["valid", "original_cap", "topup"]

MONEY_TOLERANCE = 1e-5


@dataclass
class BenchmarkConfig:
    """Benchmark configuration shared by all DBAS-ET runners."""

    input_csv: Path
    output_prefix: str
    max_rows: int | None = None
    pq_backend: str = "oqs"
    kem_backend: str = "oqs"
    strict_pq: bool = True
    progress_every: int = 500


@dataclass
class BenchmarkEnvironment:
    """Shared benchmark environment with registered entities and contract state."""

    regsc: RegSC
    authsc: AuthSC
    settlesc: SettleSC
    disputesc: DisputeSC
    backend: V2SlimSettlementBackend
    users: dict[str, User]
    stations: dict[str, Station]
    meters: dict[str, Meter]


def project_root() -> Path:
    return PROJECT_ROOT


def ensure_output_dirs() -> tuple[Path, Path, Path]:
    """Create stable output folders."""
    tables_dir = PROJECT_ROOT / "outputs" / "tables"
    traces_dir = PROJECT_ROOT / "outputs" / "traces"
    figures_dir = PROJECT_ROOT / "outputs" / "figures"

    tables_dir.mkdir(parents=True, exist_ok=True)
    traces_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    return tables_dir, traces_dir, figures_dir


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write rows to CSV with stable union schema."""
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        raise ValueError(f"cannot write empty CSV: {path}")

    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write JSONL rows."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def load_profile_csv(path: Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load benchmark profile CSV."""
    if not path.exists():
        raise FileNotFoundError(f"profile CSV not found: {path}")

    df = pd.read_csv(path)

    if df.empty:
        raise ValueError(f"profile CSV is empty: {path}")

    if max_rows is not None:
        df = df.head(max_rows).copy()

    df = df.reset_index(drop=True)
    return df


def _safe_float(row: pd.Series, key: str, default: float = 0.0) -> float:
    try:
        value = row.get(key, default)
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(row: pd.Series, key: str, default: int = 0) -> int:
    try:
        value = row.get(key, default)
        if pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def _safe_str(row: pd.Series, key: str, default: str = "") -> str:
    value = row.get(key, default)
    if value is None or pd.isna(value):
        return default
    return str(value)


def _safe_bool(value: Any) -> bool:
    """Bool parsing for pandas/CSV values."""
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    try:
        if pd.isna(value):
            return False
    except Exception:
        pass

    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    return text in {"true", "1", "yes", "y", "t"}


def build_benchmark_environment(
    df: pd.DataFrame,
    pq_backend: str = "oqs",
    kem_backend: str = "oqs",
    strict_pq: bool = True,
) -> BenchmarkEnvironment:
    """
    Build and register all users, stations, meters, and one validator.

    Keys are generated once per unique protocol ID and reused across rows.
    """
    regsc = RegSC()
    authsc = AuthSC(regsc)
    settlesc = SettleSC(regsc, authsc)
    disputesc = DisputeSC()
    backend = V2SlimSettlementBackend()

    users: dict[str, User] = {}
    stations: dict[str, Station] = {}
    meters: dict[str, Meter] = {}

    for _, row in df.iterrows():
        user_id = _safe_str(row, "protocol_user_id", "U_UNKNOWN")
        station_id = _safe_str(row, "protocol_station_id", "S_UNKNOWN")
        meter_id = _safe_str(row, "protocol_meter_id", "M_UNKNOWN")
        home_domain = _safe_str(row, "home_domain", "OH_ACN")
        foreign_domain = _safe_str(row, "foreign_domain", "OF_ACN")

        if user_id not in users:
            user = create_user(
                user_id=user_id,
                balance=1_000_000.0,
                home_domain=home_domain,
                pq_backend=pq_backend,
                pq_algorithm="ML-DSA-65",
                strict_pq=strict_pq,
            )
            users[user_id] = user
            regsc.register_user(user)

        if station_id not in stations:
            station = create_station(
                station_id=station_id,
                foreign_domain=foreign_domain,
                sig_backend=pq_backend,
                sig_algorithm="ML-DSA-65",
                kem_backend=kem_backend,
                kem_algorithm="ML-KEM-768",
                strict_pq=strict_pq,
            )
            stations[station_id] = station
            regsc.register_station(station)

        if meter_id not in meters:
            meter = create_meter(
                meter_id=meter_id,
                station_id=station_id,
                foreign_domain=foreign_domain,
            )
            meters[meter_id] = meter
            regsc.register_meter(meter)

    validator = create_validator("V_BENCHMARK")
    regsc.register_validator(validator)

    return BenchmarkEnvironment(
        regsc=regsc,
        authsc=authsc,
        settlesc=settlesc,
        disputesc=disputesc,
        backend=backend,
        users=users,
        stations=stations,
        meters=meters,
    )


def capsule_from_workload_row(
    row: pd.Series,
    user: User,
    station: Station,
    meter: Meter,
    row_index: int,
) -> CanonicalCapsule:
    """Build CanonicalCapsule from one normalized ACN workload row."""
    nonce_u = f"acn-user-{row_index}-{_safe_str(row, 'source_session_id', '')}"
    nonce_s = f"acn-station-{row_index}-{_safe_str(row, 'source_station_id', '')}"

    trade_id = build_trade_id(
        user_id=user.user_id,
        station_id=station.station_id,
        meter_id=meter.meter_id,
        nonce_u=nonce_u,
        nonce_s=nonce_s,
    )

    paytok_t = build_payment_token(
        trade_id=trade_id,
        user_address=user.address,
        station_id=station.station_id,
    )

    return CanonicalCapsule(
        trade_id=trade_id,
        user_id=user.user_id,
        user_address=user.address,
        home_domain=_safe_str(row, "home_domain", user.home_domain),
        station_id=station.station_id,
        meter_id=meter.meter_id,
        foreign_domain=station.foreign_domain,
        beneficiary=station.beneficiary,
        tariff_id=_safe_str(row, "tariff_id", "UNKNOWN_TARIFF"),
        tariff_version=_safe_str(row, "tariff_version", "v1"),
        unit_price=_safe_float(row, "unit_price", 0.0),
        tariff_mode=_safe_str(row, "tariff_mode", "ENERGY_ONLY"),
        requested_kwh=_safe_float(row, "requested_kwh", 0.0),
        cap_kwh=_safe_float(row, "cap_kwh", 0.0),
        preauth_limit_t=_safe_float(row, "preauth_limit_t", 0.0),
        tw_start=_safe_int(row, "tw_start", 0),
        tw_end=_safe_int(row, "tw_end", 0),
        paytok_t=paytok_t,
        nonce_u=nonce_u,
        nonce_s=nonce_s,
        created_at=_safe_int(row, "tw_start", 0),
        metadata={
            "source": "ACN-Data",
            "source_session_id": _safe_str(row, "source_session_id", ""),
            "source_site_id": _safe_str(row, "source_site_id", ""),
            "profile": _safe_str(row, "profile", ""),
            "tariff_note": _safe_str(row, "tariff_source", ""),
            "payment_semantics": "preauthorized_limit_not_captured_payment",
        },
    )


def run_one_workload_row(
    env: BenchmarkEnvironment,
    row: pd.Series,
    row_index: int,
    flow: ProcessedFlow,
    apply_topup: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Run one ACN row through authorization -> receipt -> settlement.

    Returns per-row result and trace rows.
    """
    start = time.perf_counter()

    trace: list[dict[str, Any]] = []
    row_record: dict[str, Any] = {
        "flow": flow,
        "row_index": int(row_index),
        "source_session_id": _safe_str(row, "source_session_id", ""),
        "source_site_id": _safe_str(row, "source_site_id", ""),
        "status": "unknown",
        "error": "",
    }

    try:
        user_id = _safe_str(row, "protocol_user_id", "U_UNKNOWN")
        station_id = _safe_str(row, "protocol_station_id", "S_UNKNOWN")
        meter_id = _safe_str(row, "protocol_meter_id", "M_UNKNOWN")

        user = env.users[user_id]
        station = env.stations[station_id]
        meter = env.meters[meter_id]

        capsule = capsule_from_workload_row(row, user, station, meter, row_index)

        layout = capsule_to_semantic_layout(capsule)
        artifact = env.backend.commit_layout(layout)

        A_view, A_proof = env.backend.open_projection(artifact, "A")
        S_view, S_proof = env.backend.open_projection(artifact, "S")

        auth_t0 = time.perf_counter()
        auth = env.authsc.authorize_trade(
            user=user,
            capsule=capsule,
            rho_t=artifact.rho_t,
            A_view=A_view,
            A_proof=A_proof,
            backend=env.backend,
        )
        auth_ms = (time.perf_counter() - auth_t0) * 1000.0

        trace.append(
            {
                "row_index": row_index,
                "flow": flow,
                "event": "authorize_trade",
                "ok": auth.ok,
                "status": str(auth.status),
                "reason": auth.reason,
                "latency_ms": round(auth_ms, 6),
                "trade_id": capsule.trade_id,
            }
        )

        if not auth.ok:
            row_record.update(
                {
                    "status": "auth_rejected",
                    "settlement_ok": False,
                    "settlement_reason": auth.reason,
                    "trade_id": capsule.trade_id,
                    "rho_t": artifact.rho_t,
                }
            )
            return row_record, trace

        sid_t = build_session_id(capsule, nonce=f"sid-{flow}-{row_index}")

        station_cert = issue_station_session_binding_certificate(
            station=station,
            trade_id=capsule.trade_id,
            rho_t=artifact.rho_t,
            sid_t=sid_t,
            meter_id=meter.meter_id,
            nonce_s=f"sid-{flow}-{row_index}",
        )

        sess_t0 = time.perf_counter()
        open_session = env.settlesc.open_session(
            capsule.trade_id,
            sid_t,
            nonce_s=f"sid-{flow}-{row_index}",
            station_cert=station_cert,
        )
        open_session_ms = (time.perf_counter() - sess_t0) * 1000.0

        trace.append(
            {
                "row_index": row_index,
                "flow": flow,
                "event": "open_session",
                "ok": open_session.ok,
                "status": str(open_session.status),
                "reason": open_session.reason,
                "latency_ms": round(open_session_ms, 6),
                "trade_id": capsule.trade_id,
            }
        )

        if not open_session.ok:
            row_record.update(
                {
                    "status": "session_rejected",
                    "settlement_ok": False,
                    "settlement_reason": open_session.reason,
                    "trade_id": capsule.trade_id,
                    "rho_t": artifact.rho_t,
                }
            )
            return row_record, trace

        receipt = build_delivery_receipt(
            capsule=capsule,
            sid_t=sid_t,
            meter=meter,
            delivered_kwh=_safe_float(row, "delivered_kwh", 0.0),
            ts_start=_safe_int(row, "tw_start", 0),
            ts_end=_safe_int(row, "tw_end", 0),
            tariff_id=_safe_str(row, "tariff_id", capsule.tariff_id),
            tariff_version=_safe_str(row, "tariff_version", capsule.tariff_version),
            tariff_mode=_safe_str(row, "tariff_mode", capsule.tariff_mode),
            connection_duration_s=_safe_int(row, "connection_duration_s", 0),
            active_charging_duration_s=_safe_int(row, "active_charging_duration_s", 0),
            parking_duration_s=_safe_int(row, "parking_duration_s", 0),
            nonce_m=f"meter-{flow}-{row_index}",
        )

        receipt_t0 = time.perf_counter()
        submit = env.settlesc.submit_receipt(receipt)
        submit_receipt_ms = (time.perf_counter() - receipt_t0) * 1000.0

        trace.append(
            {
                "row_index": row_index,
                "flow": flow,
                "event": "submit_receipt",
                "ok": submit.ok,
                "status": str(submit.status),
                "reason": submit.reason,
                "latency_ms": round(submit_receipt_ms, 6),
                "trade_id": capsule.trade_id,
            }
        )

        if not submit.ok:
            row_record.update(
                {
                    "status": "receipt_rejected",
                    "settlement_ok": False,
                    "settlement_reason": submit.reason,
                    "trade_id": capsule.trade_id,
                    "rho_t": artifact.rho_t,
                }
            )
            return row_record, trace

        topup_ok: bool | None = None
        topup_delta = 0.0
        rho_unchanged_after_topup: bool | None = None

        if apply_topup:
            old_limit = env.authsc.records[capsule.trade_id].effective_preauth_limit_t
            topup_delta = _safe_float(row, "topup_delta_recommended", 0.0)

            if topup_delta <= 0:
                expected_amount = _safe_float(row, "expected_amount", 0.0)
                topup_delta = max(0.0, expected_amount * 1.10 - old_limit)

            topup_t0 = time.perf_counter()
            topup_event = make_topup_event(
                user=user,
                trade_id=capsule.trade_id,
                rho_t=artifact.rho_t,
                sid_t=sid_t,
                old_limit=old_limit,
                delta_limit=topup_delta,
                reason="cover_final_metered_amount",
            )
            topup = env.authsc.apply_topup(user, topup_event)
            topup_ms = (time.perf_counter() - topup_t0) * 1000.0

            rho_unchanged_after_topup = (
                env.authsc.records[capsule.trade_id].rho_t == artifact.rho_t
            )
            topup_ok = topup.ok

            trace.append(
                {
                    "row_index": row_index,
                    "flow": flow,
                    "event": "apply_topup",
                    "ok": topup.ok,
                    "status": str(topup.status),
                    "reason": topup.reason,
                    "latency_ms": round(topup_ms, 6),
                    "trade_id": capsule.trade_id,
                    "topup_delta": round(float(topup_delta), 6),
                    "rho_unchanged_after_topup": rho_unchanged_after_topup,
                }
            )

            if not topup.ok:
                row_record.update(
                    {
                        "status": "topup_rejected",
                        "settlement_ok": False,
                        "settlement_reason": topup.reason,
                        "trade_id": capsule.trade_id,
                        "rho_t": artifact.rho_t,
                    }
                )
                return row_record, trace

        settle_t0 = time.perf_counter()
        settle = env.settlesc.release_settlement(
            capsule=capsule,
            rho_t=artifact.rho_t,
            S_view=S_view,
            S_proof=S_proof,
            backend=env.backend,
            user=user,
        )
        settle_ms = (time.perf_counter() - settle_t0) * 1000.0

        trace.append(
            {
                "row_index": row_index,
                "flow": flow,
                "event": "release_settlement",
                "ok": settle.ok,
                "status": str(settle.status),
                "reason": settle.reason,
                "latency_ms": round(settle_ms, 6),
                "trade_id": capsule.trade_id,
            }
        )

        expected_amount = _safe_float(row, "expected_amount", 0.0)
        expected_undercap = _safe_bool(row.get("is_undercap_original", False))

        captured_amount = None
        released_unused_hold = None
        held_amount_after = None
        amount_abs_error = None

        if settle.ok and settle.value is not None:
            captured_amount = float(settle.value.captured_amount)
            released_unused_hold = float(settle.value.released_unused_hold)
            held_amount_after = float(settle.value.held_amount_after)
            amount_abs_error = round(abs(captured_amount - expected_amount), 6)

        record = env.authsc.records.get(capsule.trade_id)

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        row_record.update(
            {
                "status": "settled" if settle.ok else "blocked_or_rejected",
                "trade_id": capsule.trade_id,
                "rho_t": artifact.rho_t,
                "settlement_ok": settle.ok,
                "settlement_status": str(settle.status),
                "settlement_reason": settle.reason,
                "expected_undercap_original": expected_undercap,
                "preauth_limit_t": float(capsule.preauth_limit_t),
                "effective_preauth_limit_t": (
                    float(record.effective_preauth_limit_t) if record else None
                ),
                "held_amount_after": (
                    held_amount_after
                    if held_amount_after is not None
                    else (float(record.held_amount) if record else None)
                ),
                "expected_amount": expected_amount,
                "captured_amount": captured_amount,
                "released_unused_hold": released_unused_hold,
                "amount_abs_error": amount_abs_error,
                "amount_abs_error_within_tolerance": (
                    True if amount_abs_error is not None and amount_abs_error <= MONEY_TOLERANCE else None
                ),
                "delivered_kwh": _safe_float(row, "delivered_kwh", 0.0),
                "tariff_mode": _safe_str(row, "tariff_mode", ""),
                "proof_A_bytes": proof_bytesize(A_proof.to_record()),
                "proof_S_bytes": proof_bytesize(S_proof.to_record()),
                "authorize_ms": round(auth_ms, 6),
                "submit_receipt_ms": round(submit_receipt_ms, 6),
                "settle_ms": round(settle_ms, 6),
                "end_to_end_ms": round(elapsed_ms, 6),
                "topup_enabled": bool(apply_topup),
                "topup_ok": topup_ok,
                "topup_delta": round(float(topup_delta), 6),
                "rho_unchanged_after_topup": rho_unchanged_after_topup,
            }
        )

        return row_record, trace

    except Exception as exc:
        row_record.update(
            {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "settlement_ok": False,
            }
        )
        trace.append(
            {
                "row_index": row_index,
                "flow": flow,
                "event": "exception",
                "ok": False,
                "error": row_record["error"],
            }
        )
        return row_record, trace


def run_profile_benchmark(
    config: BenchmarkConfig,
    flow: ProcessedFlow,
    apply_topup: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Run a full benchmark profile."""
    df = load_profile_csv(config.input_csv, max_rows=config.max_rows)

    env = build_benchmark_environment(
        df,
        pq_backend=config.pq_backend,
        kem_backend=config.kem_backend,
        strict_pq=config.strict_pq,
    )

    results: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []

    started = time.perf_counter()

    for idx, row in df.iterrows():
        if config.progress_every and idx > 0 and idx % config.progress_every == 0:
            print(f"[{flow}] processed {idx}/{len(df)} rows")

        result, trace = run_one_workload_row(
            env=env,
            row=row,
            row_index=int(idx),
            flow=flow,
            apply_topup=apply_topup,
        )
        results.append(result)
        traces.extend(trace)

    elapsed_s = time.perf_counter() - started
    summary = summarize_results(results, flow, config, elapsed_s)

    return results, traces, summary


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return float((s[mid - 1] + s[mid]) / 2.0)


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = int(round((len(s) - 1) * q))
    idx = max(0, min(idx, len(s) - 1))
    return float(s[idx])


def _num(value: Any) -> float | None:
    try:
        if value is None or pd.isna(value):
            return None
        return float(value)
    except Exception:
        return None


def summarize_results(
    results: list[dict[str, Any]],
    flow: str,
    config: BenchmarkConfig,
    elapsed_s: float,
) -> dict[str, Any]:
    """Build stable benchmark summary."""
    n = len(results)
    settled = sum(1 for r in results if _dbas_truthy_bool(r.get("settlement_ok")))
    blocked_or_rejected = sum(
        1 for r in results
        if r.get("settlement_ok") is False and r.get("status") != "error"
    )
    errors = sum(1 for r in results if r.get("status") == "error")

    amount_errors = [
        v for v in (_num(r.get("amount_abs_error")) for r in results)
        if v is not None
    ]

    auth_ms = [
        v for v in (_num(r.get("authorize_ms")) for r in results)
        if v is not None
    ]
    receipt_ms = [
        v for v in (_num(r.get("submit_receipt_ms")) for r in results)
        if v is not None
    ]
    settle_ms = [
        v for v in (_num(r.get("settle_ms")) for r in results)
        if v is not None
    ]
    e2e_ms = [
        v for v in (_num(r.get("end_to_end_ms")) for r in results)
        if v is not None
    ]

    proof_a = [
        v for v in (_num(r.get("proof_A_bytes")) for r in results)
        if v is not None
    ]
    proof_s = [
        v for v in (_num(r.get("proof_S_bytes")) for r in results)
        if v is not None
    ]

    expected_undercap = sum(1 for r in results if _dbas_truthy_bool(r.get("expected_undercap_original")))

    blocked_by_preauth = sum(
        1 for r in results
        if str(r.get("settlement_reason", "")) == str(RejectReason.AMOUNT_EXCEEDS_PREAUTH_LIMIT)
        or str(r.get("settlement_reason", "")) == "amount_exceeds_preauth_limit"
    )

    unexpected_preauth_block_non_undercap = sum(
        1 for r in results
        if (
            str(r.get("settlement_reason", "")) in {
                str(RejectReason.AMOUNT_EXCEEDS_PREAUTH_LIMIT),
                "amount_exceeds_preauth_limit",
            }
            and not _dbas_truthy_bool(r.get("expected_undercap_original"))
        )
    )

    undercap_settled_without_topup = sum(
        1 for r in results
        if _dbas_truthy_bool(r.get("expected_undercap_original")) and _dbas_truthy_bool(r.get("settlement_ok")) and not _dbas_truthy_bool(r.get("topup_enabled"))
    )

    topup_enabled_count = sum(1 for r in results if _dbas_truthy_bool(r.get("topup_enabled")))
    topup_ok_count = sum(1 for r in results if _dbas_truthy_bool(r.get("topup_enabled")) and _dbas_truthy_bool(r.get("topup_ok")))
    rho_unchanged_count = sum(
        1 for r in results
        if _dbas_truthy_bool(r.get("topup_enabled")) and _dbas_truthy_bool(r.get("rho_unchanged_after_topup"))
    )

    max_amount_abs_error = max(amount_errors) if amount_errors else 0.0
    max_amount_abs_error_within_tolerance = max_amount_abs_error <= MONEY_TOLERANCE

    return {
        "benchmark": flow,
        "input_csv": str(config.input_csv),
        "rows": n,
        "settled": settled,
        "blocked_or_rejected": blocked_or_rejected,
        "errors": errors,
        "expected_undercap_original": expected_undercap,
        "amount_exceeds_preauth_limit": blocked_by_preauth,
        "unexpected_preauth_block_non_undercap": unexpected_preauth_block_non_undercap,
        "undercap_settled_without_topup": undercap_settled_without_topup,
        "all_settled": settled == n and errors == 0,
        "max_amount_abs_error": round(float(max_amount_abs_error), 6),
        "money_tolerance": MONEY_TOLERANCE,
        "max_amount_abs_error_within_tolerance": bool(max_amount_abs_error_within_tolerance),
        "median_authorize_ms": round(_median(auth_ms), 6),
        "p95_authorize_ms": round(_quantile(auth_ms, 0.95), 6),
        "median_submit_receipt_ms": round(_median(receipt_ms), 6),
        "p95_submit_receipt_ms": round(_quantile(receipt_ms, 0.95), 6),
        "median_settle_ms": round(_median(settle_ms), 6),
        "p95_settle_ms": round(_quantile(settle_ms, 0.95), 6),
        "median_end_to_end_ms": round(_median(e2e_ms), 6),
        "p95_end_to_end_ms": round(_quantile(e2e_ms, 0.95), 6),
        "median_proof_A_bytes": round(_median(proof_a), 6),
        "median_proof_S_bytes": round(_median(proof_s), 6),
        "topup_enabled_count": topup_enabled_count,
        "topup_ok_count": topup_ok_count,
        "rho_unchanged_after_topup_count": rho_unchanged_count,
        "elapsed_s": round(float(elapsed_s), 6),
        "throughput_rows_per_s": round(float(n / elapsed_s), 6) if elapsed_s > 0 else 0.0,
        "simulator_scope": "single_workstation_acn_driven_protocol_state_simulator",
        "simulator_not_claimed_as": "production_ev_backend_or_full_ocpp_ocpi_or_network_simulator",
        "payment_semantics": "preauthorized_limit_not_captured_payment",
        "projection_security_claim": "simulated commitment-opening proof; not ZK/Verkle/KZG/PCS",
        "tariff_note": "deterministic_protocol_tariff_not_acn_billing",
    }


def write_benchmark_outputs(
    output_prefix: str,
    results: list[dict[str, Any]],
    traces: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, str]:
    """Write per-row results, traces, and summary."""
    tables_dir, traces_dir, _ = ensure_output_dirs()

    results_path = tables_dir / f"{output_prefix}_results.csv"
    summary_path = tables_dir / f"{output_prefix}_summary.csv"
    trace_path = traces_dir / f"{output_prefix}_trace.jsonl"

    write_csv(results_path, results)
    write_csv(summary_path, [summary])
    write_jsonl(trace_path, traces)

    return {
        "results_path": str(results_path),
        "summary_path": str(summary_path),
        "trace_path": str(trace_path),
    }