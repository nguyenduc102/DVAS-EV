#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def _bool_series(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s
    return s.astype(str).str.lower().isin(["true", "1", "yes", "y"])


def fix_one(df: pd.DataFrame, *, policy: str) -> pd.DataFrame:
    out = df.copy()

    if "delivered_kwh" not in out.columns and "kWhDelivered" in out.columns:
        out["delivered_kwh"] = pd.to_numeric(out["kWhDelivered"], errors="coerce")

    if "kWhDelivered" not in out.columns and "delivered_kwh" in out.columns:
        out["kWhDelivered"] = pd.to_numeric(out["delivered_kwh"], errors="coerce")

    out["delivered_kwh"] = pd.to_numeric(out["delivered_kwh"], errors="coerce")
    out["kWhDelivered"] = pd.to_numeric(out["kWhDelivered"], errors="coerce")

    if "unit_price" not in out.columns:
        raise ValueError("Missing unit_price in MFEV input")

    old_unit_price = pd.to_numeric(out["unit_price"], errors="coerce")
    old_amount = pd.to_numeric(out.get("amount", np.nan), errors="coerce")

    # Keep a copy for audit/paper explanation.
    out["mfev_original_unit_price"] = old_unit_price
    out["mfev_original_amount"] = old_amount

    # Normalize money scale for the existing ACN-style simulator.
    # Example: 320 KRW-like/kWh -> 0.320 protocol-token/kWh.
    if old_unit_price.median() > 10:
        out["unit_price"] = (old_unit_price / 1000.0).round(9)
        out["monetary_scale_fix"] = "unit_price_div_1000"
    else:
        out["unit_price"] = old_unit_price.round(9)
        out["monetary_scale_fix"] = "none"

    # Current payment code does not support off_peak/mid_peak/on_peak.
    # Treat each row as a flat per-session tariff snapshot.
    out["tariff_mode_raw_mfev"] = out.get("tariff_mode", "unknown")
    out["tariff_mode"] = "ENERGY_ONLY"

    # Recompute amount using normalized protocol tariff.
    out["amount"] = (out["delivered_kwh"] * out["unit_price"]).round(9)
    out["expected_amount"] = out["amount"]
    out["estimated_amount"] = out["amount"]
    out["captured_amount"] = out["amount"]
    out["settlement_amount"] = out["amount"]
    out["total_cost"] = out["amount"]

    # Preserve original undercap mask.
    if "is_undercap_case" in out.columns:
        undercap = _bool_series(out["is_undercap_case"])
    else:
        undercap = pd.Series(False, index=out.index)

    # Recompute preauth limits under normalized scale.
    out["preauth_limit_valid"] = (out["amount"] * 1.10).round(9)

    out["preauth_limit_original"] = out["amount"].copy()
    if undercap.any():
        # Use deterministic undercap ratio. This keeps original-cap cases blocked
        # but allows top-up to settle them later.
        ratio = 0.85
        out.loc[undercap, "preauth_limit_original"] = (
            out.loc[undercap, "amount"] * ratio
        ).round(9)

    if policy == "valid":
        out["preauth_limit_t"] = out["preauth_limit_valid"]
    elif policy == "original_cap":
        out["preauth_limit_t"] = out["preauth_limit_original"]
    elif policy == "topup_cases":
        out["preauth_limit_t"] = out["preauth_limit_original"]
        out = out[undercap].copy()
    else:
        raise ValueError(f"Unknown policy: {policy}")

    # Add common aliases used by older ACN-specific code.
    alias_cols = [
        "preauth_limit",
        "preauthorized_limit",
        "allowcap_t",
        "allowCap_t",
        "allow_cap",
        "effective_limit",
        "held_amount",
        "reserved_amount",
        "wallet_hold",
    ]
    for c in alias_cols:
        out[c] = out["preauth_limit_t"]

    # Make balance safely larger than preauth. If the runner reads row balance,
    # this prevents insufficient_balance. If it uses a default balance, the
    # normalized amount is now also small enough.
    safe_balance = max(float(out["preauth_limit_valid"].max()) * 100.0, 1_000_000.0)
    for c in [
        "user_balance",
        "wallet_balance",
        "balance",
        "initial_balance",
        "payer_balance",
    ]:
        out[c] = safe_balance

    # More aliases for energy and time.
    out["energy_kwh"] = out["delivered_kwh"]
    out["requested_energy_kwh"] = pd.to_numeric(
        out.get("requested_kwh", out["delivered_kwh"]),
        errors="coerce",
    )

    if "cap_kwh" not in out.columns:
        out["cap_kwh"] = out["delivered_kwh"] * 1.05

    out["energy_cap_kwh"] = pd.to_numeric(out["cap_kwh"], errors="coerce")
    out["energy_cap"] = out["energy_cap_kwh"]
    out["max_kwh"] = out["energy_cap_kwh"]

    if "connectionTime" not in out.columns and "start_ts" in out.columns:
        out["connectionTime"] = out["start_ts"]
    if "disconnectTime" not in out.columns and "end_ts" in out.columns:
        out["disconnectTime"] = out["end_ts"]
    if "doneChargingTime" not in out.columns and "end_ts" in out.columns:
        out["doneChargingTime"] = out["end_ts"]

    out["start_time"] = out.get("start_ts", out.get("connectionTime"))
    out["end_time"] = out.get("end_ts", out.get("disconnectTime"))
    out["ts_start"] = out["start_time"]
    out["ts_end"] = out["end_time"]

    if "tw_start" not in out.columns:
        out["tw_start"] = out["connectionTime"]
    if "tw_end" not in out.columns:
        out["tw_end"] = out["disconnectTime"]

    out["time_window_start"] = out["tw_start"]
    out["time_window_end"] = out["tw_end"]

    # Identity aliases.
    if "station_id" in out.columns:
        out["stationID"] = out["station_id"]
        out["spaceID"] = out["station_id"]
        out["EVSEID"] = out["station_id"]
        out["evse_id"] = out["station_id"]

    if "meter_id" not in out.columns and "station_id" in out.columns:
        out["meter_id"] = "M_" + out["station_id"].astype(str)

    if "session_id" not in out.columns and "source_session_id" in out.columns:
        out["session_id"] = out["source_session_id"]

    if "trade_id" not in out.columns:
        out["trade_id"] = "T_MFEV_" + out["session_id"].astype(str)

    # Tariff aliases.
    out["price_per_kwh"] = out["unit_price"]
    out["tariff_price"] = out["unit_price"]
    out["tariff_unit_price"] = out["unit_price"]

    if "tariff_id" not in out.columns:
        out["tariff_id"] = "TAR_MFEV_FLAT"
    if "tariff_version" not in out.columns:
        out["tariff_version"] = "mfev_flat_v1"

    out["currency"] = "DBAS_TOKEN"
    out["benchmark_policy"] = policy
    out["mfev_runner_fixed"] = True

    out = out.dropna(
        subset=[
            "delivered_kwh",
            "kWhDelivered",
            "unit_price",
            "amount",
            "preauth_limit_t",
        ]
    ).copy()

    out = out[out["delivered_kwh"] > 0].copy()
    out = out[out["preauth_limit_t"] >= 0].copy()

    return out.reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-dir", default="data/processed/mfev/policy_variants")
    parser.add_argument("--base-dir", default="data/processed/mfev")
    parser.add_argument("--out-dir", default="data/processed/mfev/runner_fixed")
    parser.add_argument("--sizes", nargs="+", type=int, default=[5000, 10000, 50000])
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for n in args.sizes:
        src = Path(args.in_dir) / f"mfev_{n}_policy_valid.csv"
        if not src.exists():
            src = Path(args.base_dir) / f"mfev_{n}.csv"

        if not src.exists():
            raise FileNotFoundError(f"Missing source file for N={n}: {src}")

        df = pd.read_csv(src)

        valid = fix_one(df, policy="valid")
        original = fix_one(df, policy="original_cap")
        topup = fix_one(df, policy="topup_cases")

        valid_path = out_dir / f"mfev_{n}_valid_fixed.csv"
        original_path = out_dir / f"mfev_{n}_original_cap_fixed.csv"
        topup_path = out_dir / f"mfev_{n}_topup_cases_fixed.csv"

        valid.to_csv(valid_path, index=False)
        original.to_csv(original_path, index=False)
        topup.to_csv(topup_path, index=False)

        print(f"[OK] N={n}")
        print(f"  valid:        {valid_path} rows={len(valid)}")
        print(f"  original-cap: {original_path} rows={len(original)}")
        print(f"  top-up cases: {topup_path} rows={len(topup)}")
        print(f"  amount median={valid['amount'].median():.6f}, p95={valid['amount'].quantile(0.95):.6f}")
        print(f"  max preauth={valid['preauth_limit_t'].max():.6f}")
        print(f"  balance={valid['user_balance'].iloc[0]:.6f}")
        print(f"  tariff modes={valid['tariff_mode'].value_counts().to_dict()}")
        print(f"  undercap cases={int(original['is_undercap_case'].astype(bool).sum())}")


if __name__ == "__main__":
    main()