"""Machine-readable reproducibility manifest -> <OUT>/artifact_manifest.json.

Contains: source digests (per file + aggregate), environment versions, dataset
file hashes, experiment parameters, sampling seeds, output file hashes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, environment_metadata  # noqa: E402

SOURCE_DIRS = ["dbas_et", "scripts/dvas", "scripts/env", "tests", "foundry/src", "foundry/test"]
DATASETS = [
    "data/acn/processed/profile_valid_preauthorization.csv",
    "data/acn/processed/profile_original_cap.csv",
    "data/acn/processed/profile_undercap_topup.csv",
    "data/processed/mfev/runner_fixed/mfev_5000_valid_fixed.csv",
    "data/raw/mfev/figshare_metadata.json",
    "tests/fixtures/standards/ocpi_token.json",
    "tests/fixtures/standards/ocpi_location.json",
    "tests/fixtures/standards/ocpi_tariff.json",
    "tests/fixtures/standards/dvas_authorization_request.json",
    "tests/fixtures/standards/ocpp_transaction_events.json",
    "tests/dvas/vectors/canonical_v1.json",
]


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    src = {}
    for d in SOURCE_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".py", ".sol", ".sh", ".json", ".ini", ".toml"}:
                src[str(p.relative_to(ROOT))] = sha(p)
    agg = hashlib.sha256("".join(f"{k}:{v}\n" for k, v in sorted(src.items())).encode()).hexdigest()
    params_path = OUT / "experiment_parameters.json"
    outputs = {str(p.relative_to(OUT)): sha(p) for p in sorted(OUT.rglob("*"))
               if p.is_file() and p.name != "artifact_manifest.json"}
    manifest = {
        "artifact": "DVAS-EV paper artifact",
        "source_digest_aggregate": agg,
        "source_files": src,
        "environment": environment_metadata(),
        "datasets": {d: {"sha256": sha(ROOT / d), "bytes": (ROOT / d).stat().st_size} for d in DATASETS if (ROOT / d).exists()},
        "dataset_provenance": {
            "ACN-Data": "Caltech ACN-Data sessions (ev.caltech.edu), processed by the legacy artifact into data/acn/processed",
            "MFEV": "MFEV charging records (Scientific Data 2024, figshare; metadata in data/raw/mfev/figshare_metadata.json)",
            "tariffs_and_preauthorization": "deterministic protocol tariff of the legacy artifact (not billing data)",
            "standards_fixtures": "hand-written representative OCPI/OCPP-shaped objects",
        },
        "experiment_parameters": json.loads(params_path.read_text()) if params_path.exists() else {},
        "sampling_seeds": {"attack_suite": 20261005, "formal_properties": 20261006, "money_invariant_tests": 9,
                           "note": "seeds select test cases and mutation parameters only; all keys use the OS CSPRNG"},
        "outputs": outputs,
    }
    (OUT / "artifact_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str))
    print("source digest", agg, "| outputs hashed", len(outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
