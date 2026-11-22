"""Shared helpers for the benchmark runners (paths, environment metadata, CSV).

- ``environment_metadata()`` records CPU, cores, RAM, OS, Python/compiler,
  liboqs/liboqs-python versions and enabled algorithms, crypto library
  versions, solc/forge versions, and a source digest (the repository is not
  a git repository, so the digest of the measured source files is recorded
  instead of a commit hash).
- ``measure()`` runs explicit warm-up iterations, then repeated runs timed
  with ``time.perf_counter_ns`` (monotonic, high resolution), and returns the
  raw samples.
- ``stats()`` summarises samples as median, P95, mean, std, min, max.

All timings are LOCAL PROTOCOL-PROCESSING LATENCY in one Python process.
They are not EV-charging end-to-end latency and include no network or
blockchain inclusion time.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
# DVAS_OUT redirects every runner's outputs (e.g. outputs/paper_artifact) so a new
# campaign never overwrites previously validated results.  Default unchanged.
OUT = Path(os.environ["DVAS_OUT"]).resolve() if os.environ.get("DVAS_OUT") else ROOT / "outputs"
RAW = OUT / "raw"

SCOPE = "local_protocol_processing_latency_single_process_not_end_to_end_ev_charging"


def _cmd(args: list[str]) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def _cpu() -> dict[str, Any]:
    info: dict[str, Any] = {"logical_cores": os.cpu_count()}
    txt = _cmd(["lscpu"])
    for key, name in [("Model name", "cpu_model"), ("Core(s) per socket", "cores_per_socket"),
                      ("Socket(s)", "sockets"), ("Thread(s) per core", "threads_per_core"),
                      ("CPU max MHz", "cpu_max_mhz"), ("Hypervisor vendor", "hypervisor")]:
        m = re.search(rf"^{re.escape(key)}:\s*(.+)$", txt, re.M)
        if m:
            info[name] = m.group(1).strip()
    try:
        info["physical_cores"] = int(info.get("cores_per_socket", 0)) * int(info.get("sockets", 1)) or None
    except ValueError:
        info["physical_cores"] = None
    try:
        mem = Path("/proc/meminfo").read_text()
        info["ram_gib"] = round(int(re.search(r"MemTotal:\s+(\d+)", mem).group(1)) / 1024 / 1024, 2)  # type: ignore[union-attr]
    except Exception:
        info["ram_gib"] = None
    return info


def source_digest(paths: Iterable[Path] | None = None) -> str:
    paths = paths or sorted((ROOT / "dbas_et" / "dvas").glob("*.py"))
    h = hashlib.sha256()
    for p in paths:
        h.update(p.name.encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def environment_metadata() -> dict[str, Any]:
    md: dict[str, Any] = {"timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scope": SCOPE}
    md.update(_cpu())
    md["os"] = platform.platform()
    md["kernel"] = platform.release()
    md["python"] = sys.version.split()[0]
    md["python_compiler"] = platform.python_compiler()
    md["gcc"] = _cmd(["gcc", "--version"]).splitlines()[0] if _cmd(["gcc", "--version"]) else ""
    try:
        import cryptography

        md["cryptography"] = cryptography.__version__
        from cryptography.hazmat.backends.openssl.backend import backend

        md["openssl"] = backend.openssl_version_text()
    except Exception:
        pass
    try:
        import Cryptodome

        md["pycryptodomex"] = Cryptodome.__version__
    except Exception:
        pass
    from dbas_et.dvas.profiles import backend_metadata

    md.update(backend_metadata())
    try:
        import oqs

        md["oqs_enabled_sig"] = ",".join(x for x in oqs.get_enabled_sig_mechanisms() if x.startswith("ML-DSA"))
        md["oqs_enabled_kem"] = ",".join(x for x in oqs.get_enabled_kem_mechanisms() if x.startswith("ML-KEM"))
    except Exception:
        pass
    forge = Path.home() / ".foundry" / "bin" / "forge"
    md["forge"] = _cmd([str(forge), "--version"]).splitlines()[0] if forge.exists() else ""
    toml = ROOT / "foundry" / "foundry.toml"
    m = re.search(r'solc_version\s*=\s*"([^"]+)"', toml.read_text()) if toml.exists() else None
    md["solc"] = m.group(1) if m else ""
    git = _cmd(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    md["git_commit"] = git or "not_a_git_repository"
    md["source_digest_dbas_et_dvas"] = source_digest()
    return md


def write_metadata(name: str) -> dict[str, Any]:
    md = environment_metadata()
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / f"{name}_environment.json").write_text(json.dumps(md, indent=2, sort_keys=True))
    return md


def measure(fn: Callable[[], Any], *, warmup: int, repeats: int) -> list[int]:
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t0)
    return out


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return float(s[lo] + (s[hi] - s[lo]) * (k - lo))


def stats(xs: list[float]) -> dict[str, float]:
    if not xs:
        return {"n": 0}
    return {
        "n": len(xs),
        "median": statistics.median(xs),
        "p95": percentile(xs, 0.95),
        "mean": statistics.fmean(xs),
        "std": statistics.pstdev(xs) if len(xs) > 1 else 0.0,
        "min": min(xs),
        "max": max(xs),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
