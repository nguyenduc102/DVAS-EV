"""Matched public-transcript / full-evidence / selective DVAS benchmarks.

Linux/WSL spawn workers generate their own verifier signing and KEM keys.
The coordinator receives only public keys and sends ledger snapshots over
framed loopback TCP. Production VerifierNode.evaluate and DvasLedger.settle
remain unchanged. A threshold decision ends collection and closes the late sockets.
The full-transcript reference evaluates all semantics locally with no oracle.
"""
from __future__ import annotations

import copy
import hashlib
import multiprocessing as mp
import os
import random
import select
import socket
import struct
import threading
import time
from dataclasses import replace
from decimal import Decimal
from typing import Any

from . import benchmark_wire as wire
from .delivery import PublicReceipt, h_priv_of, private_payload_bytes
from .ledger import (DvasLedger, LedgerResult, TxState, auth_request_message,
                     session_open_message)
from .pam import open_fields, open_for_reason, verify_opening
from .predicates import evaluate, predicate_for
from .profiles import KEMKeypair, PROFILES, Signer, verify_signature
from .protocol import DvasEnvironment
from .rbc import RBCBody, QuorumRBC, aggregate
from .registry import Role
from .schema import LAYOUT_V1, PROTOCOL_VERSION_VALUE
from .verifier import SettlementRequest, VerifierNode, VerifierOutcome

MAX_FRAME = 32 * 1024 * 1024
METHODS = ("FullTranscriptEscrow", "FullEvidenceQuorum", "DVASSelectiveQuorum")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise EOFError("closed TCP frame")
        out.extend(part)
    return bytes(out)


def send_frame(sock: socket.socket, data: bytes) -> int:
    if len(data) > MAX_FRAME:
        raise ValueError("oversized frame")
    sock.sendall(struct.pack("!I", len(data)) + data)
    return 4 + len(data)


def recv_frame(sock: socket.socket) -> bytes:
    n = struct.unpack("!I", _recv_exact(sock, 4))[0]
    if n > MAX_FRAME:
        raise ValueError("oversized frame")
    return _recv_exact(sock, n)


def _rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status") as f:
            return next(int(line.split()[1]) for line in f if line.startswith("VmRSS:"))
    except (OSError, StopIteration):
        return 0


def _pss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            return next(int(line.split()[1]) for line in f if line.startswith("Pss:"))
    except (OSError, StopIteration):
        return 0


def _worker(control, profile_name: str, vid: str) -> None:
    profile = PROFILES[profile_name]
    node = VerifierNode(vid, f"WORKER_{vid}", Signer(profile.verifier_sig), KEMKeypair(profile.kem))
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0)); server.listen(8)
    control.send({"pid": os.getpid(), "port": server.getsockname()[1], "sig_pk": node.signer.public_key,
                  "kem_pk": node.kem.public_key})
    setup = control.recv()
    registry = wire.registry_load(setup["registry"])
    node.key_epoch, node.kem_epoch = setup["sig_epoch"], setup["kem_epoch"]
    policy = setup["policy"]
    control.send("READY")
    control.close()
    while True:
        conn, _ = server.accept()
        try:
            conn.settimeout(10)
            data = recv_frame(conn)
            packet = wire.loads(data)
            if packet["command"] == "stop":
                break
            cpu0, t0 = time.process_time_ns(), time.perf_counter_ns()
            rng = random.Random(packet["delay_seed"])
            delay = packet["delay_ms"] + rng.uniform(0, packet["jitter_ms"])
            if delay:
                time.sleep(delay / 1000)
            ledger = DvasLedger(registry, policy)
            rec = packet["record"]
            ledger.records[rec.tid] = rec
            ledger.used_receipts = packet["used_receipts"]
            ledger.used_sids = {rec.sid}
            node.behavior = packet["behavior"]
            outcome = node.evaluate(packet["request"], registry, ledger)
            if packet["withhold"]:
                # Honest computation but no attestation returned. Wait for the
                # coordinator deadline/threshold to close this request socket.
                try:
                    conn.recv(1)
                except (socket.timeout, ConnectionError):
                    pass
                continue
            if delay:
                time.sleep(delay / 1000)
            protocol_data = wire.dumps(replace(outcome, timings_ms={}))
            reply = wire.dumps({"outcome": replace(outcome, timings_ms={}), "diagnostics": {
                "pid": os.getpid(), "cpu_ns": time.process_time_ns() - cpu0,
                "elapsed_ns": time.perf_counter_ns() - t0, "rss_kib": _rss_kib(os.getpid()),
                "protocol_response_bytes": len(protocol_data), "timings_ms": outcome.timings_ms}})
            send_frame(conn, reply)
        except (BrokenPipeError, ConnectionResetError, EOFError):
            pass  # threshold reached while this worker was still evaluating
        except Exception as exc:
            try:
                send_frame(conn, wire.dumps({"harness_error": f"{type(exc).__name__}: {exc}"}))
            except OSError:
                pass
        finally:
            conn.close()
    server.close()


class WorkerCluster:
    def __init__(self, env: DvasEnvironment, profile: str, *, startup_timeout_s: float = 30):
        self.env = env
        self.workers: dict[str, dict] = {}
        self.control_bytes = 0
        ctx = mp.get_context("spawn")
        started = time.perf_counter()
        try:
            for vid in list(env.verifiers):
                parent, child = ctx.Pipe()
                proc = ctx.Process(target=_worker, args=(child, profile, vid), daemon=True)
                proc.start(); child.close()
                self.workers[vid] = dict(process=proc, control=parent, pid=proc.pid)
                if not parent.poll(startup_timeout_s):
                    raise TimeoutError(f"worker startup: {vid}")
                info = parent.recv()
                sig = env.registry.rotate(vid, info["sig_pk"], env.profile.verifier_sig)
                kem = env.registry.rotate(vid, info["kem_pk"], env.profile.kem, purpose="kem")
                self.workers[vid] = dict(info, process=proc, control=parent,
                                          sig_epoch=sig.key_epoch, kem_epoch=kem.key_epoch)
            snapshot = wire.registry_dump(env.registry)
            self.control_bytes = len(snapshot) * len(self.workers)
            for w in self.workers.values():
                w["control"].send({"registry": snapshot, "policy": env.ledger.policy,
                    "sig_epoch": w["sig_epoch"], "kem_epoch": w["kem_epoch"]})
            for w in self.workers.values():
                if not w["control"].poll(startup_timeout_s) or w["control"].recv() != "READY":
                    raise TimeoutError("worker not ready")
                w["control"].close()
            env.verifiers.clear()  # workers own the authoritative private keys
        except BaseException:
            self.close()
            raise
        self.startup_s = time.perf_counter() - started

    @property
    def pids(self) -> list[int]:
        return [w["pid"] for w in self.workers.values() if w["process"].is_alive()]

    def offline(self, ids: list[str]) -> None:
        for vid in ids:
            p = self.workers[vid]["process"]
            p.terminate(); p.join(5)

    def evaluate(self, request: SettlementRequest, *, delay_ms: float = 0, jitter_ms: float = 0,
                 behaviors: dict[str, str] | None = None, withholding: list[str] | None = None,
                 deadline_ms: float = 150, seed: int = 0) -> dict[str, Any]:
        behaviors, withholding = behaviors or {}, withholding or []
        record = copy.deepcopy(self.env.ledger.records[request.tid])
        used = {request.receipt.dr_digest} & self.env.ledger.used_receipts
        sockets: dict[socket.socket, str] = {}
        outcomes, diagnostics, unavailable = [], [], []
        tx_bytes = rx_bytes = protocol_tx = protocol_rx = 0
        t0 = time.perf_counter_ns()
        deadline = time.perf_counter() + deadline_ms / 1000
        quorum = None
        try:
            # Serialize and fan out actual requests, including public ledger
            # context. Registry/key provisioning is excluded and reported once.
            for i, (vid, w) in enumerate(self.workers.items()):
                packet = {"command": "evaluate", "request": request, "record": record,
                    "used_receipts": used, "behavior": behaviors.get(vid, "honest"),
                    "withhold": vid in withholding, "delay_ms": delay_ms, "jitter_ms": jitter_ms,
                    "delay_seed": seed * 17 + i}
                data = wire.dumps(packet)
                sock = socket.socket(); sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(max(.001, deadline - time.perf_counter()))
                try:
                    sock.connect(("127.0.0.1", w["port"]))
                    tx_bytes += send_frame(sock, data)
                    protocol_tx += len(wire.dumps({"request": request, "record": record,
                                                  "used_receipts": used}))
                    sockets[sock] = vid
                except OSError:
                    sock.close(); unavailable.append(vid)
            while sockets and quorum is None:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                ready, _, _ = select.select(list(sockets), [], [], remaining)
                if not ready:
                    break
                for sock in ready:
                    vid = sockets.pop(sock)
                    try:
                        sock.settimeout(max(.001, deadline - time.perf_counter()))
                        data = recv_frame(sock)
                        rx_bytes += 4 + len(data)
                        reply = wire.loads(data)
                        if "harness_error" in reply:
                            raise RuntimeError(reply["harness_error"])
                        out = reply["outcome"]
                        outcomes.append(out); diagnostics.append(reply["diagnostics"])
                        protocol_rx += reply["diagnostics"]["protocol_response_bytes"]
                    except (OSError, EOFError):
                        unavailable.append(vid)
                    finally:
                        sock.close()
                bodies = {o.body.digest: o.body for o in outcomes if o.body is not None}
                quorum = aggregate([o.attestation for o in outcomes if o.attestation], bodies,
                                   self.env.ledger.policy.t)
            return {"rbc": quorum, "outcomes": outcomes, "diagnostics": diagnostics,
                "elapsed_ms": (time.perf_counter_ns() - t0) / 1e6,
                "tcp_sent_bytes": tx_bytes, "tcp_received_bytes": rx_bytes,
                "protocol_request_bytes": protocol_tx, "protocol_response_bytes": protocol_rx,
                "unavailable": unavailable, "outstanding": list(sockets.values()),
                "deadline_reached": quorum is None and time.perf_counter() >= deadline,
                "responding_pids": [d["pid"] for d in diagnostics]}
        finally:
            for sock in sockets:
                sock.close()

    def close(self) -> None:
        for w in self.workers.values():
            p = w["process"]
            if p.is_alive():
                try:
                    with socket.create_connection(("127.0.0.1", w["port"]), timeout=.2) as sock:
                        send_frame(sock, wire.dumps({"command": "stop"}))
                except (OSError, KeyError):
                    pass
                p.join(.5)
                if p.is_alive():
                    p.terminate(); p.join(5)
            try:
                w["control"].close()
            except (OSError, KeyError):
                pass


class ResourceSampler:
    """RSS/PSS/system snapshots every 100 ms. CPU times come from /proc."""
    def __init__(self, pids: list[int], interval_s: float = .1):
        self.pids = list(dict.fromkeys([os.getpid()] + pids))
        self.interval_s = interval_s
        self.rows: list[dict] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def sample(self):
        memory = {}
        with open("/proc/meminfo") as f:
            for line in f:
                if line.split(":")[0] in ("MemAvailable", "SwapFree", "SwapTotal"):
                    memory[line.split(":")[0]] = int(line.split()[1])
        self.rows.append({"timestamp_ns": time.time_ns(), "rss_sum_kib": sum(_rss_kib(p) for p in self.pids),
            "pss_sum_kib": sum(_pss_kib(p) for p in self.pids), "parent_rss_kib": _rss_kib(os.getpid()),
            "load1": os.getloadavg()[0], **memory})

    def _loop(self):
        while not self.stop.wait(self.interval_s):
            self.sample()

    def __enter__(self):
        self.sample(); self.thread.start(); return self

    def __exit__(self, *_):
        self.stop.set(); self.thread.join(); self.sample()


def proc_cpu_ns(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        # fields start at proc field 3: utime/stime are fields 14/15.
        return round((int(fields[11]) + int(fields[12])) * 1e9 / os.sysconf("SC_CLK_TCK"))
    except (OSError, IndexError):
        return 0


def public_delivery(s, overrides: dict | None = None) -> tuple[PublicReceipt, bytes]:
    """Same production receipt schema and meter signer, plaintext transcript.
    No KEM/AEAD is performed because full-transcript disclosure is intentional.
    """
    sp = s.spec
    priv = {"receipt_version": "dvas-ev-receipt-v1", "receipt_tid": sp.tid, "sid": s.sid,
        "rho_t": s.commitment.rho_t, "receipt_meter_id": sp.meter_id,
        "delivered_kwh": sp.delivered_kwh, "ts_start": sp.ts_start, "ts_end": sp.ts_end,
        "connection_duration_s": sp.connection_duration_s, "active_charging_duration_s": sp.active_charging_duration_s,
        "parking_duration_s": sp.parking_duration_s, "session_ref": sp.session_ref or f"row-{sp.row_index}",
        "meter_values_digest": sp.extra.get("meter_values_digest"), "nonce_m": f"m-{sp.tid}"}
    overrides = overrides or {}
    priv.update({k: v for k, v in overrides.items() if k in priv})
    pt = private_payload_bytes(priv)
    pub = {"receipt_version": priv["receipt_version"], "receipt_tid": sp.tid, "sid": s.sid,
        "rho_t": s.commitment.rho_t, "receipt_station_id": sp.station_id, "receipt_meter_id": sp.meter_id,
        "delivered_kwh": priv["delivered_kwh"], "ts_start": priv["ts_start"], "ts_end": priv["ts_end"],
        "applied_tariff_id": overrides.get("applied_tariff_id", sp.tariff_id),
        "applied_tariff_version": overrides.get("applied_tariff_version", sp.tariff_version),
        "nonce_m": priv["nonce_m"], "h_priv": h_priv_of(pt), "meter_key_epoch": s.meter.key_epoch}
    rc = PublicReceipt(pub)
    return replace(rc, signature=s.meter.signer.sign(rc.message())), pt


def release_public(env, request: SettlementRequest, plaintext: bytes) -> LedgerResult:
    """Public full-transcript contract-state reference (no trusted oracle).

    Uses the same canonical receipt, registry, PAM and predicate evaluator.
    The accounting step follows the public invariants of DvasLedger.
    Runs locally, no on-chain execution or real transfer.
    """
    from .delivery import decode_private_payload
    ledger, reg, r = env.ledger, env.registry, request.receipt
    rec = ledger.records.get(request.tid)
    if rec is None:
        return LedgerResult(False, "UNKNOWN_TID")
    if r.dr_digest in ledger.used_receipts or rec.state != TxState.RECEIPT_SUBMITTED:
        return LedgerResult(False, "REPLAY_OR_STATE")
    lk = reg.lookup(r["receipt_meter_id"], Role.METER, epoch=r["meter_key_epoch"])
    if not lk.ok or not verify_signature(lk.record.key_type, lk.record.public_key, r.message(), r.signature):
        return LedgerResult(False, "METER_SIGNATURE")
    if (r["receipt_tid"], r["sid"], r["rho_t"], r["receipt_meter_id"], r["receipt_station_id"], r.dr_digest) != (
        rec.tid, rec.sid, rec.rho_t, rec.meter_id, rec.station_id, rec.receipt_digest):
        return LedgerResult(False, "RECEIPT_BINDING")
    if h_priv_of(plaintext) != r["h_priv"] or r["h_priv"] != rec.h_priv:
        return LedgerResult(False, "PRIVATE_DIGEST_MISMATCH")
    priv = decode_private_payload(plaintext)
    for k in ("receipt_tid", "sid", "rho_t", "receipt_meter_id", "delivered_kwh", "ts_start", "ts_end", "nonce_m"):
        if priv[k] != r[k]:
            return LedgerResult(False, "PUBLIC_PRIVATE_MISMATCH")
    conn = priv["connection_duration_s"]
    if priv["active_charging_duration_s"] > conn or priv["parking_duration_s"] > conn or conn > r["ts_end"] - r["ts_start"]:
        return LedgerResult(False, "DURATION_INCONSISTENT")
    pv = verify_opening(rec.rho_t, request.opening, reason="settlement")
    if not pv.ok:
        return LedgerResult(False, f"PAM_{pv.code}")
    ev = {"receipt_tid": r["receipt_tid"], "receipt_station_id": r["receipt_station_id"],
        "receipt_meter_id": r["receipt_meter_id"], "applied_tariff_id": r["applied_tariff_id"],
        "applied_tariff_version": r["applied_tariff_version"], "delivered_kwh": r["delivered_kwh"],
        "ts_start": r["ts_start"], "ts_end": r["ts_end"], "sid": r["sid"], "dr_digest": r.dr_digest,
        "connection_duration_s": conn, "active_charging_duration_s": priv["active_charging_duration_s"],
        "parking_duration_s": priv["parking_duration_s"], "settlement_currency": rec.currency,
        "effective_limit": rec.effective_limit, "held_amount": rec.held,
        "payee": reg.station_beneficiary.get(r["receipt_station_id"], ""), "ledger_paytok": rec.paytok}
    relations = dict(reg.relations())
    relations["fresh_receipt"] = lambda d: d not in ledger.used_receipts
    relations["fresh_session"] = lambda tid, sid: ledger.session_is_open(tid, sid)
    pred = evaluate(predicate_for("settlement"), pv.values, ev, relations)
    if not pred.ok:
        return LedgerResult(False, f"MATCH_FAILED:{pred.reason}")
    cap = pred.outputs["amount"]
    ref = rec.held - cap
    if not (Decimal(0) <= cap <= rec.held and cap <= rec.effective_limit and ref >= 0):
        return LedgerResult(False, "ACCOUNTING")
    ledger.used_receipts.add(r.dr_digest)
    rec.captured, rec.refunded, rec.held, rec.state = cap, ref, Decimal(0), TxState.SETTLED
    ledger.balances[rec.user_account] = ledger.balances.get(rec.user_account, Decimal(0)) + ref
    ledger.payouts[rec.beneficiary] = ledger.payouts.get(rec.beneficiary, Decimal(0)) + cap
    return LedgerResult(True, "OK", value={"captured": cap, "refund": ref})


def run_session(env: DvasEnvironment, spec, method: str, cluster: WorkerCluster | None = None,
                *, scenario: dict | None = None, mutation: str = "honest", seed: int = 0) -> dict:
    if method not in METHODS:
        raise ValueError(method)
    scenario = scenario or {}
    s = env.session(spec)  # untimed, workload identities were preprovisioned
    balance_before = env.ledger.balances[s.user.account]
    payout_before = env.ledger.payouts.get(spec.beneficiary, Decimal(0))
    public_bytes = private_bytes = decision_bytes = 0
    cpu0, start = time.process_time_ns(), time.perf_counter_ns()
    s.commit()
    full = method != "DVASSelectiveQuorum"
    opening_a = (open_fields(s.commitment, LAYOUT_V1.field_names, reason="authorization") if full else
                 open_for_reason(s.commitment, "authorization"))
    auth_req = s.auth_request(); sig = s.user.signer.sign(auth_request_message(auth_req))
    public_bytes += len(wire.dumps({"request": auth_req, "signature": sig, "opening": opening_a}))
    auth = env.ledger.authorize(auth_req, sig, opening_a)
    if not auth.ok:
        raise RuntimeError(f"honest authorization: {auth.code}")
    s.sid = hashlib.sha256(f"sid|{spec.tid}|{spec.nonce_s}".encode()).hexdigest()[:40]
    so = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": spec.tid, "sid": s.sid,
          "rho_t": s.commitment.rho_t, "station_id": spec.station_id, "meter_id": spec.meter_id,
          "nonce_s": spec.nonce_s}
    ssig = s.station.signer.sign(session_open_message(so))
    public_bytes += len(wire.dumps({"request": so, "signature": ssig}))
    opened = env.ledger.open_session(so, ssig)
    if not opened.ok:
        raise RuntimeError(opened.code)
    overrides = {}
    if mutation == "tariff_swap":
        overrides["applied_tariff_version"] = spec.tariff_version + "-swap"
    elif mutation == "over_cap":
        overrides["delivered_kwh"] = spec.cap_kwh + Decimal("0.01")
    elif mutation not in ("honest", "private_substitution", "incomplete_opening", "replay"):
        raise ValueError(mutation)
    if method == "FullTranscriptEscrow":
        s.receipt, plaintext = public_delivery(s, overrides)
    else:
        s.deliver(**overrides)
        plaintext = private_payload_bytes(s.private_values)
    public_bytes += len(wire.dumps(s.receipt))
    submitted = s.submit_receipt()
    if not submitted.ok:
        raise RuntimeError(submitted.code)
    op = (open_fields(s.commitment, LAYOUT_V1.field_names, reason="settlement") if full else
          open_for_reason(s.commitment, "settlement"))
    if mutation == "incomplete_opening":
        op = open_fields(s.commitment, [x for x in op.field_names if x != "cap_kwh"], reason="settlement")
    req = SettlementRequest(spec.tid, s.receipt, s.envelope, op)
    if mutation == "private_substitution":
        from .evidence import EvidenceContext, seal_evidence
        from .delivery import decode_private_payload
        pv = decode_private_payload(plaintext)
        pv["session_ref"] += "-attacker"
        plaintext = private_payload_bytes(pv)
        if method != "FullTranscriptEscrow":
            envp = seal_evidence(plaintext, EvidenceContext(spec.tid, s.sid, s.commitment.rho_t,
                                                        spec.meter_id, s.receipt["h_priv"]), env.recipients())
            req = replace(req, envelope=envp)
    qinfo = {"elapsed_ms": 0, "tcp_sent_bytes": 0, "tcp_received_bytes": 0,
             "protocol_request_bytes": 0, "protocol_response_bytes": 0, "outcomes": [],
             "responding_pids": [], "deadline_reached": False, "diagnostics": []}
    verify_start = time.perf_counter_ns()
    if method == "FullTranscriptEscrow":
        public_bytes += len(wire.dumps({"opening": op, "plaintext": plaintext}))
        result = release_public(env, req, plaintext)
        decision = wire.dumps({"tid": spec.tid, "ok": result.ok, "code": result.code, "value": result.value})
        public_bytes += len(decision); decision_bytes = len(decision)
    else:
        if cluster is None:
            raise ValueError("quorum method needs workers")
        qinfo = cluster.evaluate(req, seed=seed, **scenario)
        rbc = qinfo["rbc"]
        if rbc:
            result = s.settle(rbc)
            decision_bytes = len(wire.dumps(rbc)); public_bytes += decision_bytes
        else:
            result = LedgerResult(False, "NO_QUORUM")
        private_bytes = qinfo["protocol_request_bytes"] + qinfo["protocol_response_bytes"]
    finish, cpu_finish = time.perf_counter_ns(), time.process_time_ns()
    elapsed_ms = (finish - start) / 1e6
    accounting_ok = True
    if result.ok:
        rec = env.ledger.records[spec.tid]
        accounting_ok = (rec.captured >= 0 and rec.captured <= rec.effective_limit
            and rec.captured + rec.refunded == rec.effective_limit and rec.held == 0
            and env.ledger.balances[s.user.account] == balance_before - rec.captured
            and env.ledger.payouts[spec.beneficiary] == payout_before + rec.captured)
    else:
        rec = env.ledger.records[spec.tid]
        accounting_ok = (rec.captured == 0 and rec.refunded == 0 and rec.held == rec.effective_limit
            and env.ledger.balances[s.user.account] == balance_before - rec.held
            and env.ledger.payouts.get(spec.beneficiary, Decimal(0)) == payout_before
            and s.receipt.dr_digest not in env.ledger.used_receipts)
    replay_refused = None
    if mutation == "replay" and result.ok:
        repeated = (release_public(env, req, plaintext) if method == "FullTranscriptEscrow" else s.settle(qinfo["rbc"]))
        replay_refused = not repeated.ok
    return {"ok": result.ok, "code": result.code, "captured": str(result.value["captured"]) if result.ok else "",
        "refund": str(result.value["refund"]) if result.ok else "", "accounting_ok": accounting_ok,
        "replay_refused": replay_refused, "elapsed_ms": elapsed_ms,
        "verification_release_ms": (finish - verify_start) / 1e6,
        "parent_cpu_ms": (cpu_finish - cpu0) / 1e6,
        "public_application_bytes": public_bytes, "private_application_bytes": private_bytes,
        "decision_bytes": decision_bytes, "tcp_sent_bytes": qinfo["tcp_sent_bytes"],
        "tcp_received_bytes": qinfo["tcp_received_bytes"], "quorum_elapsed_ms": qinfo["elapsed_ms"],
        "responses": len(qinfo["outcomes"]), "responding_pids": ",".join(map(str, qinfo["responding_pids"])),
        "verifier_reasons": ";".join(f"{o.verifier_id}:{o.reason}" for o in qinfo["outcomes"]),
        "ledger_state": env.ledger.records[spec.tid].state.value,
        "deadline_reached": qinfo["deadline_reached"],
        "worker_cpu_received_ms": sum(d["cpu_ns"] for d in qinfo["diagnostics"]) / 1e6}
