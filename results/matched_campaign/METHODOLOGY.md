# Matched campaign: setup

Run on 13 October 2026. Five independent runs, 29,160 measured attempts.
The design was fixed before the measured runs. Results are in RESULTS.md and the CSV files,
checks of the raw data are in raw_audit.json.

## Methods

The three methods use the same 26-field layout, canonical crypto messages, registered meter
signature, public/private hash binding, registry relations, predicate-completeness policy,
FIXED6 tariff and hold/refund rules. Datasets and session order are paired within each run.
Profiles are C0 (classical) and C3 (hybrid). C3 still uses classical meter and verifier signatures.

* FullTranscriptEscrow publishes all committed fields and the private receipt in plaintext.
  A local contract-state reference runs the same predicate evaluator, registry checks and
  freshness checks. There is no evidence encryption and no verifier attestation, since the
  check is public. It is an architectural reference, not a deployed contract.
* FullEvidenceQuorum opens all 26 fields for authorization and settlement and keeps the same
  encrypted evidence and t-of-n verifier pipeline as DVAS-EV. It is the direct baseline for the
  selective projection. Both quorum methods send the same encrypted private payload.
* DVASSelectiveQuorum opens the predicate-complete authorization and settlement projections
  and uses the normal verifier and ledger code.

The adversary can change public transcripts and proofs, replace private evidence and replay
accepted decisions. Meter registration, delivery binding, registry state and ledger execution
are assumed correct for all methods. The quorum methods also need f < t for safety and
n - f - u >= t responsive honest verifiers for liveness. The public reference instead relies on
correct public execution, so it has no offline-verifier case. Its t/n cells only name the
matched setup group.

## Processes and network

Each run starts a fresh coordinator and 3 or 5 verifier processes (`multiprocessing` spawn).
Each worker generates its own signing and KEM keys and sends only public keys to the
coordinator. Workers run `VerifierNode.evaluate`, the coordinator collects the responses and
calls `DvasLedger.settle`. The timer stops after this call and the decision serialization.

Transport is length-prefixed TCP on 127.0.0.1 with a whitelist of JSON types. Registry and key
provisioning and workload setup are outside the session timer. Each request carries a public
ledger snapshot that stands for the contract state (no blockchain inclusion or consensus).
Outstanding sockets are closed once the threshold is reached. Verifiers may still finish work
after the decision, so group CPU includes a drain interval.

Deadlines are 1,000 ms for healthy runs and 150 ms for fault runs. Artificial delay is applied
by each worker before evaluation and before the response, either 5 ms each direction or 25 ms
plus uniform 0-5 ms jitter each direction. Bandwidth, WAN routing and packet loss are not
emulated. Offline injection terminates verifier processes started by the harness. Withholding
runs the computation but does not send the response. Inflation produces correctly signed but
different decision digests. Threshold collusion runs f >= t, which is outside the safety
assumption, and is reported separately.

Latency covers local protocol processing, loopback coordination and the artificial delay.
It excludes physical charging, backend transport, blockchain inclusion and finality, and fund
transfers. The public reference runs in-process and has no TCP cost.

## Byte accounting

One serializer is used for all methods: compact sorted-key UTF-8 JSON with tagged Decimal
values, hex bytes and tagged records, tuples, sets and enums. Crypto messages still use the
canonical TLV encoding. Lengths are taken from the serialized buffers.

* Public application bytes: authorization request, signature and opening, session-open
  request and signature, signed public receipt and settlement output. FullTranscriptEscrow
  also publishes the full settlement opening and the private plaintext. Quorum outputs include
  every attestation in the accepted RBC. These are serialized sizes, not calldata or gas.
* Private application bytes: request, receipt, envelope, opening and public-state snapshot sent
  to each connected verifier, plus each verifier outcome received, without diagnostics and
  fault controls. The shared envelope and key slots go to every connected verifier.
* TCP sent/received bytes: complete harness frames, including the 4-byte prefix, fault
  controls and diagnostics, without TCP/IP headers, ACKs and retransmissions.
* Registry snapshot bytes and worker startup time are reported as separate setup metrics.

Keys, salts and nonces are fresh for every run. ECDSA signature length and the number of
collected attestations vary, and this variation stays in the raw samples.

## Runs and statistics

Five independent runs, with group order randomized in each run. Healthy groups have 20
warm-up and 200 measured sessions, fault groups 2 and 12, security groups 10 measured sessions
per mutation. Raw rows, resource samples, group order, source and data hashes and environment
metadata are kept. No outliers are removed. Tariffs and holds come from the deterministic
protocol profiles, not real bills.

95% intervals use 5,000 bootstrap draws over the five run medians (or P95s), and the point
estimate is the median across runs. Sessions are not treated as independent replications.

Healthy rejection rates use every measured valid session as denominator. Harness exceptions are
counted separately. Security probes cover tariff swap, over-cap delivery, substitution of a
valid encrypted private payload, authentic but incomplete openings, and replay after
settlement. Captured and refunded amounts are compared with `honest_amount`. No-quorum outcomes
in the beyond-liveness cases are not counted as attack rejections.

CPU is coordinator process time per session and /proc utime+stime summed over the coordinator
and live workers per group. The group figure includes orchestration, sampling, validation and
late worker work. RAM is summed RSS and PSS sampled every 100 ms and at group boundaries.
Summed RSS counts shared pages more than once, PSS splits them. The coordinator is reused across
groups within a run, so allocator history can affect RAM.

After the runs, one reporting bug was fixed: the per-metric sample count overwrote the verifier
count `n` in run_statistics.csv and paired_differences.csv. The column is now `sample_count` and
the summaries were recomputed from the unchanged raw rows. raw_audit.json checks that this label
is the only change in the runner and that the protocol code and data hashes are unchanged.

## Commands

```sh
bash scripts/env/dvas_run.sh python scripts/dvas/run_matched_campaign.py --prepare-only
bash scripts/env/dvas_run.sh python -m pytest tests/dvas/test_matched_benchmark.py -q
bash scripts/env/dvas_run.sh python scripts/dvas/run_matched_campaign.py
```

The campaign ran with no tests or other benchmarks in parallel, and each campaign writes to a
new output directory.
