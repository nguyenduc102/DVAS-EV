# DVAS-EV: Delivery-Verified Authorization and Settlement for Decentralized EV Charging

This repository contains the prototype, tests, experiment scripts and measured results for the paper
*DVAS-EV: Delivery-Verified Authorization and Settlement for Decentralized Electric Vehicle Charging Systems*
(submitted to Vehicular Communications).

DVAS-EV binds the pre-service authorization, the meter-signed delivery receipt and the payment release
to one committed transaction root. Settlement verifiers open only the fields that the settlement predicate
requires (PA-MSP selection, PAM-Proof multiproof), check the private receipt, and sign one decision digest.
The settlement contract releases payment only when a quorum receipt-binding certificate (RBC) from at least
`q` distinct registered verifiers matches the authorization state and the hold.

**Scope.** The prototype is a protocol-state simulator. All parties run on one host, either in one process
or as separate processes over loopback. It is not a production charging backend, it does not implement
OCPP/OCPI message transport, and PAM-Proof gives authenticated selective disclosure, not zero-knowledge
privacy. Timings are local protocol-processing times. They exclude physical charging, wide-area networking
and blockchain finality.

## Repository layout

| Path | Content |
|---|---|
| `dbas_et/dvas/` | DVAS-EV protocol core: canonical encoding and schema, capsule commitment, PAM-Proof (`pam.py`), predicates and PA-MSP minimality, private evidence (ML-KEM + AEAD), settlement verifiers, quorum RBC, reference ledger, attacks and baselines |
| `dbas_et/*.py` | Supporting modules from the earlier prototype that the core still uses (crypto wrappers, payments and tariff evaluation, workload loaders, legacy baseline harness) |
| `tests/` | Python test suite (protocol invariants, canonical test vectors, PAM-Proof, quorum, money invariants, standards adapter) |
| `foundry/` | Solidity contracts and Foundry tests. `DVASQuorumSettle.sol` is the quorum release contract used for the gas results |
| `scripts/dvas/` | Experiment runners, one per result (see the table below) |
| `scripts/figures/make_paper_figures.py` | Draws Figs. 2–6 of the paper from `results/` |
| `scripts/data_prep/` | Download and preparation of the ACN-Data and MFEV workloads |
| `library_baselines/` | Node.js benchmarks of the OpenZeppelin Merkle multiproof, SD-JWT and BBS on the same capsules |
| `results/` | Measured results reported in the paper, with environment metadata |
| `docs/RESULTS_MAP.md` | Where every number, table and figure of the paper comes from |

`dbas_et` is the historical package name of the project. The DVAS-EV design lives in `dbas_et/dvas`.

## Environment

The results were measured on an Intel Core i7-13700F (16 GB RAM) under WSL2 with Ubuntu 24.04,
Python 3.12.3, liboqs 0.15.0 with liboqs-python 0.14.0, Solidity 0.8.24, Foundry 1.8.4 and Node.js 24.

```bash
# Linux or WSL2: builds liboqs, creates ~/venvs/dvas-ev and installs the pinned requirements
bash scripts/env/setup_env.sh
# every command below runs inside that environment
bash scripts/env/dvas_run.sh python -m pytest tests
```

For the contract tests, install Foundry (<https://book.getfoundry.sh>), then:

```bash
git submodule update --init          # forge-std v1.16.1
cd foundry && forge test
```

## Data

The workloads are derived from two public datasets that are not redistributed here.
`data/README.md` describes how to download them and build the processed files.

* ACN-Data (Caltech Adaptive Charging Network), which needs a free API token.
* MFEV charging records (Baek et al., Scientific Data 2024), from figshare.

The test suite and the figure script run without the datasets.

## Reproducing the results

All runners write to `outputs/` (or to `$DVAS_OUT`) and never overwrite `results/`.

```bash
R="bash scripts/env/dvas_run.sh python"
$R scripts/dvas/run_paper_artifact.py --quick   # smoke run of the whole pipeline (a few minutes)
$R scripts/dvas/run_paper_artifact.py           # full run: tests, attacks, PAM ablation, gas, regression, multi-operator
$R scripts/dvas/run_matched_campaign.py --out outputs/matched_campaign            # Fig. 2, Table 5(b), matched rows
$R scripts/dvas/run_quorum_tables.py            # Table 4, Table 5(a), Fig. 4
$R scripts/dvas/run_parallel_replay_quorum.py   # throughput column of Table 4
$R scripts/dvas/run_scale_workloads.py --quorum 2/3,3/5                         # Fig. 3
$R scripts/figures/make_paper_figures.py        # Figs. 2-6 from results/ into outputs/figures/
```

`docs/RESULTS_MAP.md` lists the exact command, output file and paper location for each result, including the
library baselines of Fig. 6 and the pricing-stress experiment.

Run-to-run timing differences of a few percent are expected. Counts, accept and reject decisions, sizes in
bytes and gas are deterministic for the fixed seeds.

## Results shipped in `results/`

| Folder | Paper |
|---|---|
| `matched_campaign/` | Fig. 2, Table 5(b), matched attack and replay rows of Table 5(a), Section 7.1 text |
| `baselines_table/` | Table 4 (runtime and artifact bytes) |
| `quorum_tables/` | Table 5(a) attack matrix, Fig. 4 component times, Table 4 throughput |
| `scale/` | Fig. 3 |
| `paper_artifact/` | Fig. 5, Fig. 6 (PAM-Proof and ablation rows), gas, regression and multi-operator workloads, formal property and minimality checks |
| `library_baselines/` | Fig. 6 (OpenZeppelin, SD-JWT and BBS rows) |
| `tariff_sensitivity/` | Pricing-stress percentages in Section 7.2 |

Each folder keeps the environment metadata of its run, including a SHA-256 digest of the `dbas_et/dvas`
sources. `docs/RESULTS_MAP.md` explains how these digests relate to the released code.

## Citation

If you use this code, please cite the paper (the reference will be added after publication).

## License

MIT License, see `LICENSE`. The datasets keep their own terms (see `data/README.md`).
