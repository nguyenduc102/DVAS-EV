# Where each result of the paper comes from

Commands run from the repository root. `R` stands for `bash scripts/env/dvas_run.sh python`.
Runners write to `$DVAS_OUT` (default `outputs/`). The files listed under "Shipped result" are the
measured outputs reported in the paper.

## Section 7.1: matched settlement cost (Fig. 2) and controlled baselines (Table 4)

| Paper item | Values in the paper | Shipped result | Command |
|---|---|---|---|
| Fig. 2, text of 7.1 | DVAS-EV hybrid ACN 5.355 / 6.597 ms vs full-evidence 5.497 / 6.735 ms, escrow 2.670 ms, classical 4.926 ms, P95 below 7.2 ms, private bytes 20,687 to 39,730 | `results/matched_campaign/summary_uncertainty.csv`, `RESULTS.md` | `$R scripts/dvas/run_matched_campaign.py --out outputs/matched_campaign` (5 runs, 200 sessions, seed 20261013) |
| Paired gains 0.149 / 0.142 ms and their 95% intervals | | `results/matched_campaign/paired_differences.csv` | same run |
| 24,000 valid sessions, 2,160 fault attempts, 3,000 attack attempts | | `results/matched_campaign/run_statistics.csv`, `validation.csv` | same run |
| Table 4, runtime and bytes | e.g. full escrow 1.137 ms, DVAS-EV 2-of-3 3.665 ms, top-up 4.398 ms over 3,395 sessions | `results/baselines_table/t1_settlement_baselines.csv` | `$R scripts/dvas/run_quorum_tables.py --part t1` |
| Table 4, throughput | 1,262 and 869 sessions/s with eight workers | `results/quorum_tables/t4_parallel_replay.csv` | `$R scripts/dvas/run_parallel_replay_quorum.py --workers 8` |

## Section 7.2: contract cost and security (Table 5)

| Paper item | Values in the paper | Shipped result | Command |
|---|---|---|---|
| Release gas | 164,067 (2-of-3), 173,390 (3-of-5), 120,574 single verifier | `results/paper_artifact/solidity_gas.csv` | `$R scripts/dvas/run_foundry_gas.py` (runs `forge test -vv` in `foundry/`) |
| Table 5(a), attack groups | 10,000 cases, 27 types, 0 false acceptances | `results/quorum_tables/t2_attack_matrix.csv`, `attack_results.csv` | `$R scripts/dvas/run_quorum_tables.py --part t2` |
| Table 5(a), matched rows | 2,400 tampered requests, 600 replay attempts | `results/matched_campaign/validation.csv` | matched campaign |
| Table 5(b), verifier faults | outcomes and median round-trip times | `results/matched_campaign/summary_uncertainty.csv`, `run_statistics.csv` | matched campaign |
| Pricing stress | flat-rate reserve blocks 32.1–99.3% (ACN) and 23.1–99.2% (MFEV) under time-of-use, idle-fee and mixed tariffs | `results/tariff_sensitivity/tariff_sensitivity_acn30k_mfev50k_paper_table.csv` | `python scripts/dvas/run_tariff_sensitivity.py --acn-csv data/acn/processed/profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv --mfev-csv data/processed/mfev/policy_variants/mfev_50000_policy_valid.csv` (writes to `outputs/tables/`) |
| Colluding quorum (240 sessions) | | `results/matched_campaign/validation.csv` | matched campaign |

## Section 7.3: execution time and projection compression (Figs. 3–6)

| Paper item | Values in the paper | Shipped result | Command |
|---|---|---|---|
| Fig. 3 | 3,395 ACN-30k and 1,242 MFEV-50k refused at the original hold, all settled after top-up, P95 below 5.5 ms | `results/scale/scale_summary.csv`, `scale_rows.csv.gz` | `$R scripts/dvas/run_scale_workloads.py --quorum 2/3,3/5` |
| 5,000-session regression, 5,000-session multi-operator workload with 3,899 cross-domain cases | | `results/paper_artifact/regression_checks.csv`, `multi_operator_results.csv` | `$R scripts/dvas/run_paper_artifact.py` (steps 01 and 10) |
| Fig. 4 | component medians, totals 3.63 and 4.03 ms | `results/quorum_tables/t3_rbc_timing.csv` | `$R scripts/dvas/run_quorum_tables.py --part t3` |
| Fig. 5 | 3–21 instead of 6–24 fields, 72.8–86.6% smaller, 35–64% faster | `results/paper_artifact/pam_ablation.csv` | `$R scripts/dvas/run_pam_ablation.py --capsules 500 --repeats 10 --warmup 100` |
| Fig. 6, PAM-Proof and ablation rows | 4,360 → 2,728 → 584 bytes, 75 → 8 sibling hashes, 1,060 → 0 accepted incomplete openings | `results/paper_artifact/pam_ablation.csv`, `pam_ablation_updated.csv` | same as Fig. 5 |
| Fig. 6, library rows | OpenZeppelin, OZ + check, SD-JWT, BBS | `results/library_baselines/oz_e9_check_summary.csv`, `sdjwt_bbs_e9_summary.csv` | see "Library baselines" below |

All five figures are drawn by `python scripts/figures/make_paper_figures.py` from the shipped results.
The output is pixel-identical to the figures in the manuscript.

## Library baselines (Fig. 6)

```bash
$R scripts/dvas/export_e9_leaves_for_oz.py --capsules 100          # writes $DVAS_OUT/oz_e9/e9_leaves.csv
cd library_baselines/oz_multiproof && npm ci && INPUT=../../outputs/oz_e9/e9_leaves.csv node bench_oz_e9_views_check.mjs
cd ../sd_jwt_bbs && npm ci && INPUT=../../outputs/oz_e9/e9_leaves.csv node bench_sdjwt_bbs_e9_views.mjs
```

On Windows hosts with hybrid cores, `library_baselines/run_node_bench_pcore.ps1` pins Node.js to the
performance cores. Unpinned runs were about two times slower.

## Released code and the code that produced each result

Every runner records a SHA-256 digest of the `dbas_et/dvas/*.py` sources in its environment file.
The released code has digest `81471dbd…` (recomputed by `scripts/dvas/bench_env.py: source_digest`).
It differs from `bcaf2315…` only in docstrings and comments: with docstrings and comments removed, the
Python syntax trees of the two versions are identical.

| Result set | Date (UTC) | Digest | Difference from the released code |
|---|---|---|---|
| `scale/`, `baselines_table/` | 2026-11-11 | `bcaf2315…` | docstrings and comments only |
| `quorum_tables/` | 2026-11-10 | `95c49b33…` | `registry.publish_tariff` |
| `matched_campaign/` | 2026-10-13 | `36aec9cb…` | `registry.publish_tariff`. `minimality_exact.py` was added later and is not used by the campaign |
| `paper_artifact/` | 2026-10-05 | `6a5144ab…` | harness-only changes in `workload.py`, `attacks.py` and `baselines.py`, the matched-campaign modules added later, and `registry.publish_tariff` |

The `registry.publish_tariff` change only rejects republishing an existing `(station, tariff, version)` key with
different terms (assumption A2 of the minimality proof). It runs during setup and cannot change a measured
value. The released code was rerun on the deterministic experiments of `paper_artifact/`: 5,000-session
regression, PAM ablation, multi-operator workload and attack suite. The rerun matches the shipped files
exactly in every column except wall-clock timings.
