# Datasets

The experiments use two public charging datasets. They are not redistributed in this repository.
Download them under their own terms and build the processed workloads with the scripts in
`scripts/data_prep/` (run from the repository root, inside `scripts/env/dvas_run.sh`).

Energy, timestamps and durations come from the dataset rows. Tariffs, pre-authorization holds and top-up
increments are the prototype's deterministic protocol tariff, not real billing data
(see `dbas_et/dvas/workload.py`).

## ACN-Data

Source: Caltech Adaptive Charging Network, <https://ev.caltech.edu/dataset> (Lee, Li and Low, 2019).
The REST API needs a free token. Set `ACN_API_TOKEN` or pass `--api-token-file`. The scripts never store it.

Sites caltech, jpl and office001, sessions with at least 0.1 kWh.

```bash
R="bash scripts/env/dvas_run.sh python"
# 5,000-session profiles (regression workload): data/acn/processed/profile_*.csv
$R scripts/data_prep/build_acn_profiles.py --target-n 5000 \
   --site caltech --site jpl --site office001 --min-kwh 0.1 --oversample-factor 1.5
# raw download for the larger workloads (checkpointed, resumable; the paper's raw cache was
# collected over several resumed runs and holds 31,258 sessions)
$R scripts/data_prep/download_acn_sessions.py --targets 10000 30000 \
   --site caltech --site jpl --site office001 --min-kwh 0.1
# ACN-30k profiles from the downloaded unique sessions (no resampling)
$R scripts/data_prep/build_acn_workload.py --target 30000 --min-kwh 0.1
# exact top-up set of ACN-30k (3,395 sessions refused under the original hold)
$R scripts/dvas/build_acn_topup_exact.py
```

## MFEV charging records

Source: Baek et al., "Multi-family residential EV charging records", Scientific Data, 2024,
figshare file `ChargingRecords.csv` (metadata and MD5 in `data/raw/mfev/figshare_metadata.json`).
Place the file at `data/raw/mfev/ChargingRecords.csv`.

```bash
R="bash scripts/env/dvas_run.sh python"
$R scripts/data_prep/prepare_mfev_workloads.py       # data/processed/mfev/mfev_{5000,10000,50000}.csv
$R scripts/data_prep/make_mfev_policy_variants.py    # data/processed/mfev/policy_variants/
$R scripts/data_prep/fix_mfev_runner_inputs.py       # data/processed/mfev/runner_fixed/
```

## Checksums of the files used in the paper

`sha256sum -c` on these lines confirms that a rebuilt workload is identical to the one measured.

```text
857a0b90d7290077d4d2078efd053caaf6fb16a45c7b9fbf6050511b7ca102bb  data/acn/processed/profile_valid_preauthorization.csv
62a68d61481656c01743f92b77969f07566719f977078ee062d02ec63e1d2812  data/acn/processed/profile_original_cap.csv
990e6d312776353b24b420f8267f17db04faea64d29b7a6215914c53ecbc8ea3  data/acn/processed/profile_undercap_topup.csv
8baf154f7554a02f9506907f392ac5a5d796812aeb476785972a1cbe6e511e60  data/acn/processed/profile_valid_preauthorization_sites-caltech-jpl-office001_min0p1_n10000.csv
8fd8c8c863dc0d1576019ffbc2bf7a0fde7ee3c0072d7c414409aedc08326146  data/acn/processed/profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv
81abff0ef1f3444b41f43ff75c6d8c76fc19fd8fdf4cd5a9bd39c6208075fa11  data/acn/processed/profile_original_cap_cached_acn_0p1_n30000_unique.csv
9144472e5ffe4348baa129b93abee51b78f32c169324162d2506ed9d0b2850c3  data/acn/processed/profile_undercap_topup_cached_acn_0p1_n30000_unique_exact.csv
d541259bed55e2a9bc3413756954e7a059b50f9c9031f1dfc6ec87cbf3afd358  data/raw/mfev/ChargingRecords.csv
4b3e54088f1eb81e87640c18b0f14ab2b03c6be15db0423e600f22df76ebae21  data/processed/mfev/runner_fixed/mfev_5000_valid_fixed.csv
c117d5100070806052683c2405fd05852d418432e7f126751f6aae110b4b94fc  data/processed/mfev/runner_fixed/mfev_50000_valid_fixed.csv
105dbee564cf41d10cbcc9f346c43d1a56289d309ef15b789e3639a3ba228b4e  data/processed/mfev/runner_fixed/mfev_50000_original_cap_fixed.csv
b18358202bb286d4cbb445cceda6b59115c76e7345535324f37517844f2d0fb2  data/processed/mfev/runner_fixed/mfev_50000_topup_cases_fixed.csv
7a722f156f3696a3718cccf8dd8b76e4a1b2e5e8ef719cc9c0b45a0dcf08da23  data/processed/mfev/policy_variants/mfev_50000_policy_valid.csv
```

The ACN API returns sessions in its own order and may change over time, so a new download can differ from
the files above. In that case the counts in the paper (for example 3,395 refused ACN-30k sessions) can
change slightly, while the protocol checks and the accept/reject logic stay the same.
