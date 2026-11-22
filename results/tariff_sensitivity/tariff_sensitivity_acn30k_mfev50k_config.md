# Tariff sensitivity configuration

- ACN CSV: `data/acn/processed/profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv`
- MFEV CSV: `data/processed/mfev/policy_variants/mfev_50000_policy_valid.csv`
- ACN rows: 30000
- MFEV rows: 50000
- Reserve margin: 0.05
- Repeat: 5

## Tariff models

- `native_committed`: uses dataset committed amount and preauthorization fields.
- `flat`: delivered energy multiplied by row-level unit price.
- `tou`: flat energy price with representative off-peak/mid/peak multipliers.
- `session_fee`: flat energy price plus a dataset-scaled session fee.
- `idle_fee`: flat energy price plus duration-derived idle fee.
- `roaming_markup`: TOU amount plus session component and roaming markup.
- `stress_mixed`: TOU + session fee + idle fee with stress markup.

## Reserve policies

- `native_preauth`: uses the dataset preauthorization field.
- `tariff_aware`: reserves the current tariff amount with the configured margin.
- `flat_estimate`: reserves the flat tariff amount with the configured margin while actual settlement follows the selected richer tariff model.

## Fairness note

This benchmark is a tariff-sensitivity and reserve/top-up stress test. It does not claim to reproduce every production tariff or market price. The monetary units remain dataset-specific: ACN uses deterministic protocol amounts, whereas MFEV uses its processed monetary scale. The main comparison is therefore within each dataset across tariff policies, not between ACN and MFEV currencies.
