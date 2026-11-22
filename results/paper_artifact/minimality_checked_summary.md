# Checked minimality analysis

Analysis tool `dbas_et/dvas/minimality.py`; runner `scripts/dvas/run_minimality_checked.py`. The runtime selector is unchanged and claims **sufficiency only**.

Valid semantic domain: STRING: non-empty NFC strings; ENUM: registered values only; FIXED6: >= 0; TIMESTAMP: integers. Evidence: real session evidence plus tightened variants that make bound atoms active.

Contexts: 15 real sessions (10 ACN + 5 MFEV).

A witness (c1, c2, e), with c1 and c2 differing only in f and a different outcome, is a constructive proof that f is necessary. A non-necessity certificate is a proof that f is NOT necessary. A missing witness alone proves nothing (UNRESOLVED).

| predicate | \|F_r\| | classification | Boolean witnesses | decision witnesses | non-necessity certificates |
|---|---|---|---|---|---|
| authorization | 21 | **NOT_MINIMAL** | 20/21 | 20/21 | payment_semantics: SINGLETON_DOMAIN |
| replay | 3 | **BOOLEAN_MINIMAL** | 3/3 | 3/3 | - |
| station_meter_binding | 4 | **BOOLEAN_MINIMAL** | 4/4 | 4/4 | - |
| pricing | 6 | **DECISION_MINIMAL_ONLY** | 4/6 | 6/6 | tariff_mode: VACUOUS_ATOM:amount_defined, unit_price: VACUOUS_ATOM:amount_defined |
| time_window | 3 | **BOOLEAN_MINIMAL** | 3/3 | 3/3 | - |
| delivery_cap | 2 | **BOOLEAN_MINIMAL** | 2/2 | 2/2 | - |
| reserve_amount | 4 | **BOOLEAN_MINIMAL** | 4/4 | 4/4 | - |
| settlement | 15 | **BOOLEAN_MINIMAL** | 15/15 | 15/15 | - |
| dispute:over_cap | 4 | **BOOLEAN_MINIMAL** | 4/4 | 4/4 | - |
| dispute:tariff_mismatch | 3 | **BOOLEAN_MINIMAL** | 3/3 | 3/3 | - |
| dispute:time_window | 3 | **BOOLEAN_MINIMAL** | 3/3 | 3/3 | - |
| dispute:amount_exceeds_preauth | 4 | **BOOLEAN_MINIMAL** | 4/4 | 4/4 | - |
| dispute:replay | 3 | **BOOLEAN_MINIMAL** | 3/3 | 3/3 | - |

Lemmas used:
- `amount_defined`: Tariff(mode, price, kWh, durations) >= 0 for all valid-domain inputs: it is a sum of products of non-negative quantities (price >= 0, kWh >= 0, durations >= 0, rates >= 0).
- `SINGLETON_DOMAIN`: a field whose valid domain has one value cannot distinguish two valid assignments.

Classification rules: BOOLEAN_MINIMAL = every operand has a Boolean witness; DECISION_MINIMAL_ONLY = every operand has a decision witness (truth value or derived amount) and every operand without a Boolean witness carries a Boolean non-necessity certificate; NOT_MINIMAL = some operand has a decision non-necessity certificate; otherwise UNRESOLVED.

These results are properties of the specific predicates under the stated domain. They are not a general minimality claim for the selector, and protocol semantics were not changed to make them minimal.
