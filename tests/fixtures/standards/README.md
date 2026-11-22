Representative OCPI 2.2.1 (Token, Location/EVSE, Tariff) and OCPP 2.0.1
(TransactionEvent with signedMeterValue) objects used by
`tests/dvas/test_standards_adapter.py`. They are hand-written examples shaped like
the standards, not captured traffic. The OCMF signature fields are placeholders and
are not verified by the adapter. Only their digest is bound into DR_private.
