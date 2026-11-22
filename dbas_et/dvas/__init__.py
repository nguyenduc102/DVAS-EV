"""
DVAS-EV protocol core.

Built on top of the earlier DBAS-ET prototype. The legacy pipeline in ``dbas_et``
is left unchanged.

- ``canonical``   single deterministic canonical encoder + field lifecycle
- ``schema``      committed layout schema (field IDs, types, lifecycle)
- ``predicates``  restricted predicate language and dependency registry
                  (Predicate-Sufficient Projection Compiler, PA-MSP)
- ``pam``         PAM-Proof: predicate-complete authenticated openings over a
                  standard binary Merkle tree (independent paths or packed
                  multiproof)
- ``registry``    key/role registry with epochs, rotation and revocation
- ``profiles``    classical / hybrid post-quantum cryptographic profiles
- ``delivery``    meter-signed public receipt bound to the private payload
                  digest ``h_priv``
- ``evidence``    single-ciphertext multi-recipient private evidence envelope
- ``verifier``    independent settlement verifiers and attestations
- ``rbc``         quorum receipt-binding certificate (RBC_body + attestations)
- ``ledger``      contract-state simulation (authorize / session / receipt /
                  top-up / quorum settlement)
- ``protocol``    end-to-end orchestration of one charging session.

Scope: local protocol-processing simulator. Not a production OCPP/OCPI
backend, not zero-knowledge, not fully post-quantum when ECDSA paths remain.
"""

PROTOCOL_ID = "DVAS-EV"
PROTOCOL_VERSION = "DVAS-EV/2.0"
