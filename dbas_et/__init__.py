"""
DBAS-ET: Delivery-Bound Authorization and Settlement for Energy Trading.

Scope
-----
This package implements a reproducible protocol simulator for:

- capsule commitment and projection-carrying authorization,
- delivery-receipt-bound settlement,
- pre-authorized reserve-release payment,
- dynamic top-up authorization,
- dispute and attack evaluation,
- ACN-driven benchmark generation.

This is not a production EV charging backend.

Payment terminology
-------------------
`allowcap_t` or `preauth_limit_t` means a pre-authorized payment limit.
It is not the final captured payment.

`held_amount` means the amount temporarily reserved.

`captured_amount` means the final amount released to the station after a valid
delivery receipt is verified.

`released_unused_hold` means the unused held amount returned to the user.
"""

__version__ = "0.1.0"

from .entities import Meter, Station, User, ValidatorNode
from .admission import AdmissionCertificate
from .settlement_verifier import SettlementVerifier, ReceiptBindingCertificatePublic
from .result import (
    Err,
    Ok,
    ProtocolResult,
    ProtocolStatus,
    RejectReason,
    Result,
)

__all__ = [
    "Result",
    "Ok",
    "Err",
    "ProtocolResult",
    "ProtocolStatus",
    "RejectReason",
    "User",
    "Station",
    "Meter",
    "ValidatorNode",
    "AdmissionCertificate",
    "SettlementVerifier",
    "ReceiptBindingCertificatePublic",
]