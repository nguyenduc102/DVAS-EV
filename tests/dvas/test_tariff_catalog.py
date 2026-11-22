"""The tariff catalog is functional in (station, tariff_id, version) (assumption A2)."""
from __future__ import annotations

from decimal import Decimal

import pytest

from dbas_et.dvas.registry import KeyRegistry


def test_republishing_identical_tariff_is_idempotent():
    reg = KeyRegistry()
    reg.publish_tariff("ST1", "T1", "v1", "energy", Decimal("0.300000"), "USD")
    reg.publish_tariff("ST1", "T1", "v1", "energy", Decimal("0.300000"), "USD")
    assert len(reg.tariffs) == 1
    assert reg.relations()["tariff_published"]("ST1", "T1", "v1", "energy", Decimal("0.300000"), "USD")


def test_conflicting_terms_for_same_key_are_rejected():
    reg = KeyRegistry()
    reg.publish_tariff("ST1", "T1", "v1", "energy", Decimal("0.300000"), "USD")
    with pytest.raises(ValueError, match="different terms"):
        reg.publish_tariff("ST1", "T1", "v1", "energy", Decimal("0.310000"), "USD")
    # A new version or another station remains publishable.
    reg.publish_tariff("ST1", "T1", "v2", "energy", Decimal("0.310000"), "USD")
    reg.publish_tariff("ST2", "T1", "v1", "energy", Decimal("0.310000"), "USD")
    assert len(reg.tariffs) == 3
