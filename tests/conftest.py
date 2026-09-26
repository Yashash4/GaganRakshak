"""Tests marked ``sitl`` fly ArduPilot SITL; they skip when no SITL build is present."""

import pytest

from gaganrakshak import sitl


def pytest_collection_modifyitems(config, items):
    if sitl.BINARY.exists():
        return
    skip = pytest.mark.skip(reason=f"ArduPilot SITL not built ({sitl.BINARY})")
    for item in items:
        if "sitl" in item.keywords:
            item.add_marker(skip)
