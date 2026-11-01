"""Tests running inside the actual Home Assistant test framework."""

import pytest


@pytest.fixture(autouse=True)
def enable_packin(enable_custom_integrations):
    yield
