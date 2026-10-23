"""Test fixtures.

The integration tests talk to a real SNMP agent: start snmpsim with the
synthetic SFOS data in tests/fixtures/sfos.snmprec, e.g.

    snmpsim-command-responder --data-dir=tests/fixtures \
        --agent-udpv4-endpoint=127.0.0.1:1161

and run `pytest`. Set SFOS_SIM_PORT to use another port.
"""

from __future__ import annotations

import os

import pytest

SIM_HOST = "127.0.0.1"
SIM_PORT = int(os.environ.get("SFOS_SIM_PORT", "1161"))
SIM_COMMUNITY = "sfos"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations in all tests."""
    yield


@pytest.fixture(autouse=True)
def _allow_udp(socket_enabled):
    """The tests need real UDP sockets to reach the SNMP simulator."""
    yield
