"""Diagnostics download for Sophos SFOS Monitor."""

from __future__ import annotations

import asyncio
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_AUTH_KEY, CONF_COMMUNITY, CONF_PRIV_KEY, CONF_V3_USERNAME
from .coordinator import SfosConfigEntry

TO_REDACT = {CONF_COMMUNITY, CONF_AUTH_KEY, CONF_PRIV_KEY, CONF_V3_USERNAME, "serial"}


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: SfosConfigEntry) -> dict[str, Any]:
    """Return diagnostics, including a fresh discovery of what the firewall reports."""
    coordinator = entry.runtime_data
    try:
        async with asyncio.timeout(60):
            disc = (await coordinator.async_discover()).as_dict()
    except Exception as err:  # noqa: BLE001
        disc = {"error": str(err)}
    return {
        "entry": {
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": dict(entry.options),
        },
        "device": async_redact_data(coordinator.device, TO_REDACT),
        "discovery": async_redact_data(disc, TO_REDACT),
        "last_update_success": coordinator.last_update_success,
        "data": {k: {"value": str(v.value), "attributes": v.attributes} for k, v in (coordinator.data or {}).items()},
    }
