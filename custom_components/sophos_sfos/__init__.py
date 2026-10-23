"""Sophos SFOS Monitor — monitor a Sophos Firewall (SFOS) over SNMP."""

from __future__ import annotations

import logging

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .const import DOMAIN
from .coordinator import SfosConfigEntry, SfosCoordinator, async_get_engine, settings_from
from .entity import build_specs
from .snmp import SnmpClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: SfosConfigEntry) -> bool:
    """Set up a firewall from a config entry."""
    engine = await async_get_engine(hass)
    client = SnmpClient(engine, settings_from(dict(entry.data), dict(entry.options)))
    coordinator = SfosCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    _remove_deselected(hass, entry, coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SfosConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        entry.runtime_data.client.close()
    return unloaded


async def _async_options_updated(hass: HomeAssistant, entry: SfosConfigEntry) -> None:
    """Reload so the new selection takes effect."""
    await hass.config_entries.async_reload(entry.entry_id)


def _remove_deselected(hass: HomeAssistant, entry: SfosConfigEntry, coordinator: SfosCoordinator) -> None:
    """Delete entities (and interface devices) the user removed from monitoring."""
    base_id = entry.unique_id or entry.entry_id
    specs = build_specs(coordinator.selection)
    expected = {f"{base_id}_{spec.key}" for spec in specs}

    ent_reg = er.async_get(hass)
    for ent in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
        if ent.unique_id not in expected:
            _LOGGER.debug("Removing deselected entity %s", ent.entity_id)
            ent_reg.async_remove(ent.entity_id)

    expected_devices = {(DOMAIN, base_id)} | {
        (DOMAIN, f"{base_id}_{spec.sub_device[0]}_{spec.sub_device[1]}")
        for spec in specs
        if spec.sub_device
    }
    dev_reg = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(dev_reg, entry.entry_id):
        if not device.identifiers & expected_devices:
            dev_reg.async_update_device(device.id, remove_config_entry_id=entry.entry_id)
