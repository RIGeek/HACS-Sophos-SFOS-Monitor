"""Data update coordinator for Sophos SFOS Monitor."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import Discovery, ItemValue, Selection, SfosMonitor
from .const import (
    CONF_ACCESS_POINTS,
    CONF_AUTH_KEY,
    CONF_AUTH_PROTOCOL,
    CONF_COMMUNITY,
    CONF_CUSTOM_OIDS,
    CONF_HA_ITEMS,
    CONF_HARDWARE_ITEMS,
    CONF_INTERFACE_METRICS,
    CONF_INTERFACES,
    CONF_LICENSE_ITEMS,
    CONF_PRIV_KEY,
    CONF_PRIV_PROTOCOL,
    CONF_RETRIES,
    CONF_SCAN_INTERVAL,
    CONF_SERVICE_ITEMS,
    CONF_SNMP_VERSION,
    CONF_SYSTEM_ITEMS,
    CONF_TIMEOUT,
    CONF_V3_USERNAME,
    CONF_VPN_METRICS,
    CONF_VPN_TUNNELS,
    DEFAULT_PORT,
    DEFAULT_RETRIES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
)
from .snmp import SnmpAuthError, SnmpClient, SnmpError, SnmpSettings, create_engine

_LOGGER = logging.getLogger(__name__)

type SfosConfigEntry = ConfigEntry[SfosCoordinator]

ENGINE_KEY = f"{DOMAIN}_engine"


async def async_get_engine(hass: HomeAssistant):
    """Return a shared SnmpEngine (created once, in the executor)."""
    engine = hass.data.get(ENGINE_KEY)
    if engine is None:
        engine = await hass.async_add_executor_job(create_engine)
        hass.data[ENGINE_KEY] = engine
    return engine


def settings_from(data: dict[str, Any], options: dict[str, Any] | None = None) -> SnmpSettings:
    """Build SnmpSettings from entry data + options."""
    options = options or {}
    return SnmpSettings(
        host=data[CONF_HOST],
        port=int(data.get(CONF_PORT, DEFAULT_PORT)),
        version=data[CONF_SNMP_VERSION],
        community=data.get(CONF_COMMUNITY),
        username=data.get(CONF_V3_USERNAME),
        auth_protocol=data.get(CONF_AUTH_PROTOCOL, "none"),
        auth_key=data.get(CONF_AUTH_KEY),
        priv_protocol=data.get(CONF_PRIV_PROTOCOL, "none"),
        priv_key=data.get(CONF_PRIV_KEY),
        timeout=float(options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)),
        retries=int(options.get(CONF_RETRIES, DEFAULT_RETRIES)),
    )


def selection_from_options(options: dict[str, Any]) -> Selection:
    """Translate entry options into a Selection."""
    hardware = list(options.get(CONF_HARDWARE_ITEMS, []))
    return Selection(
        scalars={
            "system": list(options.get(CONF_SYSTEM_ITEMS, [])),
            "services": list(options.get(CONF_SERVICE_ITEMS, [])),
            "licenses": list(options.get(CONF_LICENSE_ITEMS, [])),
            "ha": list(options.get(CONF_HA_ITEMS, [])),
            "hardware": [h for h in hardware if "|" not in h],
        },
        interfaces=list(options.get(CONF_INTERFACES, [])),
        interface_metrics=list(options.get(CONF_INTERFACE_METRICS, [])),
        vpn_tunnels=list(options.get(CONF_VPN_TUNNELS, [])),
        vpn_metrics=list(options.get(CONF_VPN_METRICS, [])),
        access_points=list(options.get(CONF_ACCESS_POINTS, [])),
        fans=[h.split("|", 1)[1] for h in hardware if h.startswith("fan|")],
        psus=[h.split("|", 1)[1] for h in hardware if h.startswith("psu|")],
        custom=list(options.get(CONF_CUSTOM_OIDS, [])),
    )


class SfosCoordinator(DataUpdateCoordinator[dict[str, ItemValue]]):
    """Polls the firewall on a fixed interval."""

    config_entry: SfosConfigEntry

    def __init__(self, hass: HomeAssistant, entry: SfosConfigEntry, client: SnmpClient) -> None:
        """Initialize."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} {entry.data[CONF_HOST]}",
            update_interval=timedelta(
                seconds=int(entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
            ),
        )
        self.client = client
        self.monitor = SfosMonitor(client)
        self.selection = selection_from_options(dict(entry.options))
        self.device: dict[str, Any] = {}
        self.discovery: Discovery | None = None

    async def _async_setup(self) -> None:
        """Fetch identity once before the first refresh."""
        try:
            self.device = await self.monitor.device_info()
        except SnmpAuthError as err:
            raise UpdateFailed(f"SNMP authentication failed: {err}") from err
        except SnmpError as err:
            raise UpdateFailed(f"Firewall did not answer SNMP: {err}") from err

    async def _async_update_data(self) -> dict[str, ItemValue]:
        try:
            return await self.monitor.poll(self.selection)
        except SnmpError as err:
            raise UpdateFailed(f"Error polling {self.client.settings.host}: {err}") from err

    async def async_discover(self) -> Discovery:
        """Run (and cache) a full discovery."""
        self.discovery = await self.monitor.discover()
        return self.discovery
