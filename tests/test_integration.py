"""End-to-end tests against the snmpsim SFOS simulator."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr, entity_registry as er

from custom_components.sophos_sfos.const import (
    CONF_COMMUNITY,
    CONF_CUSTOM_OIDS,
    CONF_INTERFACE_METRICS,
    CONF_INTERFACES,
    CONF_SNMP_VERSION,
    CONF_SYSTEM_ITEMS,
    DOMAIN,
)

from .conftest import SIM_COMMUNITY, SIM_HOST, SIM_PORT


async def _create_entry(hass: HomeAssistant, community: str = SIM_COMMUNITY):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: SIM_HOST, CONF_PORT: SIM_PORT, CONF_SNMP_VERSION: "2c"}
    )
    assert result["step_id"] == "community"
    return await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_COMMUNITY: community})


def _uid(entity_suffix: str) -> str:
    return f"S4000ABCDEF1234_{entity_suffix}"


async def test_bad_community(hass: HomeAssistant) -> None:
    """A wrong community times out and reports cannot_connect."""
    entry = hass.config_entries.async_entries(DOMAIN)
    assert not entry
    from custom_components.sophos_sfos import coordinator as coord

    # keep the test quick
    orig = coord.settings_from

    def fast(data, options=None):
        s = orig(data, options)
        s.timeout, s.retries = 1, 0
        return s

    import custom_components.sophos_sfos.config_flow as cf

    cf.settings_from = fast
    try:
        result = await _create_entry(hass, "wrong-community")
    finally:
        cf.settings_from = orig
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_setup_and_options(hass: HomeAssistant) -> None:
    """Create, verify entities, then add and remove items through the options dialog."""
    result = await _create_entry(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    assert result["title"] == "HOME-XG"
    entry = result["result"]
    assert entry.unique_id == "S4000ABCDEF1234"
    # defaults chosen from what the firewall reported
    assert "cpu_usage" in entry.options[CONF_SYSTEM_ITEMS]
    assert entry.options[CONF_INTERFACES] == ["Port1", "Port2", "Port1.10", "ipsec0"]
    assert "base_firewall" in entry.options["license_items"]
    assert "sandstorm" not in entry.options["license_items"]  # expired -> not default
    await hass.async_block_till_done()

    ent_reg = er.async_get(hass)

    def state_of(uid_suffix: str, platform: str = "sensor"):
        entity_id = ent_reg.async_get_entity_id(platform, DOMAIN, _uid(uid_suffix))
        assert entity_id, f"missing {uid_suffix}"
        return hass.states.get(entity_id)

    assert float(state_of("system|cpu_usage").state) == 14.0
    assert state_of("system|cpu_usage").attributes["cores"] == 4
    assert state_of("system|memory_usage").state == "41"
    assert state_of("system|firmware").state == "SFOS 22.0.1 GA-Build 411"
    assert state_of("services|ipsec").state == "running"
    assert state_of("licenses|base_firewall").state == "subscribed"
    assert state_of("licenses|base_firewall").attributes["expiry_date"] == "Dec 31 2999"
    assert state_of("if|Port2|status", "binary_sensor").state == "on"
    assert state_of("vpn|Office-S2S|connected", "binary_sensor").state == "on"
    assert state_of("vpn|Cabin-Link|connected", "binary_sensor").state == "off"
    # first poll has no rate yet (needs two samples)
    assert state_of("if|Port2|rx_rate").state == "unavailable"

    # Interfaces have their own devices
    dev_reg = dr.async_get(hass)
    port2 = dev_reg.async_get_device(identifiers={(DOMAIN, "S4000ABCDEF1234_if_Port2")})
    assert port2 is not None and port2.name == "HOME-XG Port2"

    # Second poll -> rates
    coordinator = entry.runtime_data
    import asyncio

    await asyncio.sleep(1.5)
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    rx = float(state_of("if|Port2|rx_rate").state)
    assert 20 < rx < 40, rx  # simulator: 3.75 MB/s = 30 Mbit/s

    # ---- Options dialog ----
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.MENU
    assert "interfaces" in result["menu_options"]
    assert "vpn" in result["menu_options"]
    assert "access_points" not in result["menu_options"]  # none reported
    assert "custom_remove" not in result["menu_options"]  # none yet

    # remove Port1.10 and ipsec0, add Port3; add rx_total metric
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "interfaces"})
    assert result["type"] is FlowResultType.FORM
    schema_keys = {str(k) for k in result["data_schema"].schema}
    assert CONF_INTERFACES in schema_keys
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {CONF_INTERFACES: ["Port1", "Port2", "Port3"], CONF_INTERFACE_METRICS: ["status", "rx_rate", "tx_rate", "rx_total", "ip_address"]},
    )
    assert result["type"] is FlowResultType.MENU

    # add load average, remove swap
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "system"})
    current = [k for k in entry.options[CONF_SYSTEM_ITEMS] if k != "swap_usage"] + ["load_1"]
    result = await hass.config_entries.options.async_configure(result["flow_id"], {CONF_SYSTEM_ITEMS: current})

    # add a custom OID (bad one first)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "custom_add"})
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"name": "Bogus", "oid": "1.3.6.1.9.9.9.0", "mode": "number"}
    )
    assert result["errors"] == {"oid": "oid_no_value"}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"name": "Bogus", "oid": "not-an-oid", "mode": "number"}
    )
    assert result["errors"] == {"oid": "invalid_oid"}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"name": "WAN bytes in", "oid": ".1.3.6.1.2.1.31.1.1.1.6.3", "mode": "rate", "unit": "Mbit/s", "scale": 0.000008, "device_class": "data_rate", "state_class": "measurement"},
    )
    assert result["type"] is FlowResultType.MENU
    assert "custom_remove" in result["menu_options"]

    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "save"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    assert entry.options[CONF_INTERFACES] == ["Port1", "Port2", "Port3"]
    assert len(entry.options[CONF_CUSTOM_OIDS]) == 1

    # entities for removed items are gone, new ones exist
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, _uid("if|Port1.10|rx_rate")) is None
    assert ent_reg.async_get_entity_id("binary_sensor", DOMAIN, _uid("if|ipsec0|status")) is None
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, _uid("system|swap_usage")) is None
    assert dev_reg.async_get_device(identifiers={(DOMAIN, "S4000ABCDEF1234_if_Port1.10")}) is None
    assert state_of("if|Port3|status", "binary_sensor").state == "off"
    assert state_of("if|Port2|ip_address").state == "203.0.113.45"
    assert float(state_of("if|Port2|rx_total").state) > 0
    assert float(state_of("system|load_1").state) == 0.42
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, _uid("custom|wan_bytes_in"))

    # remove the custom OID again
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "custom_remove"})
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"remove": ["wan_bytes_in"]})
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "save"})
    await hass.async_block_till_done()
    assert entry.options[CONF_CUSTOM_OIDS] == []
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, _uid("custom|wan_bytes_in")) is None

    # duplicate firewall is rejected
    result = await _create_entry(hass)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"

    assert await hass.config_entries.async_unload(entry.entry_id)
