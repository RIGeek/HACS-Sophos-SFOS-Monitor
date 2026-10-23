"""Config-flow form validation and reconfigure."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.sophos_sfos.const import CONF_COMMUNITY, CONF_SNMP_VERSION, DOMAIN

from .conftest import SIM_COMMUNITY, SIM_HOST, SIM_PORT


async def test_v3_form_validation(hass: HomeAssistant) -> None:
    """Short keys and encryption-without-auth are caught before any SNMP traffic."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: SIM_HOST, CONF_PORT: SIM_PORT, CONF_SNMP_VERSION: "3"}
    )
    assert result["step_id"] == "v3"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"v3_username": "ha", "auth_protocol": "sha256", "auth_key": "short", "priv_protocol": "aes", "priv_key": "longenough"},
    )
    assert result["errors"] == {"auth_key": "key_too_short"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"v3_username": "ha", "auth_protocol": "none", "auth_key": "", "priv_protocol": "aes", "priv_key": "longenough"},
    )
    assert result["errors"] == {"priv_protocol": "priv_needs_auth"}


async def test_reconfigure(hass: HomeAssistant) -> None:
    """Reconfigure updates connection data without touching the selection."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: SIM_HOST, CONF_PORT: SIM_PORT, CONF_SNMP_VERSION: "2c"}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_COMMUNITY: SIM_COMMUNITY})
    entry = result["result"]
    await hass.async_block_till_done()
    options_before = dict(entry.options)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_RECONFIGURE, "entry_id": entry.entry_id}
    )
    assert result["step_id"] == "reconfigure"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: SIM_HOST, CONF_PORT: SIM_PORT, CONF_SNMP_VERSION: "1"}
    )
    assert result["step_id"] == "community"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_COMMUNITY: SIM_COMMUNITY})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data[CONF_SNMP_VERSION] == "1"
    assert dict(entry.options) == options_before
    assert await hass.config_entries.async_unload(entry.entry_id)
