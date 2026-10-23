"""Config and options flows for Sophos SFOS Monitor."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.util import slugify

from . import catalog as cat
from .api import Discovery, SfosMonitor, item_id
from .const import (
    AUTH_PROTOCOLS,
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
    CUSTOM_DEVICE_CLASS,
    CUSTOM_MODE,
    CUSTOM_MODE_NUMBER,
    CUSTOM_MODE_TEXT,
    CUSTOM_MODES,
    CUSTOM_NAME,
    CUSTOM_OID,
    CUSTOM_SCALE,
    CUSTOM_STATE_CLASS,
    CUSTOM_UNIT,
    DEFAULT_COMMUNITY,
    DEFAULT_PORT,
    DEFAULT_RETRIES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    PRIV_PROTOCOLS,
    SNMP_V3,
    SNMP_VERSIONS,
)
from .coordinator import async_get_engine, settings_from
from .snmp import SnmpAuthError, SnmpClient, SnmpError, is_valid_oid, normalize_oid

_LOGGER = logging.getLogger(__name__)

DISCOVERY_TIMEOUT = 60

# option key -> discovery category for the plain scalar lists
SCALAR_OPTION_KEYS = {
    CONF_SYSTEM_ITEMS: "system",
    CONF_SERVICE_ITEMS: "services",
    CONF_LICENSE_ITEMS: "licenses",
    CONF_HA_ITEMS: "ha",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _multi(options: list[SelectOptionDict]) -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(options=options, multiple=True, mode=SelectSelectorMode.LIST)
    )


def _dropdown(values: list[str], translation_key: str | None = None) -> SelectSelector:
    config = SelectSelectorConfig(options=values, mode=SelectSelectorMode.DROPDOWN)
    if translation_key:
        config["translation_key"] = translation_key
    return SelectSelector(config)


def _none_to_empty(value: Any) -> str:
    return "" if value in (None, "", "none") else str(value)


_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def default_options(disc: Discovery) -> dict[str, Any]:
    """Sensible starting selection based on what the firewall answered to."""
    opts: dict[str, Any] = {
        CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
        CONF_TIMEOUT: DEFAULT_TIMEOUT,
        CONF_RETRIES: DEFAULT_RETRIES,
    }
    for opt_key, category in SCALAR_OPTION_KEYS.items():
        available = disc.scalars.get(category, set())
        opts[opt_key] = [k for k, item in cat.SCALAR_CATALOG[category].items() if item.default and k in available]
    # Services: default to the ones that are actually running (skip mail/untouched)
    running = [
        k
        for k in sorted(disc.scalars.get("services", set()))
        if disc.scalar_values.get(item_id("services", k)) == 3 and k in ("ipsec", "sslvpn", "dns", "ips", "antivirus", "dgd")
    ]
    opts[CONF_SERVICE_ITEMS] = running
    # Licenses: the ones that are subscribed or in evaluation
    opts[CONF_LICENSE_ITEMS] = [
        k
        for k in cat.SCALAR_CATALOG["licenses"]
        if k in disc.scalars.get("licenses", set())
        and disc.scalar_values.get(item_id("licenses", k)) in (1, 3)
    ]
    opts[CONF_HARDWARE_ITEMS] = sorted(disc.scalars.get("hardware", set()))
    # Interfaces: everything that is up and isn't loopback
    opts[CONF_INTERFACES] = [
        k
        for k, i in disc.interfaces.items()
        if i.oper == "up" and i.if_type != cat.IF_TYPE_LOOPBACK and i.name.lower() != "lo"
    ]
    opts[CONF_INTERFACE_METRICS] = [k for k, m in cat.INTERFACE_METRICS.items() if m.default]
    opts[CONF_VPN_TUNNELS] = list(disc.vpn_tunnels)
    opts[CONF_VPN_METRICS] = [k for k, m in cat.VPN_METRICS.items() if m.default]
    opts[CONF_ACCESS_POINTS] = list(disc.access_points)
    opts[CONF_CUSTOM_OIDS] = []
    return opts


async def _validate(hass, data: dict[str, Any]) -> tuple[SfosMonitor, dict[str, Any]]:
    engine = await async_get_engine(hass)
    client = SnmpClient(engine, settings_from(data))
    monitor = SfosMonitor(client)
    info = await monitor.device_info()
    if all(v in (None, "", False) for v in info.values()):
        raise SnmpError("empty response")
    return monitor, info


def _connection_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_PORT, default=defaults.get(CONF_PORT, DEFAULT_PORT)): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_SNMP_VERSION, default=defaults.get(CONF_SNMP_VERSION, "2c")): _dropdown(
                SNMP_VERSIONS, "snmp_version"
            ),
        }
    )


def _community_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {vol.Required(CONF_COMMUNITY, default=defaults.get(CONF_COMMUNITY, DEFAULT_COMMUNITY)): _PASSWORD}
    )


def _v3_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_V3_USERNAME, default=defaults.get(CONF_V3_USERNAME, "")): str,
            vol.Required(CONF_AUTH_PROTOCOL, default=defaults.get(CONF_AUTH_PROTOCOL, "sha256")): _dropdown(
                AUTH_PROTOCOLS, "auth_protocol"
            ),
            vol.Optional(CONF_AUTH_KEY, default=defaults.get(CONF_AUTH_KEY, "")): _PASSWORD,
            vol.Required(CONF_PRIV_PROTOCOL, default=defaults.get(CONF_PRIV_PROTOCOL, "aes")): _dropdown(
                PRIV_PROTOCOLS, "priv_protocol"
            ),
            vol.Optional(CONF_PRIV_KEY, default=defaults.get(CONF_PRIV_KEY, "")): _PASSWORD,
        }
    )


def _v3_errors(data: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    if data.get(CONF_AUTH_PROTOCOL, "none") != "none" and len(data.get(CONF_AUTH_KEY) or "") < 8:
        errors[CONF_AUTH_KEY] = "key_too_short"
    if data.get(CONF_PRIV_PROTOCOL, "none") != "none":
        if data.get(CONF_AUTH_PROTOCOL, "none") == "none":
            errors[CONF_PRIV_PROTOCOL] = "priv_needs_auth"
        elif len(data.get(CONF_PRIV_KEY) or "") < 8:
            errors[CONF_PRIV_KEY] = "key_too_short"
    return errors


# --------------------------------------------------------------------------
# Config flow
# --------------------------------------------------------------------------
class SfosConfigFlow(ConfigFlow, domain=DOMAIN):
    """Add a Sophos firewall."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._data: dict[str, Any] = {}

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> SfosOptionsFlow:
        """Options flow."""
        return SfosOptionsFlow()

    # ---- step 1: where ----
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Host, port and SNMP version."""
        if user_input is not None:
            self._data = {**user_input, CONF_HOST: user_input[CONF_HOST].strip()}
            return await self.async_step_credentials()
        return self.async_show_form(step_id="user", data_schema=_connection_schema(self._data))

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Change host / port / version / credentials of an existing entry."""
        entry = self._get_reconfigure_entry()
        if user_input is not None:
            self._data = {**entry.data, **user_input, CONF_HOST: user_input[CONF_HOST].strip()}
            return await self.async_step_credentials()
        return self.async_show_form(step_id="reconfigure", data_schema=_connection_schema(dict(entry.data)))

    # ---- step 2: credentials ----
    async def async_step_credentials(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Route to the right credential form."""
        if self._data[CONF_SNMP_VERSION] == SNMP_V3:
            return await self.async_step_v3()
        return await self.async_step_community()

    async def async_step_community(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """SNMP v1/v2c community."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._data.update(user_input)
            for key in (CONF_V3_USERNAME, CONF_AUTH_KEY, CONF_PRIV_KEY, CONF_AUTH_PROTOCOL, CONF_PRIV_PROTOCOL):
                self._data.pop(key, None)
            result = await self._async_finish(errors)
            if result:
                return result
        return self.async_show_form(
            step_id="community",
            data_schema=_community_schema(self._data),
            errors=errors,
            description_placeholders={"host": self._data[CONF_HOST]},
        )

    async def async_step_v3(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """SNMPv3 USM credentials."""
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = _v3_errors(user_input)
            self._data.update(user_input)
            self._data.pop(CONF_COMMUNITY, None)
            if not errors:
                result = await self._async_finish(errors)
                if result:
                    return result
        return self.async_show_form(
            step_id="v3",
            data_schema=_v3_schema(self._data),
            errors=errors,
            description_placeholders={"host": self._data[CONF_HOST]},
        )

    async def _async_finish(self, errors: dict[str, str]) -> ConfigFlowResult | None:
        try:
            monitor, info = await _validate(self.hass, self._data)
        except SnmpAuthError:
            errors["base"] = "invalid_auth"
            return None
        except SnmpError as err:
            _LOGGER.debug("SNMP validation failed: %s", err)
            errors["base"] = "cannot_connect"
            return None
        except Exception:
            _LOGGER.exception("Unexpected error validating SNMP connection")
            errors["base"] = "unknown"
            return None

        if self.source == "reconfigure":
            return self.async_update_reload_and_abort(self._get_reconfigure_entry(), data=self._data)

        await self.async_set_unique_id(str(info.get("serial") or self._data[CONF_HOST]))
        self._abort_if_unique_id_configured(updates={CONF_HOST: self._data[CONF_HOST]})

        try:
            async with asyncio.timeout(DISCOVERY_TIMEOUT):
                disc = await monitor.discover()
            options = default_options(disc)
        except (SnmpError, TimeoutError) as err:
            _LOGGER.warning("Discovery failed, starting with an empty selection: %s", err)
            options = default_options(Discovery())
        title = str(info.get("name") or info.get("sys_name") or self._data[CONF_HOST])
        return self.async_create_entry(title=title, data=self._data, options=options)


# --------------------------------------------------------------------------
# Options flow: the "monitored items" settings dialog
# --------------------------------------------------------------------------
class SfosOptionsFlow(OptionsFlow):
    """Pick, add and remove monitored items."""

    def __init__(self) -> None:
        """Initialize."""
        self._options: dict[str, Any] | None = None
        self._disc: Discovery | None = None
        self._disc_error: str | None = None

    async def _ensure_loaded(self) -> None:
        if self._options is not None:
            return
        self._options = dict(self.config_entry.options)
        try:
            coordinator = getattr(self.config_entry, "runtime_data", None)
            if coordinator is not None:
                monitor = coordinator.monitor
            else:
                engine = await async_get_engine(self.hass)
                monitor = SfosMonitor(
                    SnmpClient(engine, settings_from(dict(self.config_entry.data), self._options))
                )
            async with asyncio.timeout(DISCOVERY_TIMEOUT):
                self._disc = await monitor.discover()
        except (SnmpError, TimeoutError) as err:
            self._disc_error = str(err) or "timeout"
            _LOGGER.warning("Discovery for options failed: %s", err)

    def _summary(self) -> str:
        if self._disc is None:
            return f"⚠️ Could not reach the firewall ({self._disc_error}). Only already-selected items are shown."
        d = self._disc
        found = sum(len(v) for v in d.scalars.values())
        return (
            f"Found {found} system/service/license values, {len(d.interfaces)} interfaces, "
            f"{len(d.vpn_tunnels)} IPsec connections, {len(d.access_points)} access points."
        )

    def _count(self, key: str) -> int:
        return len((self._options or {}).get(key, []))

    # ---------------- menu ----------------
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Main menu."""
        await self._ensure_loaded()
        d = self._disc
        menu = ["system", "services", "licenses"]
        if (d and d.scalars.get("ha")) or self._count(CONF_HA_ITEMS):
            menu.append("high_availability")
        if (d and (d.scalars.get("hardware") or d.fans or d.psus)) or self._count(CONF_HARDWARE_ITEMS):
            menu.append("hardware")
        menu.append("interfaces")
        if (d and d.vpn_tunnels) or self._count(CONF_VPN_TUNNELS):
            menu.append("vpn")
        if (d and d.access_points) or self._count(CONF_ACCESS_POINTS):
            menu.append("access_points")
        menu.append("custom_add")
        if self._count(CONF_CUSTOM_OIDS):
            menu.append("custom_remove")
        menu += ["polling", "save"]
        assert self._options is not None
        return self.async_show_menu(
            step_id="init",
            menu_options=menu,
            description_placeholders={
                "summary": self._summary(),
                "selected": (
                    f"{self._count(CONF_SYSTEM_ITEMS)} system, {self._count(CONF_SERVICE_ITEMS)} services, "
                    f"{self._count(CONF_LICENSE_ITEMS)} licenses, {self._count(CONF_INTERFACES)} interfaces × "
                    f"{self._count(CONF_INTERFACE_METRICS)} metrics, {self._count(CONF_VPN_TUNNELS)} VPN, "
                    f"{self._count(CONF_CUSTOM_OIDS)} custom OIDs"
                ),
            },
        )

    async def async_step_save(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Apply the changes (reloads the integration)."""
        return self.async_create_entry(data=self._options or {})

    # ---------------- scalar categories ----------------
    def _scalar_options(self, category: str, opt_key: str) -> list[SelectOptionDict]:
        assert self._options is not None
        selected = set(self._options.get(opt_key, []))
        available = self._disc.scalars.get(category, set()) if self._disc else set()
        values = self._disc.scalar_values if self._disc else {}
        out: list[SelectOptionDict] = []
        for key, item in cat.SCALAR_CATALOG[category].items():
            if key not in available and key not in selected:
                continue
            label = item.name
            raw = values.get(item_id(category, key))
            if raw is not None:
                if item.kind == cat.KIND_ENUM:
                    label += f" — {item.options.get(raw, raw)}"
                elif item.kind in (cat.KIND_TEXT,):
                    label += f" — {raw}"
                elif item.kind == cat.KIND_NUMBER:
                    shown = round(raw * item.scale, 1) if isinstance(raw, (int, float)) else raw
                    label += f" — {shown}{' ' + item.unit if item.unit else ''}"
            elif key not in available and self._disc is not None:
                label += " (not reported by firewall)"
            out.append(SelectOptionDict(value=key, label=label))
        return out

    async def _scalar_step(self, step_id: str, category: str, opt_key: str, user_input: dict[str, Any] | None) -> ConfigFlowResult:
        assert self._options is not None
        if user_input is not None:
            self._options[opt_key] = user_input.get(opt_key, [])
            return await self.async_step_init()
        options = self._scalar_options(category, opt_key)
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(
                {vol.Optional(opt_key, default=[k for k in self._options.get(opt_key, []) if any(o["value"] == k for o in options)]): _multi(options)}
            ),
        )

    async def async_step_system(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """System & resources."""
        return await self._scalar_step("system", "system", CONF_SYSTEM_ITEMS, user_input)

    async def async_step_services(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Service status."""
        return await self._scalar_step("services", "services", CONF_SERVICE_ITEMS, user_input)

    async def async_step_licenses(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """License / subscription status."""
        return await self._scalar_step("licenses", "licenses", CONF_LICENSE_ITEMS, user_input)

    async def async_step_high_availability(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """HA cluster state."""
        return await self._scalar_step("high_availability", "ha", CONF_HA_ITEMS, user_input)

    async def async_step_hardware(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Temperatures, fans and power supplies (XGS on SFOS 22+)."""
        assert self._options is not None
        if user_input is not None:
            self._options[CONF_HARDWARE_ITEMS] = user_input.get(CONF_HARDWARE_ITEMS, [])
            return await self.async_step_init()
        options = self._scalar_options("hardware", CONF_HARDWARE_ITEMS)
        seen = {o["value"] for o in options}
        if self._disc:
            for row in self._disc.fans.values():
                options.append(SelectOptionDict(value=f"fan|{row.key}", label=row.label))
            for row in self._disc.psus.values():
                options.append(SelectOptionDict(value=f"psu|{row.key}", label=row.label))
            seen = {o["value"] for o in options}
        for key in self._options.get(CONF_HARDWARE_ITEMS, []):
            if key not in seen:
                options.append(SelectOptionDict(value=key, label=f"{key} (not reported by firewall)"))
        return self.async_show_form(
            step_id="hardware",
            data_schema=vol.Schema(
                {vol.Optional(CONF_HARDWARE_ITEMS, default=list(self._options.get(CONF_HARDWARE_ITEMS, []))): _multi(options)}
            ),
        )

    # ---------------- table-based items ----------------
    def _row_options(self, rows: dict[str, Any], selected: list[str]) -> list[SelectOptionDict]:
        out = [SelectOptionDict(value=k, label=r.label) for k, r in rows.items()]
        known = set(rows)
        for key in selected:
            if key not in known:
                out.append(SelectOptionDict(value=key, label=f"{key} (not currently reported)"))
        return out

    async def async_step_interfaces(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Choose interfaces and which metrics to create for each."""
        assert self._options is not None
        if user_input is not None:
            self._options[CONF_INTERFACES] = user_input.get(CONF_INTERFACES, [])
            self._options[CONF_INTERFACE_METRICS] = user_input.get(CONF_INTERFACE_METRICS, [])
            return await self.async_step_init()
        rows = self._disc.interfaces if self._disc else {}
        selected = list(self._options.get(CONF_INTERFACES, []))
        metric_opts = [SelectOptionDict(value=k, label=m.name) for k, m in cat.INTERFACE_METRICS.items()]
        return self.async_show_form(
            step_id="interfaces",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_INTERFACES, default=selected): _multi(self._row_options(rows, selected)),
                    vol.Optional(CONF_INTERFACE_METRICS, default=list(self._options.get(CONF_INTERFACE_METRICS, []))): _multi(metric_opts),
                }
            ),
            description_placeholders={"hc": "64-bit" if (self._disc and self._disc.hc_counters) else "32-bit"},
        )

    async def async_step_vpn(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """IPsec connections."""
        assert self._options is not None
        if user_input is not None:
            self._options[CONF_VPN_TUNNELS] = user_input.get(CONF_VPN_TUNNELS, [])
            self._options[CONF_VPN_METRICS] = user_input.get(CONF_VPN_METRICS, [])
            return await self.async_step_init()
        rows = self._disc.vpn_tunnels if self._disc else {}
        selected = list(self._options.get(CONF_VPN_TUNNELS, []))
        metric_opts = [SelectOptionDict(value=k, label=m.name) for k, m in cat.VPN_METRICS.items()]
        return self.async_show_form(
            step_id="vpn",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_VPN_TUNNELS, default=selected): _multi(self._row_options(rows, selected)),
                    vol.Optional(CONF_VPN_METRICS, default=list(self._options.get(CONF_VPN_METRICS, []))): _multi(metric_opts),
                }
            ),
        )

    async def async_step_access_points(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Sophos wireless access points."""
        assert self._options is not None
        if user_input is not None:
            self._options[CONF_ACCESS_POINTS] = user_input.get(CONF_ACCESS_POINTS, [])
            return await self.async_step_init()
        rows = self._disc.access_points if self._disc else {}
        selected = list(self._options.get(CONF_ACCESS_POINTS, []))
        return self.async_show_form(
            step_id="access_points",
            data_schema=vol.Schema(
                {vol.Optional(CONF_ACCESS_POINTS, default=selected): _multi(self._row_options(rows, selected))}
            ),
        )

    # ---------------- custom OIDs ----------------
    async def async_step_custom_add(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Add any OID the firewall exposes as its own sensor."""
        assert self._options is not None
        errors: dict[str, str] = {}
        placeholders = {"value": "—"}
        if user_input is not None:
            oid = normalize_oid(user_input.get(CUSTOM_OID, ""))
            name = (user_input.get(CUSTOM_NAME) or "").strip()
            customs = list(self._options.get(CONF_CUSTOM_OIDS, []))
            if not name:
                errors[CUSTOM_NAME] = "name_required"
            if not is_valid_oid(oid):
                errors[CUSTOM_OID] = "invalid_oid"
            elif any(normalize_oid(c[CUSTOM_OID]) == oid for c in customs):
                errors[CUSTOM_OID] = "duplicate_oid"
            if not errors and not user_input.get("skip_test"):
                try:
                    engine = await async_get_engine(self.hass)
                    client = SnmpClient(engine, settings_from(dict(self.config_entry.data), self._options))
                    value = (await client.get([oid])).get(oid)
                except SnmpError:
                    value = None
                    errors["base"] = "cannot_connect"
                if value is None and "base" not in errors:
                    errors[CUSTOM_OID] = "oid_no_value"
                elif value is not None:
                    placeholders["value"] = str(value)[:80]
                    if user_input.get(CUSTOM_MODE) != CUSTOM_MODE_TEXT and not isinstance(value, (int, float)):
                        try:
                            float(str(value))
                        except ValueError:
                            errors[CUSTOM_MODE] = "not_numeric"
            if not errors:
                base = slugify(name) or "custom"
                existing = {c["id"] for c in customs}
                new_id, n = base, 2
                while new_id in existing:
                    new_id, n = f"{base}_{n}", n + 1
                customs.append(
                    {
                        "id": new_id,
                        CUSTOM_NAME: name,
                        CUSTOM_OID: oid,
                        CUSTOM_MODE: user_input.get(CUSTOM_MODE, CUSTOM_MODE_NUMBER),
                        CUSTOM_UNIT: (user_input.get(CUSTOM_UNIT) or "").strip(),
                        CUSTOM_SCALE: float(user_input.get(CUSTOM_SCALE) or 1),
                        CUSTOM_DEVICE_CLASS: _none_to_empty(user_input.get(CUSTOM_DEVICE_CLASS)),
                        CUSTOM_STATE_CLASS: _none_to_empty(user_input.get(CUSTOM_STATE_CLASS)),
                    }
                )
                self._options[CONF_CUSTOM_OIDS] = customs
                return await self.async_step_init()

        defaults = user_input or {}
        from homeassistant.components.sensor import SensorDeviceClass

        device_classes = ["none"] + sorted(dc.value for dc in SensorDeviceClass if dc.value not in ("enum", "timestamp", "date"))
        return self.async_show_form(
            step_id="custom_add",
            data_schema=vol.Schema(
                {
                    vol.Required(CUSTOM_NAME, default=defaults.get(CUSTOM_NAME, "")): str,
                    vol.Required(CUSTOM_OID, default=defaults.get(CUSTOM_OID, "")): str,
                    vol.Required(CUSTOM_MODE, default=defaults.get(CUSTOM_MODE, CUSTOM_MODE_NUMBER)): _dropdown(CUSTOM_MODES, "custom_mode"),
                    vol.Optional(CUSTOM_UNIT, default=defaults.get(CUSTOM_UNIT, "")): str,
                    vol.Optional(CUSTOM_SCALE, default=defaults.get(CUSTOM_SCALE, 1)): NumberSelector(
                        NumberSelectorConfig(mode=NumberSelectorMode.BOX, step="any")
                    ),
                    vol.Optional(CUSTOM_DEVICE_CLASS, default=defaults.get(CUSTOM_DEVICE_CLASS, "none")): _dropdown(device_classes),
                    vol.Optional(CUSTOM_STATE_CLASS, default=defaults.get(CUSTOM_STATE_CLASS, "measurement")): _dropdown(
                        ["none", "measurement", "total", "total_increasing"], "custom_state_class"
                    ),
                    vol.Optional("skip_test", default=False): BooleanSelector(),
                }
            ),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_custom_remove(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Remove custom OIDs."""
        assert self._options is not None
        customs = list(self._options.get(CONF_CUSTOM_OIDS, []))
        if user_input is not None:
            remove = set(user_input.get("remove", []))
            self._options[CONF_CUSTOM_OIDS] = [c for c in customs if c["id"] not in remove]
            return await self.async_step_init()
        options = [SelectOptionDict(value=c["id"], label=f"{c[CUSTOM_NAME]} ({c[CUSTOM_OID]})") for c in customs]
        return self.async_show_form(
            step_id="custom_remove",
            data_schema=vol.Schema({vol.Optional("remove", default=[]): _multi(options)}),
        )

    # ---------------- polling ----------------
    async def async_step_polling(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Poll interval and SNMP timeouts."""
        assert self._options is not None
        if user_input is not None:
            self._options[CONF_SCAN_INTERVAL] = int(user_input[CONF_SCAN_INTERVAL])
            self._options[CONF_TIMEOUT] = float(user_input[CONF_TIMEOUT])
            self._options[CONF_RETRIES] = int(user_input[CONF_RETRIES])
            return await self.async_step_init()
        return self.async_show_form(
            step_id="polling",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SCAN_INTERVAL, default=self._options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): NumberSelector(
                        NumberSelectorConfig(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL, step=1, unit_of_measurement="s", mode=NumberSelectorMode.BOX)
                    ),
                    vol.Required(CONF_TIMEOUT, default=self._options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)): NumberSelector(
                        NumberSelectorConfig(min=1, max=30, step=0.5, unit_of_measurement="s", mode=NumberSelectorMode.BOX)
                    ),
                    vol.Required(CONF_RETRIES, default=self._options.get(CONF_RETRIES, DEFAULT_RETRIES)): NumberSelector(
                        NumberSelectorConfig(min=0, max=5, step=1, mode=NumberSelectorMode.BOX)
                    ),
                }
            ),
        )
