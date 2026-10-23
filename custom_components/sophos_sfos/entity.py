"""Entity specs and base entity for Sophos SFOS Monitor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from homeassistant.const import CONF_HOST, EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import catalog as cat
from .api import Selection, item_id
from .const import (
    CUSTOM_DEVICE_CLASS,
    CUSTOM_MODE,
    CUSTOM_MODE_TEXT,
    CUSTOM_NAME,
    CUSTOM_STATE_CLASS,
    CUSTOM_UNIT,
    DOMAIN,
    MANUFACTURER,
)
from .coordinator import SfosCoordinator

PLATFORM_SENSOR = "sensor"
PLATFORM_BINARY = "binary_sensor"


@dataclass(slots=True)
class EntitySpec:
    """Everything needed to build one entity."""

    key: str  # data key, also the unique_id suffix
    platform: str
    name: str
    kind: str = cat.KIND_NUMBER
    unit: str | None = None
    device_class: str | None = None
    state_class: str | None = None
    icon: str | None = None
    precision: int | None = None
    options: list[str] = field(default_factory=list)
    diagnostic: bool = False
    sub_device: tuple[str, str] | None = None  # ("if", "Port2")


def _from_scalar(category: str, item: cat.ScalarItem) -> EntitySpec:
    return EntitySpec(
        key=item_id(category, item.key),
        platform=PLATFORM_BINARY if item.kind == cat.KIND_BINARY else PLATFORM_SENSOR,
        name=item.name,
        kind=item.kind,
        unit=item.unit,
        device_class=item.device_class,
        state_class=item.state_class,
        icon=item.icon,
        precision=item.precision,
        options=list(dict.fromkeys(item.options.values())),
        diagnostic=item.diagnostic,
    )


def _from_metric(key: str, prefix: str, metric: cat.MetricDef, sub_device: tuple[str, str] | None) -> EntitySpec:
    return EntitySpec(
        key=key,
        platform=PLATFORM_BINARY if metric.kind == cat.KIND_BINARY else PLATFORM_SENSOR,
        name=f"{prefix}{metric.name}",
        kind=metric.kind,
        unit=metric.unit,
        device_class=metric.device_class,
        state_class=metric.state_class,
        icon=metric.icon,
        precision=metric.precision,
        options=list(dict.fromkeys(metric.options.values())),
        diagnostic=metric.diagnostic,
        sub_device=sub_device,
    )


def build_specs(sel: Selection) -> list[EntitySpec]:
    """All entities implied by the current selection."""
    specs: list[EntitySpec] = []
    for category, keys in sel.scalars.items():
        items = cat.SCALAR_CATALOG.get(category, {})
        for key in keys:
            if (item := items.get(key)) is not None:
                specs.append(_from_scalar(category, item))

    for iface in sel.interfaces:
        for metric_key in sel.interface_metrics:
            if (metric := cat.INTERFACE_METRICS.get(metric_key)) is not None:
                specs.append(_from_metric(item_id("if", iface, metric_key), "", metric, ("if", iface)))

    for tunnel in sel.vpn_tunnels:
        for metric_key in sel.vpn_metrics:
            if (metric := cat.VPN_METRICS.get(metric_key)) is not None:
                specs.append(_from_metric(item_id("vpn", tunnel, metric_key), f"VPN {tunnel} ", metric, None))

    for ap in sel.access_points:
        for metric_key, metric in cat.AP_METRICS.items():
            specs.append(_from_metric(item_id("ap", ap, metric_key), f"AP {ap} ", metric, None))

    for fan in sel.fans:
        specs.append(EntitySpec(key=item_id("fan", fan), platform=PLATFORM_SENSOR, name=f"Fan {fan} speed", unit="RPM", state_class="measurement", icon="mdi:fan"))
    for psu in sel.psus:
        specs.append(EntitySpec(key=item_id("psu", psu), platform=PLATFORM_BINARY, name=f"Power supply {psu}", kind=cat.KIND_BINARY, device_class="power"))

    for conf in sel.custom:
        is_text = conf.get(CUSTOM_MODE) == CUSTOM_MODE_TEXT
        specs.append(
            EntitySpec(
                key=item_id("custom", conf["id"]),
                platform=PLATFORM_SENSOR,
                name=conf.get(CUSTOM_NAME) or conf["id"],
                kind=cat.KIND_TEXT if is_text else cat.KIND_NUMBER,
                unit=None if is_text else (conf.get(CUSTOM_UNIT) or None),
                device_class=None if is_text else (conf.get(CUSTOM_DEVICE_CLASS) or None),
                state_class=None if is_text else (conf.get(CUSTOM_STATE_CLASS) or None),
                icon="mdi:numeric" if not is_text else "mdi:text",
            )
        )
    return specs


def firewall_name(coordinator: SfosCoordinator) -> str:
    """Friendly firewall name."""
    dev = coordinator.device
    return str(
        dev.get("name") or dev.get("sys_name") or coordinator.config_entry.title or coordinator.config_entry.data[CONF_HOST]
    )


class SfosEntity(CoordinatorEntity[SfosCoordinator]):
    """Base entity."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SfosCoordinator, spec: EntitySpec) -> None:
        """Initialize."""
        super().__init__(coordinator)
        self.spec = spec
        entry = coordinator.config_entry
        base_id = entry.unique_id or entry.entry_id
        self._attr_unique_id = f"{base_id}_{spec.key}"
        self._attr_name = spec.name
        if spec.icon:
            self._attr_icon = spec.icon
        if spec.diagnostic:
            self._attr_entity_category = EntityCategory.DIAGNOSTIC

        dev = coordinator.device
        main_ids = {(DOMAIN, base_id)}
        if spec.sub_device is None:
            self._attr_device_info = DeviceInfo(
                identifiers=main_ids,
                name=firewall_name(coordinator),
                manufacturer=MANUFACTURER,
                model=dev.get("model") or "SFOS",
                sw_version=dev.get("firmware"),
                serial_number=dev.get("serial"),
                configuration_url=f"https://{entry.data[CONF_HOST]}:4444",
            )
        else:
            kind, name = spec.sub_device
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"{base_id}_{kind}_{name}")},
                name=f"{firewall_name(coordinator)} {name}",
                manufacturer=MANUFACTURER,
                model="Interface",
                via_device=(DOMAIN, base_id),
            )

    @property
    def _item(self):
        data = self.coordinator.data or {}
        return data.get(self.spec.key)

    @property
    def available(self) -> bool:
        """Unavailable when the poll failed or the value is missing."""
        return super().available and self._item is not None and self._item.value is not None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Per-item attributes (license expiry, interface admin status...)."""
        item = self._item
        return dict(item.attributes) if item and item.attributes else None
