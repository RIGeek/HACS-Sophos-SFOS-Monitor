"""Binary sensors for Sophos SFOS Monitor (link, VPN, AP, PSU state)."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import SfosConfigEntry
from .entity import PLATFORM_BINARY, SfosEntity, build_specs


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SfosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up binary sensors from the current selection."""
    coordinator = entry.runtime_data
    async_add_entities(
        SfosBinarySensor(coordinator, spec)
        for spec in build_specs(coordinator.selection)
        if spec.platform == PLATFORM_BINARY
    )


class SfosBinarySensor(SfosEntity, BinarySensorEntity):
    """On/off state."""

    def __init__(self, coordinator, spec) -> None:
        """Initialize."""
        super().__init__(coordinator, spec)
        if spec.device_class:
            try:
                self._attr_device_class = BinarySensorDeviceClass(spec.device_class)
            except ValueError:
                self._attr_device_class = None

    @property
    def is_on(self) -> bool | None:
        """Return the state."""
        item = self._item
        return None if item is None else item.value
