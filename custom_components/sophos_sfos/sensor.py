"""Sensors for Sophos SFOS Monitor."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import catalog as cat
from .coordinator import SfosConfigEntry
from .entity import PLATFORM_SENSOR, SfosEntity, build_specs


def _device_class(value: str | None) -> SensorDeviceClass | None:
    if not value:
        return None
    try:
        return SensorDeviceClass(value)
    except ValueError:
        return None


def _state_class(value: str | None) -> SensorStateClass | None:
    if not value:
        return None
    try:
        return SensorStateClass(value)
    except ValueError:
        return None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SfosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensors from the current selection."""
    coordinator = entry.runtime_data
    async_add_entities(
        SfosSensor(coordinator, spec)
        for spec in build_specs(coordinator.selection)
        if spec.platform == PLATFORM_SENSOR
    )


class SfosSensor(SfosEntity, SensorEntity):
    """A numeric, text, enum or timestamp sensor."""

    def __init__(self, coordinator, spec) -> None:
        """Initialize."""
        super().__init__(coordinator, spec)
        if spec.kind == cat.KIND_ENUM:
            self._attr_device_class = SensorDeviceClass.ENUM
            self._attr_options = spec.options
        elif spec.kind == cat.KIND_TIMESTAMP:
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
        elif spec.kind == cat.KIND_NUMBER:
            self._attr_device_class = _device_class(spec.device_class)
            self._attr_state_class = _state_class(spec.state_class)
            self._attr_native_unit_of_measurement = spec.unit
            if spec.precision is not None:
                self._attr_suggested_display_precision = spec.precision

    @property
    def native_value(self) -> Any:
        """Current value."""
        item = self._item
        if item is None:
            return None
        value = item.value
        if self.spec.kind == cat.KIND_ENUM and value not in self.spec.options:
            return None
        return value
