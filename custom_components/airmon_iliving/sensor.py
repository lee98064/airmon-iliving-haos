"""Diagnostic sensors for AIRMON iLIVING."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import AirmonEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AIRMON sensor entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[SensorEntity] = []

    for device_id in coordinator.data:
        entities.extend(
            [
                AirmonOutdoorTemperatureSensor(coordinator, device_id),
                AirmonPowerUsageSensor(coordinator, device_id),
                AirmonFirmwareSensor(coordinator, device_id),
                AirmonConnectionSensor(coordinator, device_id),
            ]
        )

    async_add_entities(entities)


class AirmonOutdoorTemperatureSensor(AirmonEntity, SensorEntity):
    """Outdoor temperature sensor."""

    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_suggested_display_precision = 1

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_outdoor_temperature"
        self._attr_name = "Outdoor Temperature"

    @property
    def native_value(self) -> float | None:
        """Return the outdoor temperature."""
        return self.device.outdoor_temperature


class AirmonFirmwareSensor(AirmonEntity, SensorEntity):
    """Firmware version sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:chip"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_firmware"
        self._attr_name = "Firmware"

    @property
    def native_value(self) -> str | None:
        """Return the firmware version."""
        return self.device.firmware_version


class AirmonPowerUsageSensor(AirmonEntity, SensorEntity):
    """Power usage sensor."""

    _attr_icon = "mdi:flash"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_power_usage"
        self._attr_name = "Power Usage"

    @property
    def native_value(self) -> float | None:
        """Return the latest power usage value."""
        return self.device.power_usage


class AirmonConnectionSensor(AirmonEntity, SensorEntity):
    """Connectivity sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:lan-connect"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_connection"
        self._attr_name = "Connection"

    @property
    def native_value(self) -> str:
        """Return connectivity state."""
        if self.device.online is True:
            return "online"
        if self.device.online is False:
            return "offline"
        return "unknown"
