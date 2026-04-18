"""Diagnostic sensors for AIRMON iLIVING."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfEnergy, UnitOfTemperature
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
                AirmonIndoorTemperatureSensor(coordinator, device_id),
                AirmonOutdoorTemperatureSensor(coordinator, device_id),
                AirmonPowerUsageSensor(coordinator, device_id),
                AirmonFirmwareSensor(coordinator, device_id),
                AirmonConnectionSensor(coordinator, device_id),
                AirmonAcErrorCodeSensor(coordinator, device_id),
                AirmonFilterStatusSensor(coordinator, device_id),
                AirmonIndoorUnitVersionSensor(coordinator, device_id),
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


class AirmonIndoorTemperatureSensor(AirmonEntity, SensorEntity):
    """Indoor temperature sensor."""

    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_suggested_display_precision = 1

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_indoor_temperature"
        self._attr_name = "Indoor Temperature"

    @property
    def native_value(self) -> float | None:
        """Return the indoor temperature."""
        return self.device.current_temperature


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

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_icon = "mdi:flash"
    _attr_native_unit_of_measurement = UnitOfEnergy.WATT_HOUR
    _attr_suggested_display_precision = 1

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


class AirmonAcErrorCodeSensor(AirmonEntity, SensorEntity):
    """Latest AC error code."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:alert-circle-outline"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_ac_error_code"
        self._attr_name = "AC Error Code"

    @property
    def native_value(self) -> str | None:
        """Return the latest AC error code."""
        return self.device.ac_error_code


class AirmonFilterStatusSensor(AirmonEntity, SensorEntity):
    """Filter expiration sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:air-filter"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_filter_status"
        self._attr_name = "Filter Status"

    @property
    def native_value(self) -> str:
        """Return the current filter state."""
        if self.device.filter_expired is True:
            return "expired"
        if self.device.filter_expired is False:
            return "ok"
        return "unknown"


class AirmonIndoorUnitVersionSensor(AirmonEntity, SensorEntity):
    """Indoor unit version sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:chip"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_indoor_unit_version"
        self._attr_name = "Indoor Unit Version"

    @property
    def native_value(self) -> str | None:
        """Return the indoor unit firmware/version string."""
        return self.device.indoor_unit_version
