"""Shared AIRMON entity helpers."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_DEVICE_MAC,
    ATTR_FAMILY_ID,
    ATTR_HOME_LEAVE_MODE,
    ATTR_SILENT_MODE,
    DOMAIN,
    MANUFACTURER,
)
from .coordinator import AirmonDataUpdateCoordinator
from .models import AirmonDevice


class AirmonEntity(CoordinatorEntity[AirmonDataUpdateCoordinator]):
    """Base AIRMON entity."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: AirmonDataUpdateCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self._device_id = device_id

    @property
    def device(self) -> AirmonDevice:
        """Return the latest device state."""
        return self.coordinator.data[self._device_id]

    @property
    def available(self) -> bool:
        """Return entity availability."""
        online = self.device.online
        return super().available and online is not False

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self.device.unique_id)},
            manufacturer=MANUFACTURER,
            model=self.device.model,
            name=self.device.name,
            sw_version=self.device.firmware_version,
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            ATTR_DEVICE_MAC: self.device.mac,
            ATTR_FAMILY_ID: self.device.family_id,
            ATTR_HOME_LEAVE_MODE: self.device.home_leave_mode,
            ATTR_SILENT_MODE: self.device.silent_mode,
        }
