"""Shared AIRMON entity helpers."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_AC_ERROR_CODE,
    ATTR_DEVICE_MAC,
    ATTR_ENERGY_SAVING,
    ATTR_FAMILY_ID,
    ATTR_FILTER_EXPIRED,
    ATTR_HOME_LEAVE_MODE,
    ATTR_INDOOR_UNIT_VERSION,
    ATTR_LEFT_RIGHT_SWING,
    ATTR_LOUVER_LEFT_RIGHT_FIXED_POSITION,
    ATTR_LOUVER_POSITION,
    ATTR_LOUVER_SWINGING,
    ATTR_MODE_3D_AUTO,
    ATTR_OPERATION,
    ATTR_OPERATION_MODE,
    ATTR_POWERFUL_MODE,
    ATTR_SET_POINT,
    ATTR_SILENT_MODE,
    ATTR_UPDATED_TIME,
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
            ATTR_ENERGY_SAVING: self.device.energy_saving,
            ATTR_LEFT_RIGHT_SWING: self.device.left_right_swing,
            ATTR_LOUVER_LEFT_RIGHT_FIXED_POSITION: (
                self.device.louver_left_right_fixed_position
            ),
            ATTR_LOUVER_POSITION: self.device.louver_position,
            ATTR_LOUVER_SWINGING: self.device.louver_swinging,
            ATTR_MODE_3D_AUTO: self.device.mode_3d_auto,
            ATTR_OPERATION: self.device.operation,
            ATTR_OPERATION_MODE: self.device.operation_mode,
            ATTR_POWERFUL_MODE: self.device.powerful_mode,
            ATTR_SET_POINT: self.device.set_point,
            ATTR_UPDATED_TIME: self.device.updated_time,
            ATTR_AC_ERROR_CODE: self.device.ac_error_code,
            ATTR_FILTER_EXPIRED: self.device.filter_expired,
            ATTR_INDOOR_UNIT_VERSION: self.device.indoor_unit_version,
        }
