"""Switch entities for AIRMON iLIVING feature toggles."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import AirmonEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AIRMON switch entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[SwitchEntity] = []

    for device_id, device in coordinator.data.items():
        if coordinator.experimental_control or device.home_leave_mode is not None:
            entities.append(
                AirmonModeSwitch(
                    coordinator=coordinator,
                    device_id=device_id,
                    unique_suffix="home_leave_mode",
                    name="Home Leave Mode",
                    icon="mdi:home-export-outline",
                    attribute_name="home_leave_mode",
                    payload_key="homeLeaveMode",
                )
            )

        if coordinator.experimental_control or device.silent_mode is not None:
            entities.append(
                AirmonModeSwitch(
                    coordinator=coordinator,
                    device_id=device_id,
                    unique_suffix="silent_mode",
                    name="Silent Mode",
                    icon="mdi:volume-off",
                    attribute_name="silent_mode",
                    payload_key="silentMode",
                )
            )

    async_add_entities(entities)


class AirmonModeSwitch(AirmonEntity, SwitchEntity):
    """Shared boolean switch entity for experimental device features."""

    def __init__(
        self,
        coordinator,
        device_id: str,
        unique_suffix: str,
        name: str,
        icon: str,
        attribute_name: str,
        payload_key: str,
    ) -> None:
        super().__init__(coordinator, device_id)
        self._attribute_name = attribute_name
        self._payload_key = payload_key
        self._attr_unique_id = f"{self.device.unique_id}_{unique_suffix}"
        self._attr_name = name
        self._attr_icon = icon

    @property
    def is_on(self) -> bool:
        """Return the boolean feature state."""
        return bool(getattr(self.device, self._attribute_name))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return switch-specific extra attributes."""
        attributes = dict(super().extra_state_attributes)
        attributes["experimental_control"] = self.coordinator.experimental_control
        return attributes

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the feature."""
        await self.coordinator.async_send_device_command(
            self.device, {self._payload_key: True}
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the feature."""
        await self.coordinator.async_send_device_command(
            self.device, {self._payload_key: False}
        )
