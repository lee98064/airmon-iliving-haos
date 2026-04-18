"""Climate entities for AIRMON iLIVING."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import (
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import AirmonEntity

APP_TO_HA_HVAC = {
    "auto": HVACMode.AUTO,
    "cool": HVACMode.COOL,
    "cold": HVACMode.COOL,
    "dry": HVACMode.DRY,
    "fan": HVACMode.FAN_ONLY,
    "fanonly": HVACMode.FAN_ONLY,
    "heat": HVACMode.HEAT,
    "off": HVACMode.OFF,
    "poweroff": HVACMode.OFF,
}

HA_TO_APP_HVAC = {
    HVACMode.AUTO: "auto",
    HVACMode.COOL: "cool",
    HVACMode.DRY: "dry",
    HVACMode.FAN_ONLY: "fan",
    HVACMode.HEAT: "heat",
}

SUPPORTED_HVAC_MODES = [
    HVACMode.OFF,
    HVACMode.AUTO,
    HVACMode.COOL,
    HVACMode.HEAT,
    HVACMode.DRY,
    HVACMode.FAN_ONLY,
]
KNOWN_FAN_MODES = ["auto", "low", "medium", "high"]
KNOWN_SWING_MODES = ["stop", "auto", "p1", "p2", "p3", "p4", "p5"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AIRMON climate entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        AirmonClimateEntity(coordinator, device_id)
        for device_id in coordinator.data
    )


class AirmonClimateEntity(AirmonEntity, ClimateEntity):
    """AIRMON air conditioner climate entity."""

    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = 1.0
    _attr_min_temp = 16
    _attr_max_temp = 31

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_climate"
        self._attr_name = "HVAC"

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        return self.device.current_temperature

    @property
    def target_temperature(self) -> float | None:
        """Return the target temperature."""
        return self.device.target_temperature

    @property
    def hvac_mode(self) -> HVACMode:
        """Return the current HVAC mode."""
        if self.device.power is False:
            return HVACMode.OFF

        mode = (self.device.hvac_mode or "").strip().lower()
        return APP_TO_HA_HVAC.get(mode, HVACMode.OFF)

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return supported HVAC modes."""
        if self.coordinator.experimental_control:
            return SUPPORTED_HVAC_MODES
        return [self.hvac_mode]

    @property
    def fan_mode(self) -> str | None:
        """Return current fan mode."""
        if self.device.fan_mode is None:
            return None
        return self.device.fan_mode.strip().lower()

    @property
    def fan_modes(self) -> list[str] | None:
        """Return supported fan modes."""
        if not self.coordinator.experimental_control:
            return [self.fan_mode] if self.fan_mode else None
        modes = list(KNOWN_FAN_MODES)
        if self.fan_mode and self.fan_mode not in modes:
            modes.append(self.fan_mode)
        return modes

    @property
    def swing_mode(self) -> str | None:
        """Return current swing mode."""
        if self.device.swing_mode is None:
            return None
        return self.device.swing_mode.strip().lower()

    @property
    def swing_modes(self) -> list[str] | None:
        """Return supported swing modes."""
        if not self.coordinator.experimental_control:
            return [self.swing_mode] if self.swing_mode else None
        modes = list(KNOWN_SWING_MODES)
        if self.swing_mode and self.swing_mode not in modes:
            modes.append(self.swing_mode)
        return modes

    @property
    def supported_features(self) -> ClimateEntityFeature:
        """Return the supported climate features."""
        if not self.coordinator.experimental_control:
            return ClimateEntityFeature(0)

        features = ClimateEntityFeature.TURN_ON | ClimateEntityFeature.TURN_OFF
        if self.device.target_temperature is not None:
            features |= ClimateEntityFeature.TARGET_TEMPERATURE
        if self.fan_modes:
            features |= ClimateEntityFeature.FAN_MODE
        if self.swing_modes:
            features |= ClimateEntityFeature.SWING_MODE
        return features

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attributes = dict(super().extra_state_attributes)
        attributes.update(
            {
                "horizontal_swing_mode": self.device.horizontal_swing_mode,
                "outdoor_temperature": self.device.outdoor_temperature,
                "power_usage": self.device.power_usage,
                "experimental_control": self.coordinator.experimental_control,
            }
        )
        return attributes

    async def async_turn_on(self) -> None:
        """Turn the device on."""
        await self.coordinator.async_send_device_command(self.device, {"power": True})

    async def async_turn_off(self) -> None:
        """Turn the device off."""
        await self.coordinator.async_send_device_command(self.device, {"power": False})

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set the target temperature."""
        temperature = kwargs.get("temperature")
        if temperature is None:
            return
        await self.coordinator.async_send_device_command(
            self.device, {"targetTemperature": temperature}
        )

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set HVAC mode."""
        if hvac_mode == HVACMode.OFF:
            await self.async_turn_off()
            return

        await self.coordinator.async_send_device_command(
            self.device,
            {
                "power": True,
                "mode": HA_TO_APP_HVAC[hvac_mode],
            },
        )

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """Set fan mode."""
        await self.coordinator.async_send_device_command(
            self.device, {"fanSpeed": fan_mode}
        )

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        """Set swing mode."""
        await self.coordinator.async_send_device_command(
            self.device, {"swingMode": swing_mode}
        )
