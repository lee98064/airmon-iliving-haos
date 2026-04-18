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
    "AUTO": HVACMode.AUTO,
    "cool": HVACMode.COOL,
    "cold": HVACMode.COOL,
    "COOLING": HVACMode.COOL,
    "dry": HVACMode.DRY,
    "DRY": HVACMode.DRY,
    "fan": HVACMode.FAN_ONLY,
    "fanonly": HVACMode.FAN_ONLY,
    "FAN": HVACMode.FAN_ONLY,
    "heat": HVACMode.HEAT,
    "HEATING": HVACMode.HEAT,
    "off": HVACMode.OFF,
    "poweroff": HVACMode.OFF,
    "STOP": HVACMode.OFF,
}

HA_TO_APP_HVAC = {
    HVACMode.AUTO: "AUTO",
    HVACMode.COOL: "COOLING",
    HVACMode.DRY: "DRY",
    HVACMode.FAN_ONLY: "FAN",
    HVACMode.HEAT: "HEATING",
}

SUPPORTED_HVAC_MODES = [
    HVACMode.OFF,
    HVACMode.AUTO,
    HVACMode.COOL,
    HVACMode.HEAT,
    HVACMode.DRY,
    HVACMode.FAN_ONLY,
]
KNOWN_FAN_MODES = ["AUTO", "LOW", "MID", "HI", "POWERFUL"]
KNOWN_SWING_MODES = ["AUTO", "P1", "P2", "P3", "P4"]


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
    _attr_target_temperature_step = 0.5
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
        return self.device.set_point or self.device.target_temperature

    @property
    def hvac_mode(self) -> HVACMode:
        """Return the current HVAC mode."""
        if self.device.power is False or self.device.operation == "STOP":
            return HVACMode.OFF

        mode = (self.device.operation_mode or self.device.hvac_mode or "").strip()
        return APP_TO_HA_HVAC.get(mode, HVACMode.OFF)

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return supported HVAC modes."""
        return SUPPORTED_HVAC_MODES

    @property
    def fan_mode(self) -> str | None:
        """Return current fan mode."""
        if self.device.fan_mode is None:
            return None
        return self.device.fan_mode.strip().upper()

    @property
    def fan_modes(self) -> list[str] | None:
        """Return supported fan modes."""
        modes = list(KNOWN_FAN_MODES)
        if self.fan_mode and self.fan_mode not in modes:
            modes.append(self.fan_mode)
        return modes

    @property
    def swing_mode(self) -> str | None:
        """Return current swing mode."""
        if self.device.swing_mode is None:
            return None
        return self.device.swing_mode.strip().upper()

    @property
    def swing_modes(self) -> list[str] | None:
        """Return supported swing modes."""
        modes = list(KNOWN_SWING_MODES)
        if self.swing_mode and self.swing_mode not in modes:
            modes.append(self.swing_mode)
        return modes

    @property
    def supported_features(self) -> ClimateEntityFeature:
        """Return the supported climate features."""
        features = ClimateEntityFeature.TURN_ON | ClimateEntityFeature.TURN_OFF
        features |= ClimateEntityFeature.TARGET_TEMPERATURE
        features |= ClimateEntityFeature.FAN_MODE
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
        await self.coordinator.async_send_device_command(
            self.device,
            {"operation": "OPERATION"},
        )

    async def async_turn_off(self) -> None:
        """Turn the device off."""
        await self.coordinator.async_send_device_command(
            self.device,
            {"operation": "STOP"},
        )

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set the target temperature."""
        temperature = kwargs.get("temperature")
        if temperature is None:
            return
        await self.coordinator.async_send_device_command(
            self.device,
            {"setPoint": float(temperature)},
        )

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set HVAC mode."""
        if hvac_mode == HVACMode.OFF:
            await self.async_turn_off()
            return

        await self.coordinator.async_send_device_command(
            self.device,
            {
                "operation": "OPERATION",
                "operationMode": HA_TO_APP_HVAC[hvac_mode],
            },
        )

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """Set fan mode."""
        await self.coordinator.async_send_device_command(
            self.device,
            {"fanSpeed": fan_mode.strip().upper()},
        )

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        """Set swing mode."""
        normalized = swing_mode.strip().upper()
        payload: dict[str, Any]
        if normalized == "AUTO":
            payload = {"louverSwinging": "ON"}
        else:
            payload = {
                "louverSwinging": "OFF",
                "louverPosition": normalized,
            }
        await self.coordinator.async_send_device_command(self.device, payload)
