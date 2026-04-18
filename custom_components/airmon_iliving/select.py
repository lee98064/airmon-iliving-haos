"""Select entities for AIRMON airflow controls."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import AirmonEntity

VERTICAL_AIRFLOW_OPTIONS = ["AUTO", "P1", "P2", "P3", "P4"]
HORIZONTAL_AIRFLOW_OPTIONS = ["AUTO", "P1", "P2", "P3", "P4", "P5", "WIDE", "SPOT"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AIRMON airflow select entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[SelectEntity] = []

    for device_id, device in coordinator.data.items():
        if coordinator.experimental_control or device.swing_mode is not None:
            entities.append(AirmonVerticalAirflowSelect(coordinator, device_id))
        if coordinator.experimental_control or device.horizontal_swing_mode is not None:
            entities.append(AirmonHorizontalAirflowSelect(coordinator, device_id))

    async_add_entities(entities)


class AirmonAirflowSelect(AirmonEntity, SelectEntity):
    """Shared AIRMON airflow select."""

    _options: list[str] = []

    @property
    def options(self) -> list[str]:
        """Return selectable options."""
        return list(self._options)


class AirmonVerticalAirflowSelect(AirmonAirflowSelect):
    """Vertical airflow select."""

    _options = VERTICAL_AIRFLOW_OPTIONS
    _attr_icon = "mdi:arrow-up-down"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_vertical_airflow"
        self._attr_name = "Vertical Airflow"

    @property
    def current_option(self) -> str | None:
        """Return the effective vertical airflow option."""
        return self.device.swing_mode

    async def async_select_option(self, option: str) -> None:
        """Set the vertical airflow option."""
        normalized = option.strip().upper()
        if normalized not in self._options:
            raise ValueError(f"Unsupported vertical airflow option: {option}")

        if normalized == "AUTO":
            payload = {"louverSwinging": "ON"}
        else:
            payload = {
                "louverSwinging": "OFF",
                "louverPosition": normalized,
            }

        await self.coordinator.async_send_device_command(self.device, payload)


class AirmonHorizontalAirflowSelect(AirmonAirflowSelect):
    """Horizontal airflow select."""

    _options = HORIZONTAL_AIRFLOW_OPTIONS
    _attr_icon = "mdi:arrow-left-right"

    def __init__(self, coordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{self.device.unique_id}_horizontal_airflow"
        self._attr_name = "Horizontal Airflow"

    @property
    def current_option(self) -> str | None:
        """Return the effective horizontal airflow option."""
        return self.device.horizontal_swing_mode

    async def async_select_option(self, option: str) -> None:
        """Set the horizontal airflow option."""
        normalized = option.strip().upper()
        if normalized not in self._options:
            raise ValueError(f"Unsupported horizontal airflow option: {option}")

        if normalized == "AUTO":
            payload = {"leftRightSwing": "ON"}
        else:
            payload = {
                "leftRightSwing": "OFF",
                "louverLeftRightFixedPosition": normalized,
            }

        await self.coordinator.async_send_device_command(self.device, payload)
