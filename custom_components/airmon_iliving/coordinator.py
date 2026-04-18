"""Coordinator for AIRMON iLIVING data updates."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AirmonApiClient, AirmonApiError
from .const import DEFAULT_POLL_INTERVAL
from .models import AirmonDevice, MAC_CANDIDATES, coerce_text, deep_merge, extract_first

_LOGGER = logging.getLogger(__name__)


class AirmonDataUpdateCoordinator(DataUpdateCoordinator[dict[str, AirmonDevice]]):
    """Coordinate AIRMON cloud polling."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AirmonApiClient,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        experimental_control: bool = False,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="AIRMON iLIVING",
            update_interval=timedelta(seconds=poll_interval),
        )
        self.api = api
        self.experimental_control = experimental_control

    async def _async_update_data(self) -> dict[str, AirmonDevice]:
        """Fetch the latest data from the API."""
        try:
            devices = await self.api.async_get_devices()
        except AirmonApiError as err:
            raise UpdateFailed(str(err)) from err

        return {device.unique_id: device for device in devices}

    async def async_send_device_command(
        self, device: AirmonDevice, command: dict[str, Any]
    ) -> None:
        """Send a command and refresh the device state."""
        if not self.experimental_control:
            raise UpdateFailed(
                "Experimental control is disabled for this config entry."
            )

        try:
            await self.api.async_send_command(device.mac, command)
            latest = await self.api.async_get_device(device.mac)
        except AirmonApiError as err:
            raise UpdateFailed(str(err)) from err

        if latest is not None:
            updated = dict(self.data)
            updated[device.unique_id] = latest
            self.async_set_updated_data(updated)
            return

        await self.async_request_refresh()

    async def async_apply_push_update(self, topic: str, payload: Any) -> None:
        """Merge an MQTT payload into the current coordinator state."""
        device = self._device_from_push_payload(topic, payload)
        if device is None:
            _LOGGER.debug("Ignoring MQTT payload on topic %s; no device resolved", topic)
            return

        updated = dict(self.data)
        updated[device.unique_id] = device
        self.async_set_updated_data(updated)

    def _device_from_push_payload(self, topic: str, payload: Any) -> AirmonDevice | None:
        """Build a device object from a push payload and existing state."""
        topic_mac = self._extract_mac_from_topic(topic)
        current = self._find_device_by_mac(topic_mac) if topic_mac else None

        if isinstance(payload, dict):
            candidate = dict(payload)
        else:
            candidate = {"mqtt_payload": payload}

        if topic_mac and extract_first(candidate, MAC_CANDIDATES) is None:
            candidate["mac"] = topic_mac

        base = current.raw if current is not None else {}
        merged = deep_merge(base, candidate)
        return AirmonDevice.from_mapping(merged)

    def _extract_mac_from_topic(self, topic: str) -> str | None:
        """Extract the device MAC from topics like devices/<mac>/status."""
        parts = topic.split("/")
        if len(parts) < 2 or parts[0] != "devices":
            return None
        return coerce_text(parts[1])

    def _find_device_by_mac(self, mac: str | None) -> AirmonDevice | None:
        """Return the tracked device with the given MAC address."""
        if mac is None:
            return None

        normalized = mac.lower()
        for device in self.data.values():
            if device.mac.lower() == normalized:
                return device
        return None
