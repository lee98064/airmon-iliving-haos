"""Coordinator for AIRMON iLIVING data updates."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AirmonApiClient, AirmonApiError
from .const import DEFAULT_POLL_INTERVAL
from .models import (
    AirmonDevice,
    CONTROL_STATUS_KEYS,
    HOME_LEAVE_CANDIDATES,
    MAC_CANDIDATES,
    SILENT_MODE_CANDIDATES,
    build_device_command_payload,
    coerce_float,
    coerce_status_text,
    coerce_text,
    deep_merge,
    extract_first,
    normalize_mode_value,
)

if TYPE_CHECKING:
    from .mqtt import AirmonMqttClient

_LOGGER = logging.getLogger(__name__)


class AirmonDataUpdateCoordinator(DataUpdateCoordinator[dict[str, AirmonDevice]]):
    """Coordinate AIRMON cloud polling."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AirmonApiClient,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        experimental_control: bool = False,
        mqtt_client: AirmonMqttClient | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="AIRMON iLIVING",
            update_interval=timedelta(seconds=poll_interval),
        )
        self.api = api
        self.experimental_control = experimental_control
        self.mqtt = mqtt_client
        self._status_waiters: dict[str, list[asyncio.Future[AirmonDevice]]] = {}

    async def _async_update_data(self) -> dict[str, AirmonDevice]:
        """Fetch the latest data from the API."""
        try:
            devices = await self.api.async_get_devices()
        except AirmonApiError as err:
            raise UpdateFailed(str(err)) from err

        merged: dict[str, AirmonDevice] = {}
        current = self.data if isinstance(self.data, dict) else {}
        for device in devices:
            existing = current.get(device.unique_id)
            if self._should_prefer_existing(existing, device):
                merged[device.unique_id] = existing
            else:
                merged[device.unique_id] = device
        return merged

    async def async_send_device_command(
        self, device: AirmonDevice, command: dict[str, Any]
    ) -> None:
        """Send a command and refresh the device state."""
        push_waiter: asyncio.Task[AirmonDevice | None] | None = None
        optimistic = None
        try:
            payload, _action_key, _action_status = build_device_command_payload(
                device,
                command,
            )
            optimistic = self._device_from_push_payload(
                f"devices/{device.mac}/control/json",
                payload,
            )
            if optimistic is not None:
                updated = dict(self.data)
                updated[device.unique_id] = optimistic
                self.async_set_updated_data(updated)

            if self.mqtt is not None:
                push_waiter = self.hass.async_create_task(
                    self._async_wait_for_status_update(device.mac)
                )
            await self._async_publish_device_command(
                device,
                payload,
            )
            latest = await push_waiter if push_waiter is not None else None
            if latest is None:
                latest = await self._async_wait_for_updated_device(device.mac, payload)
        except AirmonApiError as err:
            if push_waiter is not None and not push_waiter.done():
                push_waiter.cancel()
            raise UpdateFailed(str(err)) from err
        except Exception as err:  # noqa: BLE001
            if push_waiter is not None and not push_waiter.done():
                push_waiter.cancel()
            raise UpdateFailed(str(err)) from err

        if latest is not None:
            updated = dict(self.data)
            updated[device.unique_id] = latest
            self.async_set_updated_data(updated)
            self.hass.async_create_task(self._async_delayed_refresh())
            return

        if optimistic is None:
            await self.async_request_refresh()
            return

        self.hass.async_create_task(self._async_delayed_refresh())

    async def _async_publish_device_command(
        self,
        device: AirmonDevice,
        payload: dict[str, Any],
    ) -> None:
        """Publish a device control payload over MQTT when available."""
        if self.mqtt is None:
            await self.api.async_send_command(device.mac, payload)
            return

        mqtt_failure: str | None = None
        try:
            await self.mqtt.async_publish_json(
                f"devices/{device.mac}/control/json",
                payload,
            )
            return
        except Exception as mqtt_err:  # noqa: BLE001
            mqtt_failure = str(mqtt_err)
            _LOGGER.warning(
                "AIRMON MQTT control failed for %s; falling back to HTTP: %s",
                device.mac,
                mqtt_failure,
            )

        try:
            await self.api.async_send_command(device.mac, payload)
        except AirmonApiError as http_err:
            raise AirmonApiError(
                f"MQTT failed: {mqtt_failure or 'unknown'}; HTTP fallback failed: {http_err}"
            ) from http_err

    async def _async_wait_for_updated_device(
        self,
        mac: str,
        expected_payload: dict[str, Any] | None = None,
    ) -> AirmonDevice | None:
        """Fetch the updated device state after a command."""
        current = self._find_device_by_mac(mac)
        current_updated_ms = self._device_updated_ms(current)
        for delay in (0.75, 1.0, 1.5):
            await asyncio.sleep(delay)
            latest = await self.api.async_get_device(mac)
            if latest is None:
                continue
            if expected_payload and self._device_matches_payload(latest, expected_payload):
                return latest
            latest_updated_ms = self._device_updated_ms(latest)
            if (
                latest_updated_ms is None
                or current_updated_ms is None
                or latest_updated_ms > current_updated_ms
            ):
                return latest
            _LOGGER.debug(
                "Ignoring stale AIRMON API state for %s; payload not reflected yet",
                mac,
            )
        return None

    async def async_apply_push_update(self, topic: str, payload: Any) -> None:
        """Merge an MQTT payload into the current coordinator state."""
        device = self._device_from_push_payload(topic, payload)
        if device is None:
            _LOGGER.debug("Ignoring MQTT payload on topic %s; no device resolved", topic)
            return

        updated = dict(self.data)
        updated[device.unique_id] = device
        self.async_set_updated_data(updated)
        self._resolve_status_waiters(device, topic)

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

    async def _async_wait_for_status_update(self, mac: str) -> AirmonDevice | None:
        """Wait for an MQTT status payload for the given device."""
        future: asyncio.Future[AirmonDevice] = self.hass.loop.create_future()
        key = mac.lower()
        self._status_waiters.setdefault(key, []).append(future)
        try:
            return await asyncio.wait_for(future, timeout=5)
        except TimeoutError:
            return None
        finally:
            waiters = self._status_waiters.get(key, [])
            if future in waiters:
                waiters.remove(future)
            if not waiters:
                self._status_waiters.pop(key, None)

    def _resolve_status_waiters(self, device: AirmonDevice, topic: str) -> None:
        """Resolve pending status waiters for a device."""
        if not topic.endswith("/status/json"):
            return
        waiters = self._status_waiters.pop(device.mac.lower(), [])
        for future in waiters:
            if not future.done():
                future.set_result(device)

    async def _async_delayed_refresh(self, delay: float = 12.0) -> None:
        """Refresh later, after the cloud API has had time to catch up."""
        await asyncio.sleep(delay)
        await self.async_request_refresh()

    def _device_updated_ms(self, device: AirmonDevice | None) -> int | None:
        """Return the device updated timestamp in milliseconds when available."""
        if device is None:
            return None
        value = extract_first(device.raw, ("updatedTime",))
        float_value = coerce_float(value)
        if float_value is None:
            return None
        return int(float_value)

    def _device_matches_payload(
        self,
        device: AirmonDevice,
        payload: dict[str, Any],
    ) -> bool:
        """Return whether the device already reflects the expected command payload."""
        for key, expected in payload.items():
            if key in CONTROL_STATUS_KEYS:
                current = extract_first(device.raw, (key,))
                if key == "setPoint":
                    if coerce_float(current) != coerce_float(expected):
                        return False
                    continue
                if (
                    normalize_mode_value(coerce_status_text(current))
                    != normalize_mode_value(coerce_status_text(expected))
                ):
                    return False
                continue

            if key == "homeLeave":
                current = extract_first(device.raw, HOME_LEAVE_CANDIDATES)
            elif key == "silentMode":
                current = extract_first(device.raw, SILENT_MODE_CANDIDATES)
            else:
                continue

            current_mode = normalize_mode_value(coerce_status_text(current))
            expected_mode = normalize_mode_value(coerce_status_text(expected))
            if current_mode != expected_mode:
                return False

        return True

    def _should_prefer_existing(
        self,
        existing: AirmonDevice | None,
        fresh: AirmonDevice,
    ) -> bool:
        """Keep the current device state when MQTT data is newer than the API."""
        if existing is None:
            return False

        existing_updated_ms = self._device_updated_ms(existing)
        fresh_updated_ms = self._device_updated_ms(fresh)
        if existing_updated_ms is None or fresh_updated_ms is None:
            return False

        return existing_updated_ms > fresh_updated_ms
