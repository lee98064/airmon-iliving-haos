"""MQTT client for AIRMON iLIVING push updates."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import paho.mqtt.client as mqtt

from .api import AirmonApiClient

if TYPE_CHECKING:
    from .coordinator import AirmonDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


class AirmonMqttClient:
    """Best-effort MQTT client inferred from AIRMON APK strings."""

    def __init__(
        self,
        hass,
        api: AirmonApiClient,
        coordinator: AirmonDataUpdateCoordinator,
        host: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = False,
        subscribe_updates: bool = False,
    ) -> None:
        self._hass = hass
        self._api = api
        self._coordinator = coordinator
        self._host = host
        self._port = port
        self._username = username or None
        self._password = password or None
        self._use_tls = use_tls
        self._subscribe_updates = subscribe_updates
        self._started = False
        self._connected = False
        self._connect_lock = asyncio.Lock()
        self._connected_event = asyncio.Event()
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"ha-airmon-{uuid4().hex[:10]}",
            protocol=mqtt.MQTTv311,
        )
        self._client.enable_logger(_LOGGER)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

    async def async_start(self) -> None:
        """Start the background MQTT loop."""
        async with self._connect_lock:
            if self._started and self._connected:
                return

            if not self._password:
                self._password = await self._api.async_ensure_access_token()
            self._username = self._username or self._api.username

            if self._username:
                self._client.username_pw_set(self._username, self._password)

            if self._use_tls:
                self._client.tls_set(cert_reqs=ssl.CERT_REQUIRED)

            self._connected_event.clear()
            if not self._started:
                await self._hass.async_add_executor_job(self._connect)
                self._started = True
            elif not self._connected:
                await self._hass.async_add_executor_job(self._reconnect)

            try:
                await asyncio.wait_for(self._connected_event.wait(), timeout=10)
            except TimeoutError as err:
                raise RuntimeError("AIRMON MQTT connection timed out") from err

    async def async_stop(self) -> None:
        """Stop the background MQTT loop."""
        if not self._started:
            return

        await self._hass.async_add_executor_job(self._disconnect)
        self._started = False
        self._connected = False
        self._connected_event.clear()

    async def async_publish_json(self, topic: str, payload: dict[str, Any]) -> None:
        """Publish a JSON payload to the MQTT broker."""
        await self.async_start()
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        result = await self._hass.async_add_executor_job(self._publish, topic, encoded)
        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"Failed to publish AIRMON MQTT payload: {result}")

    def _connect(self) -> None:
        """Connect and start the MQTT loop in a worker thread."""
        self._client.connect(self._host, self._port, keepalive=60)
        self._client.loop_start()

    def _disconnect(self) -> None:
        """Disconnect and stop the MQTT loop."""
        try:
            self._client.disconnect()
        finally:
            self._client.loop_stop()

    def _reconnect(self) -> None:
        """Reconnect an existing MQTT client session."""
        try:
            self._client.reconnect()
        except Exception:  # noqa: BLE001
            self._client.connect(self._host, self._port, keepalive=60)

    def _on_connect(
        self,
        client: mqtt.Client,
        _userdata: Any,
        _flags: Any,
        reason_code: Any,
        _properties: Any,
    ) -> None:
        """Subscribe after connection."""
        reason_value = int(reason_code)
        if reason_value != 0:
            _LOGGER.warning("AIRMON MQTT connect failed: %s", reason_code)
            return

        self._connected = True
        self._hass.loop.call_soon_threadsafe(self._connected_event.set)

        if not self._subscribe_updates:
            return

        topics = {"devices/+/#"}
        topics.update(
            f"devices/{device.mac}/#"
            for device in self._coordinator.data.values()
            if device.mac
        )
        for topic in topics:
            result, _mid = client.subscribe(topic)
            if result != mqtt.MQTT_ERR_SUCCESS:
                _LOGGER.warning("Failed to subscribe AIRMON MQTT topic %s: %s", topic, result)

    def _on_disconnect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _disconnect_flags: Any,
        reason_code: Any,
        _properties: Any,
    ) -> None:
        """Log disconnects for troubleshooting."""
        self._connected = False
        self._hass.loop.call_soon_threadsafe(self._connected_event.clear)
        if int(reason_code) == 0:
            return
        _LOGGER.warning("AIRMON MQTT disconnected: %s", reason_code)

    def _on_message(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        message: mqtt.MQTTMessage,
    ) -> None:
        """Forward MQTT messages back into Home Assistant's event loop."""
        payload_text = message.payload.decode("utf-8", errors="replace")
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            payload = payload_text

        self._hass.loop.call_soon_threadsafe(
            self._schedule_push_update,
            message.topic,
            payload,
        )

    def _schedule_push_update(self, topic: str, payload: Any) -> None:
        """Schedule coordinator state merge from the HA event loop."""
        self._hass.async_create_task(
            self._coordinator.async_apply_push_update(topic, payload)
        )

    def _publish(self, topic: str, payload: str) -> int:
        """Publish a payload from a worker thread."""
        message = self._client.publish(topic, payload=payload, qos=1, retain=False)
        message.wait_for_publish()
        return message.rc
