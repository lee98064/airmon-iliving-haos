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
        self._configured_username = username or None
        self._configured_password = password or None
        self._username: str | None = None
        self._password: str | None = None
        self._active_username: str | None = None
        self._active_password: str | None = None
        self._use_tls = use_tls
        self._subscribe_updates = subscribe_updates
        self._started = False
        self._connected = False
        self._connect_lock = asyncio.Lock()
        self._connected_event = asyncio.Event()
        self._failed_event = asyncio.Event()
        self._last_failure: str | None = None
        self._client = self._build_client()

    async def async_start(self) -> None:
        """Start the background MQTT loop."""
        async with self._connect_lock:
            if self._started and self._connected:
                return

            token = await self._api.async_ensure_access_token()
            last_error: RuntimeError | None = None

            for username, password, label in self._credential_candidates(token):
                self._username = username
                self._password = password
                if self._username:
                    self._client.username_pw_set(self._username, self._password)

                if self._use_tls:
                    self._client.tls_set(cert_reqs=ssl.CERT_REQUIRED)

                self._connected_event.clear()
                self._failed_event.clear()
                self._last_failure = None
                _LOGGER.debug(
                    "Trying AIRMON MQTT connection to %s:%s using %s",
                    self._host,
                    self._port,
                    label,
                )

                try:
                    if not self._started:
                        await self._hass.async_add_executor_job(self._connect)
                        self._started = True
                    elif not self._connected:
                        await self._hass.async_add_executor_job(self._reconnect)
                    await self._async_wait_for_connection()
                except RuntimeError as err:
                    last_error = err
                    _LOGGER.warning(
                        "AIRMON MQTT connect attempt failed using %s: %s",
                        label,
                        err,
                    )
                    if self._started:
                        await self._hass.async_add_executor_job(self._disconnect)
                        self._started = False
                        self._connected = False
                    self._client = self._build_client()
                    continue

                self._active_username = self._username
                self._active_password = self._password
                return

            raise last_error or RuntimeError(
                f"AIRMON MQTT connection failed for {self._host}:{self._port}"
            )

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
        if not self._is_success_reason_code(reason_code):
            self._connected = False
            self._last_failure = (
                f"AIRMON MQTT connect rejected by broker: {self._reason_code_text(reason_code)}"
            )
            self._hass.loop.call_soon_threadsafe(self._failed_event.set)
            _LOGGER.warning("AIRMON MQTT connect failed: %s", reason_code)
            return

        self._connected = True
        self._last_failure = None
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
        if self._is_success_reason_code(reason_code):
            return
        if not self._connected_event.is_set():
            self._last_failure = (
                "AIRMON MQTT disconnected during connect: "
                f"{self._reason_code_text(reason_code)}"
            )
            self._hass.loop.call_soon_threadsafe(self._failed_event.set)
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

    def _build_client(self) -> mqtt.Client:
        """Create a fresh MQTT client instance bound to this object."""
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"ha-airmon-{uuid4().hex[:10]}",
            protocol=mqtt.MQTTv311,
        )
        client.enable_logger(_LOGGER)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        return client

    def _credential_candidates(
        self,
        token: str,
    ) -> list[tuple[str, str, str]]:
        """Return MQTT credential candidates in the order worth trying."""
        candidates: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(
            username: str | None,
            password: str | None,
            label: str,
        ) -> None:
            if not username or not password:
                return
            key = (username, password)
            if key in seen:
                return
            seen.add(key)
            candidates.append((username, password, label))

        add(self._active_username, self._active_password, "cached MQTT credentials")
        add(
            self._configured_username or self._api.username,
            self._configured_password or token,
            "configured MQTT credentials",
        )
        add(self._api.username, token, "AIRMON app credentials")
        return candidates

    async def _async_wait_for_connection(self) -> None:
        """Wait for either a successful MQTT connection or a definite failure."""
        connected_task = asyncio.create_task(self._connected_event.wait())
        failed_task = asyncio.create_task(self._failed_event.wait())
        try:
            done, pending = await asyncio.wait(
                {connected_task, failed_task},
                timeout=10,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for task in (connected_task, failed_task):
                if not task.done():
                    task.cancel()

        if not done:
            raise RuntimeError(
                f"AIRMON MQTT connection timed out for {self._host}:{self._port}"
            )

        if failed_task in done and self._failed_event.is_set():
            raise RuntimeError(self._last_failure or "AIRMON MQTT connection failed")

    @staticmethod
    def _is_success_reason_code(reason_code: Any) -> bool:
        """Return whether a paho reason code represents success."""
        is_failure = getattr(reason_code, "is_failure", None)
        if is_failure is not None:
            try:
                return not bool(is_failure)
            except Exception:  # noqa: BLE001
                pass

        value = getattr(reason_code, "value", reason_code)
        try:
            return int(value) == 0
        except (TypeError, ValueError):
            text = str(reason_code).strip().lower()
            return text in {"0", "success", "normal disconnection"}

    @staticmethod
    def _reason_code_text(reason_code: Any) -> str:
        """Return a stable human-readable reason-code string."""
        value = getattr(reason_code, "value", None)
        if value is not None:
            return f"{reason_code} ({value})"
        return str(reason_code)
