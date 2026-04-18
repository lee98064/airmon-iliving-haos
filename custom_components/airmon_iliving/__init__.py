"""The AIRMON iLIVING integration."""

from __future__ import annotations

import json
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AirmonApiClient
from .const import (
    ATTR_DEVICE_MAC,
    CONF_API_BASE_URL,
    CONF_ENABLE_EXPERIMENTAL_CONTROL,
    CONF_ENABLE_PUSH,
    CONF_MQTT_HOST,
    CONF_MQTT_PASSWORD,
    CONF_MQTT_PORT,
    CONF_MQTT_TLS,
    CONF_MQTT_USERNAME,
    CONF_POLL_INTERVAL,
    DEFAULT_API_BASE_URL,
    DEFAULT_MQTT_HOST,
    DEFAULT_MQTT_PORT,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    PLATFORMS,
    SERVICE_RAW_API_REQUEST,
    SERVICE_REFRESH,
    SERVICE_SEND_COMMAND,
)
from .coordinator import AirmonDataUpdateCoordinator
from .mqtt import AirmonMqttClient

_LOGGER = logging.getLogger(__name__)

SERVICE_FIELD_AUTH_REQUIRED = "auth_required"
SERVICE_FIELD_ENTRY_ID = "entry_id"
SERVICE_FIELD_METHOD = "method"
SERVICE_FIELD_PATH = "path"
SERVICE_FIELD_PAYLOAD = "payload"

REFRESH_SERVICE_SCHEMA = vol.Schema(
    {
        vol.Optional(SERVICE_FIELD_ENTRY_ID): cv.string,
    }
)
COMMAND_SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_DEVICE_MAC): cv.string,
        vol.Required(SERVICE_FIELD_PAYLOAD): vol.Any(dict, cv.string),
        vol.Optional(SERVICE_FIELD_ENTRY_ID): cv.string,
    }
)
RAW_REQUEST_SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required(SERVICE_FIELD_METHOD): cv.string,
        vol.Required(SERVICE_FIELD_PATH): cv.string,
        vol.Optional(SERVICE_FIELD_PAYLOAD): vol.Any(dict, cv.string),
        vol.Optional(SERVICE_FIELD_AUTH_REQUIRED, default=True): cv.boolean,
        vol.Optional(SERVICE_FIELD_ENTRY_ID): cv.string,
    }
)


async def async_setup(hass: HomeAssistant, _config: dict[str, Any]) -> bool:
    """Set up the AIRMON domain and register services."""
    hass.data.setdefault(DOMAIN, {})

    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH):
        async def _async_refresh_wrapper(call: ServiceCall) -> None:
            await _async_handle_refresh_service(hass, call)

        async def _async_send_command_wrapper(call: ServiceCall) -> None:
            await _async_handle_send_command_service(hass, call)

        async def _async_raw_request_wrapper(call: ServiceCall) -> None:
            await _async_handle_raw_request_service(hass, call)

        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH,
            _async_refresh_wrapper,
            schema=REFRESH_SERVICE_SCHEMA,
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_SEND_COMMAND,
            _async_send_command_wrapper,
            schema=COMMAND_SERVICE_SCHEMA,
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_RAW_API_REQUEST,
            _async_raw_request_wrapper,
            schema=RAW_REQUEST_SERVICE_SCHEMA,
        )

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AIRMON iLIVING from a config entry."""
    session = async_get_clientsession(hass)
    api = AirmonApiClient(
        session=session,
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        api_base_url=entry.options.get(
            CONF_API_BASE_URL,
            entry.data.get(CONF_API_BASE_URL, DEFAULT_API_BASE_URL),
        ),
    )
    coordinator = AirmonDataUpdateCoordinator(
        hass=hass,
        api=api,
        poll_interval=entry.options.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
        experimental_control=entry.options.get(CONF_ENABLE_EXPERIMENTAL_CONTROL, False),
    )

    await coordinator.async_config_entry_first_refresh()

    mqtt_client: AirmonMqttClient | None = None
    if entry.options.get(CONF_ENABLE_PUSH, False):
        mqtt_client = AirmonMqttClient(
            hass=hass,
            api=api,
            coordinator=coordinator,
            host=entry.options.get(CONF_MQTT_HOST, DEFAULT_MQTT_HOST),
            port=entry.options.get(CONF_MQTT_PORT, DEFAULT_MQTT_PORT),
            username=entry.options.get(CONF_MQTT_USERNAME),
            password=entry.options.get(CONF_MQTT_PASSWORD),
            use_tls=entry.options.get(CONF_MQTT_TLS, False),
        )
        try:
            await mqtt_client.async_start()
        except Exception:  # noqa: BLE001
            _LOGGER.warning(
                "AIRMON MQTT push setup failed; continuing with polling only",
                exc_info=True,
            )
            mqtt_client = None

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
        "mqtt": mqtt_client,
    }

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    entry_data: dict[str, Any] = hass.data[DOMAIN].pop(entry.entry_id)
    mqtt_client: AirmonMqttClient | None = entry_data["mqtt"]
    if mqtt_client is not None:
        await mqtt_client.async_stop()

    api: AirmonApiClient = entry_data["api"]
    await api.async_close()

    if not hass.data[DOMAIN]:
        hass.data.pop(DOMAIN)

    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


def _entry_data_for_call(
    hass: HomeAssistant,
    entry_id: str | None,
) -> dict[str, Any]:
    """Resolve a config-entry runtime record for a service call."""
    entries = hass.data.get(DOMAIN, {})
    if not entries:
        raise HomeAssistantError("No AIRMON iLIVING config entries are loaded.")

    if entry_id is None:
        return next(iter(entries.values()))

    try:
        return entries[entry_id]
    except KeyError as err:
        raise HomeAssistantError(f"Unknown AIRMON entry_id: {entry_id}") from err


def _parse_payload(value: dict[str, Any] | str | None) -> dict[str, Any] | None:
    """Parse object-or-JSON-string service payloads."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as err:
        raise HomeAssistantError(f"Invalid JSON payload: {err}") from err
    if not isinstance(parsed, dict):
        raise HomeAssistantError("Payload must decode to a JSON object.")
    return parsed


async def _async_handle_refresh_service(hass: HomeAssistant, call: ServiceCall) -> None:
    """Refresh one or all AIRMON entries."""
    entry_id = call.data.get(SERVICE_FIELD_ENTRY_ID)

    if entry_id is not None:
        coordinator: AirmonDataUpdateCoordinator = _entry_data_for_call(
            hass, entry_id
        )["coordinator"]
        await coordinator.async_request_refresh()
        return

    for entry_data in hass.data.get(DOMAIN, {}).values():
        coordinator = entry_data["coordinator"]
        await coordinator.async_request_refresh()


async def _async_handle_send_command_service(
    hass: HomeAssistant, call: ServiceCall
) -> None:
    """Send an experimental command to a device."""
    entry_data = _entry_data_for_call(hass, call.data.get(SERVICE_FIELD_ENTRY_ID))
    coordinator: AirmonDataUpdateCoordinator = entry_data["coordinator"]
    mac = call.data[ATTR_DEVICE_MAC].lower()
    payload = _parse_payload(call.data.get(SERVICE_FIELD_PAYLOAD))
    if payload is None:
        raise HomeAssistantError("Command payload is required.")

    for device in coordinator.data.values():
        if device.mac.lower() != mac:
            continue
        await coordinator.async_send_device_command(device, payload)
        return

    raise HomeAssistantError(f"No AIRMON device found for MAC address {mac}.")


async def _async_handle_raw_request_service(
    hass: HomeAssistant, call: ServiceCall
) -> None:
    """Run an arbitrary API request for troubleshooting."""
    entry_data = _entry_data_for_call(hass, call.data.get(SERVICE_FIELD_ENTRY_ID))
    api: AirmonApiClient = entry_data["api"]
    payload = _parse_payload(call.data.get(SERVICE_FIELD_PAYLOAD))
    await api.async_raw_request(
        method=call.data[SERVICE_FIELD_METHOD].upper(),
        path=call.data[SERVICE_FIELD_PATH],
        json_payload=payload,
        auth_required=call.data[SERVICE_FIELD_AUTH_REQUIRED],
    )
