"""Config flow for AIRMON iLIVING."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    AirmonApiClient,
    AirmonAuthenticationError,
    AirmonConnectionError,
)
from .const import (
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
)

_LOGGER = logging.getLogger(__name__)


def _user_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    """Return the user form schema."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, "")): str,
            vol.Required(CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, "")): str,
            vol.Optional(
                CONF_API_BASE_URL,
                default=defaults.get(CONF_API_BASE_URL, DEFAULT_API_BASE_URL),
            ): str,
            vol.Optional(
                CONF_POLL_INTERVAL,
                default=defaults.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
            ): vol.All(int, vol.Range(min=15, max=3600)),
            vol.Optional(
                CONF_ENABLE_EXPERIMENTAL_CONTROL,
                default=defaults.get(CONF_ENABLE_EXPERIMENTAL_CONTROL, False),
            ): bool,
            vol.Optional(
                CONF_ENABLE_PUSH,
                default=defaults.get(CONF_ENABLE_PUSH, False),
            ): bool,
            vol.Optional(
                CONF_MQTT_HOST,
                default=defaults.get(CONF_MQTT_HOST, DEFAULT_MQTT_HOST),
            ): str,
            vol.Optional(
                CONF_MQTT_PORT,
                default=defaults.get(CONF_MQTT_PORT, DEFAULT_MQTT_PORT),
            ): vol.All(int, vol.Range(min=1, max=65535)),
            vol.Optional(
                CONF_MQTT_USERNAME,
                default=defaults.get(CONF_MQTT_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_PASSWORD,
                default=defaults.get(CONF_MQTT_PASSWORD, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_TLS,
                default=defaults.get(CONF_MQTT_TLS, False),
            ): bool,
        }
    )


def _options_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    """Return the options form schema."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Optional(
                CONF_API_BASE_URL,
                default=defaults.get(CONF_API_BASE_URL, DEFAULT_API_BASE_URL),
            ): str,
            vol.Optional(
                CONF_POLL_INTERVAL,
                default=defaults.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
            ): vol.All(int, vol.Range(min=15, max=3600)),
            vol.Optional(
                CONF_ENABLE_EXPERIMENTAL_CONTROL,
                default=defaults.get(CONF_ENABLE_EXPERIMENTAL_CONTROL, False),
            ): bool,
            vol.Optional(
                CONF_ENABLE_PUSH,
                default=defaults.get(CONF_ENABLE_PUSH, False),
            ): bool,
            vol.Optional(
                CONF_MQTT_HOST,
                default=defaults.get(CONF_MQTT_HOST, DEFAULT_MQTT_HOST),
            ): str,
            vol.Optional(
                CONF_MQTT_PORT,
                default=defaults.get(CONF_MQTT_PORT, DEFAULT_MQTT_PORT),
            ): vol.All(int, vol.Range(min=1, max=65535)),
            vol.Optional(
                CONF_MQTT_USERNAME,
                default=defaults.get(CONF_MQTT_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_PASSWORD,
                default=defaults.get(CONF_MQTT_PASSWORD, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_TLS,
                default=defaults.get(CONF_MQTT_TLS, False),
            ): bool,
        }
    )


class AirmonConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for AIRMON iLIVING."""

    VERSION = 1

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Return the options flow."""
        return AirmonOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_USERNAME])
            self._abort_if_unique_id_configured()

            if await self._async_validate_credentials(user_input, errors):
                data = {
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                    CONF_API_BASE_URL: user_input[CONF_API_BASE_URL],
                }
                options = {
                    CONF_POLL_INTERVAL: user_input[CONF_POLL_INTERVAL],
                    CONF_ENABLE_EXPERIMENTAL_CONTROL: user_input[
                        CONF_ENABLE_EXPERIMENTAL_CONTROL
                    ],
                    CONF_ENABLE_PUSH: user_input[CONF_ENABLE_PUSH],
                    CONF_MQTT_HOST: user_input[CONF_MQTT_HOST],
                    CONF_MQTT_PORT: user_input[CONF_MQTT_PORT],
                    CONF_MQTT_USERNAME: user_input[CONF_MQTT_USERNAME],
                    CONF_MQTT_PASSWORD: user_input[CONF_MQTT_PASSWORD],
                    CONF_MQTT_TLS: user_input[CONF_MQTT_TLS],
                }
                return self.async_create_entry(
                    title=f"AIRMON {user_input[CONF_USERNAME]}",
                    data=data,
                    options=options,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input),
            errors=errors,
        )

    async def _async_validate_credentials(
        self, user_input: dict[str, Any], errors: dict[str, str]
    ) -> bool:
        """Validate credentials by hitting the cloud API."""
        api = AirmonApiClient(
            session=async_get_clientsession(self.hass),
            username=user_input[CONF_USERNAME],
            password=user_input[CONF_PASSWORD],
            api_base_url=user_input[CONF_API_BASE_URL],
        )
        try:
            await api.async_test_connection()
        except AirmonAuthenticationError:
            errors["base"] = "invalid_auth"
            return False
        except AirmonConnectionError:
            errors["base"] = "cannot_connect"
            return False
        except Exception:
            _LOGGER.exception("Unexpected error during AIRMON validation")
            errors["base"] = "unknown"
            return False
        return True


class AirmonOptionsFlow(config_entries.OptionsFlow):
    """Options flow for AIRMON iLIVING."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = {
            CONF_POLL_INTERVAL: self.config_entry.options.get(
                CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
            ),
            CONF_ENABLE_EXPERIMENTAL_CONTROL: self.config_entry.options.get(
                CONF_ENABLE_EXPERIMENTAL_CONTROL, False
            ),
            CONF_ENABLE_PUSH: self.config_entry.options.get(CONF_ENABLE_PUSH, False),
            CONF_MQTT_HOST: self.config_entry.options.get(
                CONF_MQTT_HOST, DEFAULT_MQTT_HOST
            ),
            CONF_MQTT_PORT: self.config_entry.options.get(
                CONF_MQTT_PORT, DEFAULT_MQTT_PORT
            ),
            CONF_MQTT_USERNAME: self.config_entry.options.get(CONF_MQTT_USERNAME, ""),
            CONF_MQTT_PASSWORD: self.config_entry.options.get(CONF_MQTT_PASSWORD, ""),
            CONF_MQTT_TLS: self.config_entry.options.get(CONF_MQTT_TLS, False),
            CONF_API_BASE_URL: self.config_entry.options.get(
                CONF_API_BASE_URL,
                self.config_entry.data.get(CONF_API_BASE_URL, DEFAULT_API_BASE_URL),
            ),
        }
        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(current),
        )
