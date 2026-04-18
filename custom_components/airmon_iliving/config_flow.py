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
    CONF_AUTH_CLIENT_ID,
    CONF_AUTH_CLIENT_SECRET,
    CONF_AUTH_GRANT_TYPE,
    CONF_AUTH_PROVIDER,
    CONF_CWA_AUTHORIZATION,
    CONF_ENABLE_EXPERIMENTAL_CONTROL,
    CONF_ENABLE_PUSH,
    CONF_MQTT_HOST,
    CONF_MQTT_PASSWORD,
    CONF_MQTT_PORT,
    CONF_MQTT_TLS,
    CONF_MQTT_USERNAME,
    CONF_POLL_INTERVAL,
    DEFAULT_API_BASE_URL,
    DEFAULT_AUTH_CLIENT_ID,
    DEFAULT_AUTH_GRANT_TYPE,
    DEFAULT_MQTT_HOST,
    DEFAULT_MQTT_PORT,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _default_str(
    defaults: dict[str, Any],
    key: str,
    fallback: str = "",
) -> str:
    """Return a string default safe for schema serialization."""
    value = defaults.get(key, fallback)
    if value is None:
        return fallback
    return str(value)


def _default_bool(
    defaults: dict[str, Any],
    key: str,
    fallback: bool = False,
) -> bool:
    """Return a boolean default safe for schema serialization."""
    value = defaults.get(key, fallback)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return fallback


def _default_int(
    defaults: dict[str, Any],
    key: str,
    fallback: int,
) -> int:
    """Return an integer default safe for schema serialization."""
    value = defaults.get(key, fallback)
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _default_provider(defaults: dict[str, Any]) -> str:
    """Return the stored provider override if one exists."""
    return _default_str(defaults, CONF_AUTH_PROVIDER, "")


def _user_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    """Return the user form schema."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_USERNAME, default=_default_str(defaults, CONF_USERNAME)): str,
            vol.Required(CONF_PASSWORD, default=_default_str(defaults, CONF_PASSWORD)): str,
            vol.Optional(
                CONF_API_BASE_URL,
                default=_default_str(
                    defaults,
                    CONF_API_BASE_URL,
                    DEFAULT_API_BASE_URL,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_CLIENT_ID,
                default=_default_str(
                    defaults,
                    CONF_AUTH_CLIENT_ID,
                    DEFAULT_AUTH_CLIENT_ID,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_CLIENT_SECRET,
                default=_default_str(defaults, CONF_AUTH_CLIENT_SECRET, ""),
            ): str,
            vol.Optional(
                CONF_AUTH_GRANT_TYPE,
                default=_default_str(
                    defaults,
                    CONF_AUTH_GRANT_TYPE,
                    DEFAULT_AUTH_GRANT_TYPE,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_PROVIDER,
                default=_default_provider(defaults),
            ): str,
            vol.Optional(
                CONF_CWA_AUTHORIZATION,
                default=_default_str(defaults, CONF_CWA_AUTHORIZATION, ""),
            ): str,
            vol.Optional(
                CONF_POLL_INTERVAL,
                default=_default_int(
                    defaults,
                    CONF_POLL_INTERVAL,
                    DEFAULT_POLL_INTERVAL,
                ),
            ): vol.All(int, vol.Range(min=15, max=3600)),
            vol.Optional(
                CONF_ENABLE_EXPERIMENTAL_CONTROL,
                default=_default_bool(
                    defaults,
                    CONF_ENABLE_EXPERIMENTAL_CONTROL,
                    False,
                ),
            ): bool,
            vol.Optional(
                CONF_ENABLE_PUSH,
                default=_default_bool(defaults, CONF_ENABLE_PUSH, False),
            ): bool,
            vol.Optional(
                CONF_MQTT_HOST,
                default=_default_str(defaults, CONF_MQTT_HOST, DEFAULT_MQTT_HOST),
            ): str,
            vol.Optional(
                CONF_MQTT_PORT,
                default=_default_int(defaults, CONF_MQTT_PORT, DEFAULT_MQTT_PORT),
            ): vol.All(int, vol.Range(min=1, max=65535)),
            vol.Optional(
                CONF_MQTT_USERNAME,
                default=_default_str(defaults, CONF_MQTT_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_PASSWORD,
                default=_default_str(defaults, CONF_MQTT_PASSWORD, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_TLS,
                default=_default_bool(defaults, CONF_MQTT_TLS, False),
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
                default=_default_str(
                    defaults,
                    CONF_API_BASE_URL,
                    DEFAULT_API_BASE_URL,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_CLIENT_ID,
                default=_default_str(
                    defaults,
                    CONF_AUTH_CLIENT_ID,
                    DEFAULT_AUTH_CLIENT_ID,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_CLIENT_SECRET,
                default=_default_str(defaults, CONF_AUTH_CLIENT_SECRET, ""),
            ): str,
            vol.Optional(
                CONF_AUTH_GRANT_TYPE,
                default=_default_str(
                    defaults,
                    CONF_AUTH_GRANT_TYPE,
                    DEFAULT_AUTH_GRANT_TYPE,
                ),
            ): str,
            vol.Optional(
                CONF_AUTH_PROVIDER,
                default=_default_str(defaults, CONF_AUTH_PROVIDER, ""),
            ): str,
            vol.Optional(
                CONF_CWA_AUTHORIZATION,
                default=_default_str(defaults, CONF_CWA_AUTHORIZATION, ""),
            ): str,
            vol.Optional(
                CONF_POLL_INTERVAL,
                default=_default_int(
                    defaults,
                    CONF_POLL_INTERVAL,
                    DEFAULT_POLL_INTERVAL,
                ),
            ): vol.All(int, vol.Range(min=15, max=3600)),
            vol.Optional(
                CONF_ENABLE_EXPERIMENTAL_CONTROL,
                default=_default_bool(
                    defaults,
                    CONF_ENABLE_EXPERIMENTAL_CONTROL,
                    False,
                ),
            ): bool,
            vol.Optional(
                CONF_ENABLE_PUSH,
                default=_default_bool(defaults, CONF_ENABLE_PUSH, False),
            ): bool,
            vol.Optional(
                CONF_MQTT_HOST,
                default=_default_str(defaults, CONF_MQTT_HOST, DEFAULT_MQTT_HOST),
            ): str,
            vol.Optional(
                CONF_MQTT_PORT,
                default=_default_int(defaults, CONF_MQTT_PORT, DEFAULT_MQTT_PORT),
            ): vol.All(int, vol.Range(min=1, max=65535)),
            vol.Optional(
                CONF_MQTT_USERNAME,
                default=_default_str(defaults, CONF_MQTT_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_PASSWORD,
                default=_default_str(defaults, CONF_MQTT_PASSWORD, ""),
            ): str,
            vol.Optional(
                CONF_MQTT_TLS,
                default=_default_bool(defaults, CONF_MQTT_TLS, False),
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
                    CONF_AUTH_CLIENT_ID: user_input[CONF_AUTH_CLIENT_ID],
                    CONF_AUTH_CLIENT_SECRET: user_input[CONF_AUTH_CLIENT_SECRET],
                    CONF_AUTH_GRANT_TYPE: user_input[CONF_AUTH_GRANT_TYPE],
                    CONF_AUTH_PROVIDER: user_input[CONF_AUTH_PROVIDER],
                    CONF_CWA_AUTHORIZATION: user_input[CONF_CWA_AUTHORIZATION],
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
            auth_client_id=user_input[CONF_AUTH_CLIENT_ID],
            auth_client_secret=user_input[CONF_AUTH_CLIENT_SECRET],
            auth_grant_type=user_input[CONF_AUTH_GRANT_TYPE],
            auth_provider=user_input[CONF_AUTH_PROVIDER],
        )
        try:
            await api.async_test_connection()
        except AirmonAuthenticationError as err:
            message = str(err).lower()
            if "client_id" in message:
                errors["base"] = "invalid_client"
            else:
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
            CONF_AUTH_CLIENT_ID: _default_str(
                self.config_entry.options,
                CONF_AUTH_CLIENT_ID,
                DEFAULT_AUTH_CLIENT_ID,
            ),
            CONF_AUTH_CLIENT_SECRET: _default_str(
                self.config_entry.options,
                CONF_AUTH_CLIENT_SECRET,
                "",
            ),
            CONF_AUTH_GRANT_TYPE: _default_str(
                self.config_entry.options,
                CONF_AUTH_GRANT_TYPE,
                DEFAULT_AUTH_GRANT_TYPE,
            ),
            CONF_AUTH_PROVIDER: _default_str(
                self.config_entry.options,
                CONF_AUTH_PROVIDER,
                "",
            ),
            CONF_CWA_AUTHORIZATION: _default_str(
                self.config_entry.options,
                CONF_CWA_AUTHORIZATION,
                "",
            ),
            CONF_POLL_INTERVAL: _default_int(
                self.config_entry.options,
                CONF_POLL_INTERVAL,
                DEFAULT_POLL_INTERVAL,
            ),
            CONF_ENABLE_EXPERIMENTAL_CONTROL: _default_bool(
                self.config_entry.options,
                CONF_ENABLE_EXPERIMENTAL_CONTROL,
                False,
            ),
            CONF_ENABLE_PUSH: _default_bool(
                self.config_entry.options,
                CONF_ENABLE_PUSH,
                False,
            ),
            CONF_MQTT_HOST: _default_str(
                self.config_entry.options,
                CONF_MQTT_HOST,
                DEFAULT_MQTT_HOST,
            ),
            CONF_MQTT_PORT: _default_int(
                self.config_entry.options,
                CONF_MQTT_PORT,
                DEFAULT_MQTT_PORT,
            ),
            CONF_MQTT_USERNAME: _default_str(
                self.config_entry.options,
                CONF_MQTT_USERNAME,
                "",
            ),
            CONF_MQTT_PASSWORD: _default_str(
                self.config_entry.options,
                CONF_MQTT_PASSWORD,
                "",
            ),
            CONF_MQTT_TLS: _default_bool(
                self.config_entry.options,
                CONF_MQTT_TLS,
                False,
            ),
            CONF_API_BASE_URL: _default_str(
                self.config_entry.options,
                CONF_API_BASE_URL,
                self.config_entry.data.get(CONF_API_BASE_URL, DEFAULT_API_BASE_URL),
            ),
        }
        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(current),
        )
