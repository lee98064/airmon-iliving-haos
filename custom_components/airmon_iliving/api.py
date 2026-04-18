"""AIRMON iLIVING cloud API client."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin

import aiohttp
from yarl import URL

from .const import (
    DEFAULT_AUTH_CLIENT_ID,
    DEFAULT_AUTH_GRANT_TYPE,
    DEFAULT_AUTH_REFRESH_GRANT_TYPE,
    DEFAULT_TIMEOUT,
)
from .models import (
    AirmonDevice,
    coerce_float,
    coerce_text,
    extract_device_payloads,
    extract_first,
)

_LOGGER = logging.getLogger(__name__)

_ACCESS_TOKEN_KEYS = (
    "access_token",
    "accessToken",
    "token",
    "jwt",
)
_REFRESH_TOKEN_KEYS = (
    "refresh_token",
    "refreshToken",
)


class AirmonApiError(Exception):
    """Base error class for API issues."""


class AirmonAuthenticationError(AirmonApiError):
    """Raised when authentication fails."""


class AirmonConnectionError(AirmonApiError):
    """Raised when the API cannot be reached."""


class AirmonApiClient:
    """Best-effort AIRMON client based on APK reverse engineering."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        api_base_url: str,
        auth_client_id: str | None = None,
        auth_client_secret: str | None = None,
        auth_grant_type: str | None = None,
        auth_provider: str | None = None,
    ) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._api_base_url = api_base_url.rstrip("/")
        self._auth_client_id = auth_client_id or DEFAULT_AUTH_CLIENT_ID
        self._auth_client_secret = auth_client_secret or None
        self._auth_grant_type = auth_grant_type or DEFAULT_AUTH_GRANT_TYPE
        self._auth_provider = auth_provider or None
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._session_authenticated = False

    async def async_close(self) -> None:
        """Close the client."""
        return None

    @property
    def username(self) -> str:
        """Return the configured login identifier."""
        return self._username

    @property
    def access_token(self) -> str | None:
        """Return the current access token if available."""
        return self._access_token

    async def async_test_connection(self) -> list[AirmonDevice]:
        """Authenticate and fetch the first device list."""
        await self.async_authenticate()
        try:
            return await self.async_get_devices()
        except AirmonAuthenticationError as err:
            raise AirmonConnectionError(
                "Authenticated, but the device list request was rejected."
            ) from err

    async def async_authenticate(self) -> None:
        """Authenticate against the cloud API."""
        errors: list[str] = []
        for payload in self._build_auth_payload_candidates():
            try:
                response = await self._async_request(
                    "POST",
                    "/v1/users/auth",
                    json_payload=payload,
                    auth_required=False,
                )
            except AirmonApiError as err:
                errors.append(str(err))
                continue

            self._capture_tokens(response)
            if self._access_token:
                self._session_authenticated = True
                _LOGGER.debug("Authenticated with payload keys: %s", list(payload))
                return

            if self._has_session_cookies():
                self._session_authenticated = True
                _LOGGER.debug(
                    "Authenticated with session cookies using payload keys: %s",
                    list(payload),
                )
                return

        raise AirmonAuthenticationError(
            "Authentication failed. Tried payload variants: "
            + ", ".join(errors[-3:] or ["unknown"])
        )

    async def async_get_devices(self) -> list[AirmonDevice]:
        """Fetch and normalize devices from the cloud API."""
        payload = await self._async_request("GET", "/v1/devices")
        devices = self._normalize_devices(payload)

        try:
            power_usage = await self.async_get_power_usage()
        except AirmonApiError as err:
            _LOGGER.debug("Power usage endpoint unavailable: %s", err)
            power_usage = {}

        merged: list[AirmonDevice] = []
        for device in devices:
            if device.mac in power_usage:
                device.power_usage = power_usage[device.mac]
            merged.append(device)

        return merged

    async def async_get_power_usage(self) -> dict[str, float]:
        """Fetch power usage by device MAC if the endpoint is accessible."""
        payload = await self._async_request("GET", "/v1/devices/power-usage")
        mapping: dict[str, float] = {}
        for device_payload in extract_device_payloads(payload):
            device = AirmonDevice.from_mapping(device_payload)
            if device is None or device.power_usage is None:
                continue
            mapping[device.mac] = device.power_usage

        if mapping:
            return mapping

        # Some backends may return a lighter payload containing only usage records.
        records = payload if isinstance(payload, list) else [payload]
        for record in records:
            if not isinstance(record, dict):
                continue
            mac = coerce_text(extract_first(record, ["mac", "deviceMac", "device_mac"]))
            usage = coerce_float(
                extract_first(record, ["powerUsage", "usage", "value", "power_usage"])
            )
            if mac and usage is not None:
                mapping[mac] = usage

        return mapping

    async def async_get_device(self, mac: str) -> AirmonDevice | None:
        """Fetch a single device by MAC address."""
        payload = await self._async_request("GET", f"/v1/devices/mac/{mac}")
        devices = self._normalize_devices(payload)
        if devices:
            return devices[0]
        return None

    async def async_send_command(self, mac: str, command: dict[str, Any]) -> Any:
        """Send an experimental device command."""
        attempts = [
            ("PATCH", f"/v1/devices/mac/{mac}", command),
            ("PUT", f"/v1/devices/mac/{mac}", command),
            ("PATCH", "/v1/devices", {"mac": mac, **command}),
            ("PUT", "/v1/devices", {"mac": mac, **command}),
        ]
        last_error: Exception | None = None

        for method, path, payload in attempts:
            try:
                return await self._async_request(method, path, json_payload=payload)
            except AirmonApiError as err:
                last_error = err
                _LOGGER.debug("Command attempt failed: %s %s -> %s", method, path, err)

        raise AirmonApiError(
            f"Experimental command failed for {mac}: {last_error or 'unknown error'}"
        )

    async def async_raw_request(
        self,
        method: str,
        path: str,
        json_payload: dict[str, Any] | None = None,
        auth_required: bool = True,
    ) -> Any:
        """Run an arbitrary authenticated API request."""
        return await self._async_request(
            method=method,
            path=path,
            json_payload=json_payload,
            auth_required=auth_required,
        )

    def _build_auth_payload_candidates(self) -> list[dict[str, Any]]:
        """Return login payloads matching the Flutter app."""
        username = self._username
        password = self._password
        login_field = self._preferred_login_field(username)
        payloads: list[dict[str, Any]] = []

        for shared in (
            self._auth_payload_shared_fields(),
            self._auth_payload_shared_fields(camel_case=True),
        ):
            for field in dict.fromkeys((login_field, "email", "phone")):
                payload = {**shared, field: username, "password": password}
                if payload not in payloads:
                    payloads.append(payload)

        return payloads

    def _preferred_login_field(self, username: str) -> str:
        """Return the primary login key inferred from the identifier."""
        return "email" if "@" in username else "phone"

    def _auth_payload_shared_fields(
        self,
        *,
        camel_case: bool = False,
        grant_type: str | None = None,
    ) -> dict[str, Any]:
        """Return shared auth fields for login and refresh requests."""
        payload: dict[str, Any] = {}
        client_id_key = "clientId" if camel_case else "client_id"
        client_secret_key = "clientSecret" if camel_case else "client_secret"
        grant_type_key = "grantType" if camel_case else "grant_type"
        if self._auth_client_id:
            payload[client_id_key] = self._auth_client_id
        if self._auth_client_secret:
            payload[client_secret_key] = self._auth_client_secret
        if grant_type or self._auth_grant_type:
            payload[grant_type_key] = grant_type or self._auth_grant_type
        if self._auth_provider:
            payload["provider"] = self._auth_provider
        return payload

    def _capture_tokens(self, payload: Any) -> None:
        """Extract tokens from arbitrary login or refresh responses."""
        access_token = coerce_text(extract_first(payload, _ACCESS_TOKEN_KEYS))
        refresh_token = coerce_text(extract_first(payload, _REFRESH_TOKEN_KEYS))

        if access_token:
            self._access_token = access_token
        if refresh_token:
            self._refresh_token = refresh_token

    def _capture_tokens_from_headers(self, headers: aiohttp.typedefs.LooseHeaders) -> None:
        """Extract bearer or token headers if the backend uses headers instead of JSON."""
        authorization = headers.get("Authorization") or headers.get("authorization")
        if isinstance(authorization, str) and authorization.startswith("Bearer "):
            self._access_token = authorization.removeprefix("Bearer ").strip() or None

        for header_name in ("X-Access-Token", "x-access-token", "access_token", "token"):
            header_value = headers.get(header_name)
            if isinstance(header_value, str) and header_value.strip():
                self._access_token = header_value.strip()
                break

        for header_name in (
            "X-Refresh-Token",
            "x-refresh-token",
            "refresh_token",
            "refreshToken",
        ):
            header_value = headers.get(header_name)
            if isinstance(header_value, str) and header_value.strip():
                self._refresh_token = header_value.strip()
                break

    def _normalize_devices(self, payload: Any) -> list[AirmonDevice]:
        """Normalize arbitrary device payloads into device objects."""
        devices: list[AirmonDevice] = []
        seen: set[str] = set()

        for device_payload in extract_device_payloads(payload):
            device = AirmonDevice.from_mapping(device_payload)
            if device is None or device.unique_id in seen:
                continue
            seen.add(device.unique_id)
            devices.append(device)

        return devices

    async def _async_refresh_token(self) -> None:
        """Refresh the access token."""
        if not self._refresh_token:
            raise AirmonAuthenticationError("No refresh token available")

        attempts = [
            (
                "/v1/users/auth",
                {
                    **self._auth_payload_shared_fields(
                        grant_type=DEFAULT_AUTH_REFRESH_GRANT_TYPE
                    ),
                    "refresh_token": self._refresh_token,
                },
            ),
            (
                "/v1/users/auth",
                {
                    **self._auth_payload_shared_fields(
                        camel_case=True,
                        grant_type=DEFAULT_AUTH_REFRESH_GRANT_TYPE,
                    ),
                    "refreshToken": self._refresh_token,
                },
            ),
            ("api/refresh_token", {"refresh_token": self._refresh_token}),
            ("api/refresh_token", {"refreshToken": self._refresh_token}),
            ("api/refresh_token", {"token": self._refresh_token}),
        ]

        for path, payload in attempts:
            try:
                response = await self._async_request(
                    "POST",
                    path,
                    json_payload=payload,
                    auth_required=False,
                    allow_retry=False,
                )
            except AirmonApiError:
                continue

            self._capture_tokens(response)
            if self._access_token:
                self._session_authenticated = True
                return

        raise AirmonAuthenticationError("Unable to refresh access token")

    async def _async_request(
        self,
        method: str,
        path: str,
        json_payload: dict[str, Any] | None = None,
        auth_required: bool = True,
        allow_retry: bool = True,
    ) -> Any:
        """Execute a JSON HTTP request."""
        if auth_required and not (self._access_token or self._session_authenticated):
            await self.async_authenticate()

        headers: dict[str, str] = {"Accept": "application/json"}
        if auth_required and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        url = self._build_url(path)

        try:
            async with self._session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_payload,
                timeout=DEFAULT_TIMEOUT,
            ) as response:
                payload = await self._decode_response(response)
                self._capture_tokens_from_headers(response.headers)
                if response.cookies:
                    self._session_authenticated = True
        except aiohttp.ClientError as err:
            raise AirmonConnectionError(str(err)) from err

        if 200 <= response.status < 300:
            return payload

        if response.status == 401 and auth_required and allow_retry:
            self._access_token = None
            self._session_authenticated = False
            if self._refresh_token:
                try:
                    await self._async_refresh_token()
                except AirmonAuthenticationError:
                    await self.async_authenticate()
            else:
                await self.async_authenticate()
            return await self._async_request(
                method,
                path,
                json_payload=json_payload,
                auth_required=auth_required,
                allow_retry=False,
            )

        message = self._extract_error_message(payload)
        if response.status in (401, 403):
            raise AirmonAuthenticationError(message)
        raise AirmonApiError(f"{response.status}: {message}")

    async def _decode_response(self, response: aiohttp.ClientResponse) -> Any:
        """Decode JSON or text responses."""
        if response.status == 204:
            return {}

        text = await response.text()
        if not text:
            return {}

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    def _extract_error_message(self, payload: Any) -> str:
        """Extract a human-readable error from a payload."""
        message = coerce_text(
            extract_first(payload, ["message", "error", "detail", "msg", "raw"])
        )
        return message or "Unknown API error"

    def _build_url(self, path: str) -> str:
        """Build an absolute URL from a path."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(f"{self._api_base_url}/", path.lstrip("/"))

    def _has_session_cookies(self) -> bool:
        """Return True when the aiohttp session has cookies for the API host."""
        return bool(self._session.cookie_jar.filter_cookies(URL(self._api_base_url)))
