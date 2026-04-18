"""AIRMON iLIVING cloud API client."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from datetime import UTC, date, datetime, timedelta
import json
import logging
from typing import Any
from urllib.parse import urljoin
from uuid import uuid4

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

_CWA_BASE_URL = "https://opendata.cwa.gov.tw/api"
_OPEN_METEO_URL = "https://api.open-meteo.com/v1/forecast"
_WEATHER_CACHE_TTL = timedelta(hours=1)
_CWA_CITY_DATASET_CODES = {
    "基隆市": "F-D0047-049",
    "臺北市": "F-D0047-061",
    "台北市": "F-D0047-061",
    "新北市": "F-D0047-069",
    "桃園市": "F-D0047-005",
    "新竹市": "F-D0047-053",
    "新竹縣": "F-D0047-009",
    "苗栗縣": "F-D0047-013",
    "臺中市": "F-D0047-073",
    "台中市": "F-D0047-073",
    "彰化縣": "F-D0047-017",
    "南投縣": "F-D0047-021",
    "雲林縣": "F-D0047-025",
    "嘉義市": "F-D0047-057",
    "嘉義縣": "F-D0047-029",
    "臺南市": "F-D0047-077",
    "台南市": "F-D0047-077",
    "高雄市": "F-D0047-065",
    "屏東縣": "F-D0047-033",
    "臺東縣": "F-D0047-037",
    "台東縣": "F-D0047-037",
    "花蓮縣": "F-D0047-041",
    "宜蘭縣": "F-D0047-001",
    "澎湖縣": "F-D0047-045",
    "金門縣": "F-D0047-085",
    "連江縣": "F-D0047-081",
}

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
        cwa_authorization: str | None = None,
    ) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._api_base_url = api_base_url.rstrip("/")
        self._auth_client_id = auth_client_id or DEFAULT_AUTH_CLIENT_ID
        self._auth_client_secret = auth_client_secret or None
        self._auth_grant_type = auth_grant_type or DEFAULT_AUTH_GRANT_TYPE
        self._auth_provider = auth_provider or None
        self._cwa_authorization = cwa_authorization or None
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._user_id: str | None = None
        self._session_authenticated = False
        self._weather_cache: dict[str, tuple[datetime, float | None]] = {}

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
        family_locations = await self.async_get_family_locations()

        try:
            power_usage = await self.async_get_power_usage(devices)
        except AirmonApiError as err:
            _LOGGER.debug("Power usage endpoint unavailable: %s", err)
            power_usage = {}

        outdoor_temperatures = await self.async_get_outdoor_temperatures(family_locations)
        merged: list[AirmonDevice] = []
        for device in devices:
            if device.mac in power_usage:
                device.power_usage = power_usage[device.mac]
            if device.family_id and device.family_id in outdoor_temperatures:
                device.outdoor_temperature = outdoor_temperatures[device.family_id]
            merged.append(device)

        return merged

    async def async_get_power_usage(
        self,
        devices: list[AirmonDevice],
    ) -> dict[str, float]:
        """Fetch per-device monthly energy usage by device MAC."""
        mapping: dict[str, float] = {}

        today = date.today()
        params = {
            "timeUnit": "Month",
            "startDate": date(today.year, 1, 1).isoformat(),
            "endDate": today.isoformat(),
        }

        for device in devices:
            try:
                payload = await self._async_request(
                    "GET",
                    f"/v1/devices/mac/{device.mac}/power-usage",
                    params=params,
                )
            except AirmonApiError as err:
                _LOGGER.debug("Power usage unavailable for %s: %s", device.mac, err)
                continue

            usage = self._extract_power_usage_value(payload)
            if usage is None:
                continue
            mapping[device.mac] = usage

        return mapping

    async def async_get_family_locations(self) -> dict[str, dict[str, Any]]:
        """Fetch family metadata keyed by family id."""
        try:
            payload = await self._async_request("GET", "/v1/families")
        except AirmonApiError as err:
            _LOGGER.debug("Family endpoint unavailable: %s", err)
            return {}

        families = payload.get("families") if isinstance(payload, dict) else None
        if not isinstance(families, list):
            return {}

        mapping: dict[str, dict[str, Any]] = {}
        for family in families:
            if not isinstance(family, dict):
                continue
            family_id = coerce_text(extract_first(family, ["id", "familyId"]))
            location = family.get("location")
            if family_id is None or not isinstance(location, dict):
                continue
            mapping[family_id] = location

        return mapping

    async def async_get_outdoor_temperatures(
        self,
        family_locations: dict[str, dict[str, Any]],
    ) -> dict[str, float]:
        """Fetch outdoor temperatures keyed by family id."""
        temperatures: dict[str, float] = {}
        for family_id, location in family_locations.items():
            temperature = await self._async_get_outdoor_temperature(location)
            if temperature is not None:
                temperatures[family_id] = temperature
        return temperatures

    async def async_get_device(self, mac: str) -> AirmonDevice | None:
        """Fetch a single device by MAC address."""
        payload = await self._async_request("GET", f"/v1/devices/mac/{mac}")
        devices = self._normalize_devices(payload)
        if devices:
            return devices[0]
        return None

    async def async_ensure_access_token(self) -> str:
        """Return a valid bearer token for MQTT or authenticated requests."""
        if self._access_token:
            return self._access_token

        await self.async_authenticate()
        if self._access_token:
            return self._access_token

        if self._refresh_token:
            await self._async_refresh_token()
        if self._access_token:
            return self._access_token

        raise AirmonAuthenticationError("No access token returned by the AIRMON API.")

    async def async_get_user_id(self) -> str | None:
        """Return the current user id when it can be inferred from the token."""
        if self._user_id is not None:
            return self._user_id

        try:
            token = await self.async_ensure_access_token()
        except AirmonAuthenticationError:
            return None

        self._user_id = self._extract_user_id_from_token(token)
        return self._user_id

    async def _async_get_outdoor_temperature(
        self,
        location: dict[str, Any],
    ) -> float | None:
        """Return the cached or freshly fetched outdoor temperature."""
        city = self._normalize_city_name(coerce_text(location.get("city")))
        district = coerce_text(location.get("district"))
        cache_key = f"{city or ''}|{district or ''}"
        now = datetime.now(UTC)

        if cache_key in self._weather_cache:
            cached_at, cached_value = self._weather_cache[cache_key]
            if now - cached_at < _WEATHER_CACHE_TTL:
                return cached_value

        temperature = await self._async_fetch_cwa_temperature(city, district)
        if temperature is None:
            temperature = await self._async_fetch_open_meteo_temperature(location)

        self._weather_cache[cache_key] = (now, temperature)
        return temperature

    async def _async_fetch_cwa_temperature(
        self,
        city: str | None,
        district: str | None,
    ) -> float | None:
        """Fetch outdoor temperature from the CWA township forecast."""
        if city is None or district is None:
            return None

        dataset_code = _CWA_CITY_DATASET_CODES.get(city)
        if dataset_code is None or self._cwa_authorization is None:
            return None

        payload = await self._async_external_request(
            "GET",
            f"{_CWA_BASE_URL}/v1/rest/datastore/{dataset_code}",
            params={
                "ElementName": "溫度,天氣現象",
                "LocationName": district,
                "uid": uuid4().hex,
            },
            headers={"Authorization": self._cwa_authorization},
        )
        return self._extract_cwa_temperature(payload, district)

    async def _async_fetch_open_meteo_temperature(
        self,
        location: dict[str, Any],
    ) -> float | None:
        """Fallback outdoor temperature using coordinates when CWA fails."""
        latitude = coerce_float(location.get("latitude"))
        longitude = coerce_float(location.get("longitude"))
        if latitude is None or longitude is None:
            return None

        payload = await self._async_external_request(
            "GET",
            _OPEN_METEO_URL,
            params={
                "latitude": latitude,
                "longitude": longitude,
                "current": "temperature_2m",
                "timezone": "auto",
            },
        )
        if not isinstance(payload, dict):
            return None

        current = payload.get("current")
        if isinstance(current, dict):
            temperature = coerce_float(current.get("temperature_2m"))
            if temperature is not None:
                return temperature

        current_weather = payload.get("current_weather")
        if isinstance(current_weather, dict):
            temperature = coerce_float(current_weather.get("temperature"))
            if temperature is not None:
                return temperature

        return None

    async def _async_external_request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Run an external HTTP request without AIRMON auth handling."""
        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        try:
            async with self._session.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                timeout=DEFAULT_TIMEOUT,
            ) as response:
                payload = await self._decode_response(response)
        except aiohttp.ClientError as err:
            _LOGGER.debug("External request failed: %s %s -> %s", method, url, err)
            return None

        if 200 <= response.status < 300:
            return payload

        _LOGGER.debug(
            "External request returned %s for %s: %s",
            response.status,
            url,
            self._extract_error_message(payload),
        )
        return None

    def _extract_power_usage_value(self, payload: Any) -> float | None:
        """Extract the latest month total from a power usage payload."""
        items = extract_first(payload, ["items"])
        if isinstance(items, list):
            for item in reversed(items):
                if not isinstance(item, dict):
                    continue
                usage = coerce_float(extract_first(item, ["wh", "powerUsage", "value"]))
                if usage is not None:
                    return usage

        return coerce_float(extract_first(payload, ["wh", "powerUsage", "value"]))

    def _extract_cwa_temperature(self, payload: Any, district: str) -> float | None:
        """Extract the first township temperature from a CWA response."""
        if not isinstance(payload, dict):
            return None

        records = payload.get("records")
        if not isinstance(records, dict):
            return None

        locations = records.get("Locations") or records.get("locations")
        if not isinstance(locations, list):
            locations = [locations] if isinstance(locations, dict) else []

        for locations_item in locations:
            if not isinstance(locations_item, dict):
                continue

            towns = locations_item.get("Location") or locations_item.get("location")
            if not isinstance(towns, list):
                towns = [towns] if isinstance(towns, dict) else []

            for town in towns:
                if not isinstance(town, dict):
                    continue
                location_name = coerce_text(
                    town.get("LocationName") or town.get("locationName")
                )
                if location_name not in {district, self._normalize_town_name(district)}:
                    continue

                weather_elements = (
                    town.get("WeatherElement") or town.get("weatherElement")
                )
                if not isinstance(weather_elements, list):
                    weather_elements = (
                        [weather_elements] if isinstance(weather_elements, dict) else []
                    )

                for weather_element in weather_elements:
                    if not isinstance(weather_element, dict):
                        continue
                    element_name = coerce_text(
                        weather_element.get("ElementName")
                        or weather_element.get("elementName")
                    )
                    if element_name not in {"溫度", "Temperature"}:
                        continue

                    times = weather_element.get("Time") or weather_element.get("time")
                    if not isinstance(times, list):
                        times = [times] if isinstance(times, dict) else []

                    for time_item in times:
                        if not isinstance(time_item, dict):
                            continue
                        element_values = (
                            time_item.get("ElementValue")
                            or time_item.get("elementValue")
                        )
                        if not isinstance(element_values, list):
                            element_values = (
                                [element_values]
                                if isinstance(element_values, dict)
                                else []
                            )

                        for element_value in element_values:
                            if not isinstance(element_value, dict):
                                continue
                            temperature = coerce_float(
                                extract_first(element_value, ["Temperature", "value"])
                            )
                            if temperature is not None:
                                return temperature

        return None

    def _normalize_city_name(self, value: str | None) -> str | None:
        """Normalize Taiwan city names for dataset lookup."""
        if value is None:
            return None
        return value.replace("台", "臺")

    def _normalize_town_name(self, value: str | None) -> str | None:
        """Normalize township names for comparison."""
        if value is None:
            return None
        return value.replace("台", "臺")

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
            self._user_id = self._extract_user_id_from_token(access_token)
        if refresh_token:
            self._refresh_token = refresh_token

    def _capture_tokens_from_headers(self, headers: aiohttp.typedefs.LooseHeaders) -> None:
        """Extract bearer or token headers if the backend uses headers instead of JSON."""
        authorization = headers.get("Authorization") or headers.get("authorization")
        if isinstance(authorization, str) and authorization.startswith("Bearer "):
            self._access_token = authorization.removeprefix("Bearer ").strip() or None
            self._user_id = self._extract_user_id_from_token(self._access_token)

        for header_name in ("X-Access-Token", "x-access-token", "access_token", "token"):
            header_value = headers.get(header_name)
            if isinstance(header_value, str) and header_value.strip():
                self._access_token = header_value.strip()
                self._user_id = self._extract_user_id_from_token(self._access_token)
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
        params: dict[str, Any] | None = None,
        auth_required: bool = True,
        allow_retry: bool = True,
    ) -> Any:
        """Execute a JSON HTTP request."""
        if auth_required and not self._access_token:
            try:
                await self.async_ensure_access_token()
            except AirmonAuthenticationError:
                if not self._session_authenticated:
                    raise

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
                params=params,
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
            self._user_id = None
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
                params=params,
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

    def _extract_user_id_from_token(self, token: str | None) -> str | None:
        """Extract a likely user id from a JWT-like access token."""
        if token is None or token.count(".") < 2:
            return None

        payload_segment = token.split(".", 2)[1]
        padding = "=" * (-len(payload_segment) % 4)
        try:
            decoded = urlsafe_b64decode(f"{payload_segment}{padding}")
            payload = json.loads(decoded.decode("utf-8"))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None

        if not isinstance(payload, dict):
            return None

        return coerce_text(extract_first(payload, ("userId", "uid", "sub", "id")))

    def _build_url(self, path: str) -> str:
        """Build an absolute URL from a path."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(f"{self._api_base_url}/", path.lstrip("/"))

    def _has_session_cookies(self) -> bool:
        """Return True when the aiohttp session has cookies for the API host."""
        return bool(self._session.cookie_jar.filter_cookies(URL(self._api_base_url)))
