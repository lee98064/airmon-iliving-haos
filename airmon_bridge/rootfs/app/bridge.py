"""Small local bridge for AIRMON iLIVING."""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("airmon_bridge")

OPTIONS_FILE = Path("/data/options.json")
DEFAULT_AUTH_CLIENT_ID = "cngP1ABZCe96KmyE"
DEFAULT_AUTH_GRANT_TYPE = "password"
DEFAULT_AUTH_REFRESH_GRANT_TYPE = "refresh_token"


def normalize_key(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def extract_first(payload: Any, candidates: list[str] | tuple[str, ...]) -> Any:
    normalized = {normalize_key(candidate) for candidate in candidates}
    queue = [payload]
    seen: set[int] = set()

    while queue:
        current = queue.pop(0)
        identifier = id(current)
        if identifier in seen:
            continue
        seen.add(identifier)

        if isinstance(current, dict):
            for key, value in current.items():
                if normalize_key(str(key)) in normalized and value not in (None, "", [], {}):
                    return value
            queue.extend(current.values())
            continue

        if isinstance(current, list):
            queue.extend(current)

    return None


def coerce_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def load_options() -> dict[str, Any]:
    if not OPTIONS_FILE.exists():
        return {}
    return json.loads(OPTIONS_FILE.read_text())


class BridgeClient:
    """Simple synchronous AIRMON client for the add-on."""

    def __init__(self, options: dict[str, Any]) -> None:
        self.username = options.get("username", "")
        self.password = options.get("password", "")
        self.api_base_url = options.get("api_base_url", "https://api.wificontrolbox.com").rstrip("/")
        self.auth_client_id = options.get("auth_client_id") or DEFAULT_AUTH_CLIENT_ID
        self.auth_client_secret = options.get("auth_client_secret") or None
        self.auth_grant_type = options.get("auth_grant_type") or DEFAULT_AUTH_GRANT_TYPE
        self.auth_provider = options.get("auth_provider") or None
        self.experimental_control = bool(options.get("experimental_control", False))
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.session_authenticated = False

    def authenticate(self) -> dict[str, Any]:
        if not self.username or not self.password:
            raise RuntimeError("Username and password must be configured in add-on options")

        payloads: list[dict[str, Any]] = []
        login_field = self._preferred_login_field(self.username)

        for shared in (
            self._auth_payload_shared_fields(),
            self._auth_payload_shared_fields(camel_case=True),
        ):
            for field in dict.fromkeys((login_field, "email", "phone")):
                payload = {**shared, field: self.username, "password": self.password}
                if payload not in payloads:
                    payloads.append(payload)

        last_error: Exception | None = None
        for payload in payloads:
            try:
                response = self.request("POST", "/v1/users/auth", payload, auth_required=False)
            except Exception as err:  # noqa: BLE001
                last_error = err
                continue

            self._capture_tokens(response)
            if self.access_token or self.session_authenticated:
                return response

        raise RuntimeError(f"Authentication failed: {last_error or 'unknown error'}")

    def list_devices(self) -> Any:
        return self.request("GET", "/v1/devices")

    def send_command(self, mac: str, payload: dict[str, Any]) -> Any:
        if not self.experimental_control:
            raise RuntimeError("experimental_control is disabled")

        attempts = [
            ("PATCH", f"/v1/devices/mac/{mac}", payload),
            ("PUT", f"/v1/devices/mac/{mac}", payload),
            ("PATCH", "/v1/devices", {"mac": mac, **payload}),
            ("PUT", "/v1/devices", {"mac": mac, **payload}),
        ]

        last_error: Exception | None = None
        for method, path, body in attempts:
            try:
                return self.request(method, path, body)
            except Exception as err:  # noqa: BLE001
                last_error = err
                LOGGER.info("Command attempt failed %s %s: %s", method, path, err)
        raise RuntimeError(f"Command failed: {last_error or 'unknown error'}")

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        auth_required: bool = True,
        allow_retry: bool = True,
    ) -> Any:
        if auth_required and not (self.access_token or self.session_authenticated):
            self.authenticate()

        url = urljoin(f"{self.api_base_url}/", path.lstrip("/"))
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth_required and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        request = Request(url=url, data=body, headers=headers, method=method)

        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
                payload = json.loads(raw) if raw else {}
                self._capture_tokens_from_headers(response.headers)
                cookies = response.headers.get_all("Set-Cookie", [])
                if cookies:
                    self.session_authenticated = True
                return payload
        except HTTPError as err:
            raw = err.read().decode("utf-8")
            try:
                error_payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                error_payload = {"raw": raw}
            if err.code == 401 and auth_required and allow_retry:
                self.access_token = None
                self.session_authenticated = False
                if self.refresh_token:
                    try:
                        self.refresh_access_token()
                    except Exception:  # noqa: BLE001
                        self.authenticate()
                else:
                    self.authenticate()
                return self.request(
                    method,
                    path,
                    payload=payload,
                    auth_required=auth_required,
                    allow_retry=False,
                )
            raise RuntimeError(
                f"{err.code}: {extract_first(error_payload, ['message', 'error']) or raw}"
            )
        except URLError as err:
            raise RuntimeError(str(err)) from err

    def refresh_access_token(self) -> None:
        if not self.refresh_token:
            raise RuntimeError("No refresh token available")

        attempts = [
            (
                "/v1/users/auth",
                {
                    **self._auth_payload_shared_fields(
                        grant_type=DEFAULT_AUTH_REFRESH_GRANT_TYPE
                    ),
                    "refresh_token": self.refresh_token,
                },
            ),
            (
                "/v1/users/auth",
                {
                    **self._auth_payload_shared_fields(
                        camel_case=True,
                        grant_type=DEFAULT_AUTH_REFRESH_GRANT_TYPE,
                    ),
                    "refreshToken": self.refresh_token,
                },
            ),
            ("api/refresh_token", {"refresh_token": self.refresh_token}),
            ("api/refresh_token", {"refreshToken": self.refresh_token}),
            ("api/refresh_token", {"token": self.refresh_token}),
        ]

        for path, payload in attempts:
            try:
                response = self.request(
                    "POST",
                    path,
                    payload=payload,
                    auth_required=False,
                    allow_retry=False,
                )
            except Exception:  # noqa: BLE001
                continue

            self._capture_tokens(response)
            if self.access_token or self.session_authenticated:
                return

        raise RuntimeError("Unable to refresh access token")

    def _capture_tokens(self, payload: Any) -> None:
        access = coerce_text(extract_first(payload, ["access_token", "accessToken", "token", "jwt"]))
        refresh = coerce_text(extract_first(payload, ["refresh_token", "refreshToken"]))
        if access:
            self.access_token = access
            self.session_authenticated = True
        if refresh:
            self.refresh_token = refresh

    def _capture_tokens_from_headers(self, headers: Any) -> None:
        authorization = headers.get("Authorization") or headers.get("authorization")
        if isinstance(authorization, str) and authorization.startswith("Bearer "):
            self.access_token = authorization.removeprefix("Bearer ").strip() or None

        for header_name in ("X-Access-Token", "x-access-token", "access_token", "token"):
            header_value = headers.get(header_name)
            if isinstance(header_value, str) and header_value.strip():
                self.access_token = header_value.strip()
                break

        for header_name in (
            "X-Refresh-Token",
            "x-refresh-token",
            "refresh_token",
            "refreshToken",
        ):
            header_value = headers.get(header_name)
            if isinstance(header_value, str) and header_value.strip():
                self.refresh_token = header_value.strip()
                break

        if self.access_token:
            self.session_authenticated = True

    def _preferred_login_field(self, username: str) -> str:
        return "email" if "@" in username else "phone"

    def _auth_payload_shared_fields(
        self,
        *,
        camel_case: bool = False,
        grant_type: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        client_id_key = "clientId" if camel_case else "client_id"
        client_secret_key = "clientSecret" if camel_case else "client_secret"
        grant_type_key = "grantType" if camel_case else "grant_type"
        if self.auth_client_id:
            payload[client_id_key] = self.auth_client_id
        if self.auth_client_secret:
            payload[client_secret_key] = self.auth_client_secret
        if grant_type or self.auth_grant_type:
            payload[grant_type_key] = grant_type or self.auth_grant_type
        if self.auth_provider:
            payload["provider"] = self.auth_provider
        return payload


class BridgeHandler(BaseHTTPRequestHandler):
    """HTTP handler for the bridge service."""

    client = BridgeClient(load_options())

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._write_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "api_base_url": self.client.api_base_url,
                    "experimental_control": self.client.experimental_control,
                    "configured": bool(self.client.username and self.client.password),
                },
            )
            return

        if self.path == "/devices":
            try:
                devices = self.client.list_devices()
            except Exception as err:  # noqa: BLE001
                self._write_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
                return
            self._write_json(HTTPStatus.OK, devices)
            return

        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/auth/test":
            try:
                response = self.client.authenticate()
            except Exception as err:  # noqa: BLE001
                self._write_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
                return
            self._write_json(
                HTTPStatus.OK,
                {
                    "status": "authenticated",
                    "token_keys_found": {
                        "access_token": bool(self.client.access_token),
                        "refresh_token": bool(self.client.refresh_token),
                    },
                    "response_sample": response,
                },
            )
            return

        if self.path.startswith("/devices/") and self.path.endswith("/command"):
            mac = self.path.removeprefix("/devices/").removesuffix("/command")
            payload = self._read_json()
            try:
                response = self.client.send_command(mac, payload)
            except Exception as err:  # noqa: BLE001
                self._write_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
                return
            self._write_json(HTTPStatus.OK, response)
            return

        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), format % args)

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw)

    def _write_json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8099), BridgeHandler)
    LOGGER.info("AIRMON bridge listening on 0.0.0.0:8099")
    server.serve_forever()


if __name__ == "__main__":
    main()
