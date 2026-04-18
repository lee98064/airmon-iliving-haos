"""Constants for the AIRMON iLIVING integration."""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "airmon_iliving"

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SENSOR, Platform.SWITCH]

DEFAULT_NAME = "AIRMON iLIVING"
DEFAULT_API_BASE_URL = "https://api.wificontrolbox.com"
DEFAULT_AUTH_CLIENT_ID = "cngP1ABZCe96KmyE"
DEFAULT_AUTH_GRANT_TYPE = "password"
DEFAULT_AUTH_REFRESH_GRANT_TYPE = "refresh_token"
DEFAULT_MQTT_HOST = "appbroker.wificontrolbox.com"
DEFAULT_MQTT_PORT = 1883
DEFAULT_POLL_INTERVAL = 60
DEFAULT_TIMEOUT = 30

CONF_API_BASE_URL = "api_base_url"
CONF_AUTH_CLIENT_ID = "auth_client_id"
CONF_AUTH_CLIENT_SECRET = "auth_client_secret"
CONF_AUTH_GRANT_TYPE = "auth_grant_type"
CONF_AUTH_PROVIDER = "auth_provider"
CONF_ENABLE_EXPERIMENTAL_CONTROL = "enable_experimental_control"
CONF_ENABLE_PUSH = "enable_push"
CONF_MQTT_HOST = "mqtt_host"
CONF_MQTT_PASSWORD = "mqtt_password"
CONF_MQTT_PORT = "mqtt_port"
CONF_MQTT_TLS = "mqtt_tls"
CONF_MQTT_USERNAME = "mqtt_username"
CONF_POLL_INTERVAL = "poll_interval"

ATTR_DEVICE_MAC = "device_mac"
ATTR_FAMILY_ID = "family_id"
ATTR_HOME_LEAVE_MODE = "home_leave_mode"
ATTR_RAW_PAYLOAD = "raw_payload"
ATTR_SILENT_MODE = "silent_mode"

SERVICE_RAW_API_REQUEST = "raw_api_request"
SERVICE_REFRESH = "refresh"
SERVICE_SEND_COMMAND = "send_command"

MANUFACTURER = "UpYoung"

DISCOVERED_ENDPOINTS = {
    "users_auth": "/v1/users/auth",
    "users_check": "/v1/users/check",
    "refresh_token": "api/refresh_token",
    "devices": "/v1/devices",
    "device_by_mac": "/v1/devices/mac/{mac}",
    "devices_power_usage": "/v1/devices/power-usage",
    "devices_firmware": "/v1/devices/firmware",
    "schedules": "/v1/schedules",
    "messages": "/v1/messages",
}
