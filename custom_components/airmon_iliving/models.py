"""Data models and payload parsing helpers for AIRMON iLIVING."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

MAC_CANDIDATES = (
    "mac",
    "mac_address",
    "macAddress",
    "deviceMac",
    "device_mac",
)
ID_CANDIDATES = ("id", "deviceId", "device_id")
NAME_CANDIDATES = ("name", "deviceName", "device_name", "nickname", "title")
MODEL_CANDIDATES = ("model", "deviceModel", "deviceType", "modelTypeName", "type")
ONLINE_CANDIDATES = ("online", "isOnline", "connected", "isConnected", "deviceOnline")
POWER_CANDIDATES = ("power", "powerOn", "isOn", "switch", "status")
MODE_CANDIDATES = ("mode", "acMode", "modeType", "ac_mode", "airConditionerMode")
FAN_CANDIDATES = ("fan", "fanSpeed", "fan_mode", "windSpeed")
SWING_CANDIDATES = ("swing", "swingMode", "verticalSwing", "swing_ud")
HORIZONTAL_SWING_CANDIDATES = (
    "horizontalSwing",
    "lrSwing",
    "swing_lr",
    "swingHorizontal",
)
CURRENT_TEMP_CANDIDATES = (
    "currentTemperature",
    "current_temperature",
    "temperature",
    "indoorTemperature",
    "indoor_temperature",
    "roomTemperature",
)
TARGET_TEMP_CANDIDATES = (
    "targetTemperature",
    "target_temperature",
    "setTemperature",
    "set_temperature",
    "coolingTemperature",
)
OUTDOOR_TEMP_CANDIDATES = (
    "outdoorTemperature",
    "outdoor_temperature",
    "outdoorTemp",
    "outsideTemperature",
)
FIRMWARE_CANDIDATES = ("firmwareVersion", "firmware", "version", "fwVer")
POWER_USAGE_CANDIDATES = ("powerUsage", "power_usage", "consumption", "deviceConsum")
FAMILY_ID_CANDIDATES = ("familyId", "family_id")
HOME_LEAVE_CANDIDATES = ("homeLeaveMode", "leave_home", "leaveHome", "home_leave_mode")
SILENT_MODE_CANDIDATES = ("silentMode", "silent_mode")


def deep_merge(base: Any, update: Any) -> Any:
    """Recursively merge update into base."""
    if isinstance(base, dict) and isinstance(update, dict):
        merged = dict(base)
        for key, value in update.items():
            if key in merged:
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    return update


def normalize_key(value: str) -> str:
    """Normalize a dict key for tolerant matching."""
    return "".join(char for char in value.lower() if char.isalnum())


def extract_first(payload: Any, candidates: tuple[str, ...] | list[str]) -> Any:
    """Return the first matching value found in a nested payload."""
    normalized = {normalize_key(candidate) for candidate in candidates}
    queue: deque[Any] = deque([payload])
    seen: set[int] = set()

    while queue:
        current = queue.popleft()
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


def coerce_bool(value: Any) -> bool | None:
    """Try to coerce a value into a boolean."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "on", "online", "connected", "open"}:
            return True
        if lowered in {"0", "false", "off", "offline", "disconnected", "close", "closed"}:
            return False
    return None


def coerce_float(value: Any) -> float | None:
    """Try to coerce a value into a float."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def coerce_text(value: Any) -> str | None:
    """Try to coerce a value into text."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def looks_like_device(mapping: dict[str, Any]) -> bool:
    """Best-effort detection of device objects inside arbitrary JSON."""
    mac = extract_first(mapping, MAC_CANDIDATES)
    name = extract_first(mapping, NAME_CANDIDATES)
    mode = extract_first(mapping, MODE_CANDIDATES)
    temp = extract_first(mapping, CURRENT_TEMP_CANDIDATES)
    return mac is not None or (name is not None and (mode is not None or temp is not None))


def extract_device_payloads(payload: Any) -> list[dict[str, Any]]:
    """Extract all likely device dictionaries from an API payload."""
    queue: deque[Any] = deque([payload])
    seen: set[int] = set()
    results: list[dict[str, Any]] = []

    while queue:
        current = queue.popleft()
        identifier = id(current)
        if identifier in seen:
            continue
        seen.add(identifier)

        if isinstance(current, dict):
            if looks_like_device(current):
                results.append(current)
            queue.extend(current.values())
            continue

        if isinstance(current, list):
            queue.extend(current)

    return results


@dataclass(slots=True)
class AirmonDevice:
    """Normalized AIRMON device model."""

    unique_id: str
    mac: str
    name: str
    device_id: str | None
    family_id: str | None
    model: str | None
    online: bool | None
    power: bool | None
    hvac_mode: str | None
    fan_mode: str | None
    swing_mode: str | None
    horizontal_swing_mode: str | None
    current_temperature: float | None
    target_temperature: float | None
    outdoor_temperature: float | None
    firmware_version: str | None
    power_usage: float | None
    home_leave_mode: bool | None
    silent_mode: bool | None
    raw: dict[str, Any]

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "AirmonDevice | None":
        """Build a normalized device from an arbitrary API payload."""
        mac = coerce_text(extract_first(payload, MAC_CANDIDATES))
        device_id = coerce_text(extract_first(payload, ID_CANDIDATES))
        name = coerce_text(extract_first(payload, NAME_CANDIDATES))

        unique_id = mac or device_id
        if unique_id is None:
            return None

        return cls(
            unique_id=unique_id,
            mac=mac or unique_id,
            name=name or f"AIRMON {unique_id}",
            device_id=device_id,
            family_id=coerce_text(extract_first(payload, FAMILY_ID_CANDIDATES)),
            model=coerce_text(extract_first(payload, MODEL_CANDIDATES)),
            online=coerce_bool(extract_first(payload, ONLINE_CANDIDATES)),
            power=coerce_bool(extract_first(payload, POWER_CANDIDATES)),
            hvac_mode=coerce_text(extract_first(payload, MODE_CANDIDATES)),
            fan_mode=coerce_text(extract_first(payload, FAN_CANDIDATES)),
            swing_mode=coerce_text(extract_first(payload, SWING_CANDIDATES)),
            horizontal_swing_mode=coerce_text(
                extract_first(payload, HORIZONTAL_SWING_CANDIDATES)
            ),
            current_temperature=coerce_float(extract_first(payload, CURRENT_TEMP_CANDIDATES)),
            target_temperature=coerce_float(extract_first(payload, TARGET_TEMP_CANDIDATES)),
            outdoor_temperature=coerce_float(extract_first(payload, OUTDOOR_TEMP_CANDIDATES)),
            firmware_version=coerce_text(extract_first(payload, FIRMWARE_CANDIDATES)),
            power_usage=coerce_float(extract_first(payload, POWER_USAGE_CANDIDATES)),
            home_leave_mode=coerce_bool(extract_first(payload, HOME_LEAVE_CANDIDATES)),
            silent_mode=coerce_bool(extract_first(payload, SILENT_MODE_CANDIDATES)),
            raw=payload,
        )
