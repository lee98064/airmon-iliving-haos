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
POWER_CANDIDATES = ("power", "powerOn", "isOn", "switch")
MODE_CANDIDATES = (
    "operationMode",
    "mode",
    "acMode",
    "modeType",
    "ac_mode",
    "airConditionerMode",
)
FAN_CANDIDATES = ("fan", "fanSpeed", "fan_mode", "windSpeed")
SWING_CANDIDATES = ("swing", "swingMode", "verticalSwing", "swing_ud")
HORIZONTAL_SWING_CANDIDATES = (
    "leftRightSwing",
    "louverLeftRightFixedPosition",
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
    "setPoint",
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
ENERGY_SAVING_CANDIDATES = ("energySaving",)
LEFT_RIGHT_SWING_CANDIDATES = ("leftRightSwing",)
LOUVER_LEFT_RIGHT_FIXED_POSITION_CANDIDATES = ("louverLeftRightFixedPosition",)
LOUVER_POSITION_CANDIDATES = ("louverPosition",)
LOUVER_SWINGING_CANDIDATES = ("louverSwinging",)
MODE_3D_AUTO_CANDIDATES = ("mode3DAuto",)
OPERATION_CANDIDATES = ("operation",)
OPERATION_MODE_CANDIDATES = ("operationMode",)
POWERFUL_MODE_CANDIDATES = ("powerfulMode",)
SET_POINT_CANDIDATES = ("setPoint",)
UPDATED_TIME_CANDIDATES = ("updatedTime",)
AC_ERROR_CODE_CANDIDATES = ("acErrorCode",)
FILTER_EXPIRED_CANDIDATES = ("filterExpired",)
INDOOR_UNIT_VERSION_CANDIDATES = ("iuVer", "indoorUnitVersion", "indoor_unit_version")

MODE_STATE_ON = {"ON", "OPERATION", "ENERGY SAVING", "POWERFUL MODE"}
MODE_STATE_OFF = {"OFF", "STOP", "NORMAL"}


def normalize_mode_value(value: str | None) -> str | None:
    """Normalize an AIRMON mode/status value for comparisons."""
    if value is None:
        return None
    normalized = value.strip().upper()
    return normalized or None


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


def coerce_status_text(value: Any) -> str | None:
    """Try to coerce a mode-like payload into text."""
    if isinstance(value, dict):
        nested = extract_first(value, ("mode", "status", "state", "value"))
        if nested is not None and nested is not value:
            return coerce_text(nested)
    return coerce_text(value)


def coerce_status_flag(
    value: Any,
    *,
    on_values: set[str] | None = None,
    off_values: set[str] | None = None,
) -> bool | None:
    """Try to coerce a mode/status payload into a boolean."""
    if value is None:
        return None

    if isinstance(value, dict):
        nested = extract_first(value, ("mode", "status", "state", "value"))
        if nested is not None and nested is not value:
            value = nested

    boolean = coerce_bool(value)
    if boolean is not None:
        return boolean

    normalized = normalize_mode_value(coerce_text(value))
    if normalized is None:
        return None

    if on_values and normalized in on_values:
        return True
    if off_values and normalized in off_values:
        return False
    return None


def resolve_vertical_airflow(
    swing_state: str | None,
    louver_position: str | None,
    legacy_value: Any,
) -> str | None:
    """Resolve the effective vertical airflow mode."""
    if normalize_mode_value(swing_state) == "ON":
        return "AUTO"

    if louver_position:
        return normalize_mode_value(louver_position) or louver_position

    legacy_text = coerce_status_text(legacy_value)
    if legacy_text:
        normalized = normalize_mode_value(legacy_text)
        return "AUTO" if normalized == "ON" else normalized
    return None


def resolve_horizontal_airflow(
    swing_state: str | None,
    fixed_position: str | None,
    legacy_value: Any,
) -> str | None:
    """Resolve the effective horizontal airflow mode."""
    if normalize_mode_value(swing_state) == "ON":
        return "AUTO"

    if fixed_position:
        return normalize_mode_value(fixed_position) or fixed_position

    legacy_text = coerce_status_text(legacy_value)
    if legacy_text:
        normalized = normalize_mode_value(legacy_text)
        return "AUTO" if normalized == "ON" else normalized
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
    energy_saving: str | None
    left_right_swing: str | None
    louver_left_right_fixed_position: str | None
    louver_position: str | None
    louver_swinging: str | None
    mode_3d_auto: str | None
    operation: str | None
    operation_mode: str | None
    powerful_mode: str | None
    set_point: float | None
    updated_time: str | None
    ac_error_code: str | None
    filter_expired: bool | None
    indoor_unit_version: str | None
    raw: dict[str, Any]

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "AirmonDevice | None":
        """Build a normalized device from an arbitrary API payload."""
        mac = coerce_text(extract_first(payload, MAC_CANDIDATES))
        device_id = coerce_text(extract_first(payload, ID_CANDIDATES))
        name = coerce_text(extract_first(payload, NAME_CANDIDATES))
        operation_mode = coerce_status_text(
            extract_first(payload, OPERATION_MODE_CANDIDATES)
        )
        legacy_mode = coerce_status_text(extract_first(payload, MODE_CANDIDATES))
        louver_swinging = coerce_status_text(
            extract_first(payload, LOUVER_SWINGING_CANDIDATES)
        )
        louver_position = coerce_status_text(
            extract_first(payload, LOUVER_POSITION_CANDIDATES)
        )
        left_right_swing = coerce_status_text(
            extract_first(payload, LEFT_RIGHT_SWING_CANDIDATES)
        )
        louver_left_right_fixed_position = coerce_status_text(
            extract_first(payload, LOUVER_LEFT_RIGHT_FIXED_POSITION_CANDIDATES)
        )
        target_temperature = coerce_float(extract_first(payload, TARGET_TEMP_CANDIDATES))
        set_point = coerce_float(extract_first(payload, SET_POINT_CANDIDATES))
        home_leave_value = extract_first(payload, HOME_LEAVE_CANDIDATES)
        silent_mode_value = extract_first(payload, SILENT_MODE_CANDIDATES)

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
            hvac_mode=operation_mode or legacy_mode,
            fan_mode=normalize_mode_value(
                coerce_status_text(extract_first(payload, FAN_CANDIDATES))
            ),
            swing_mode=resolve_vertical_airflow(
                louver_swinging,
                louver_position,
                extract_first(payload, SWING_CANDIDATES),
            ),
            horizontal_swing_mode=resolve_horizontal_airflow(
                left_right_swing,
                louver_left_right_fixed_position,
                extract_first(payload, HORIZONTAL_SWING_CANDIDATES),
            ),
            current_temperature=coerce_float(extract_first(payload, CURRENT_TEMP_CANDIDATES)),
            target_temperature=target_temperature,
            outdoor_temperature=coerce_float(extract_first(payload, OUTDOOR_TEMP_CANDIDATES)),
            firmware_version=coerce_text(extract_first(payload, FIRMWARE_CANDIDATES)),
            power_usage=coerce_float(extract_first(payload, POWER_USAGE_CANDIDATES)),
            home_leave_mode=coerce_status_flag(
                home_leave_value,
                on_values={"ON", "ENABLE", "ENABLED"},
                off_values=MODE_STATE_OFF,
            ),
            silent_mode=coerce_status_flag(
                silent_mode_value,
                on_values={"ON", "SILENT"},
                off_values=MODE_STATE_OFF,
            ),
            energy_saving=coerce_status_text(
                extract_first(payload, ENERGY_SAVING_CANDIDATES)
            ),
            left_right_swing=left_right_swing,
            louver_left_right_fixed_position=louver_left_right_fixed_position,
            louver_position=louver_position,
            louver_swinging=louver_swinging,
            mode_3d_auto=coerce_status_text(
                extract_first(payload, MODE_3D_AUTO_CANDIDATES)
            ),
            operation=coerce_status_text(extract_first(payload, OPERATION_CANDIDATES)),
            operation_mode=operation_mode,
            powerful_mode=coerce_status_text(
                extract_first(payload, POWERFUL_MODE_CANDIDATES)
            ),
            set_point=set_point or target_temperature,
            updated_time=coerce_text(extract_first(payload, UPDATED_TIME_CANDIDATES)),
            ac_error_code=coerce_text(extract_first(payload, AC_ERROR_CODE_CANDIDATES)),
            filter_expired=coerce_bool(extract_first(payload, FILTER_EXPIRED_CANDIDATES)),
            indoor_unit_version=coerce_text(
                extract_first(payload, INDOOR_UNIT_VERSION_CANDIDATES)
            ),
            raw=payload,
        )

    @property
    def energy_saving_enabled(self) -> bool | None:
        """Return whether energy saving is enabled."""
        return coerce_status_flag(
            self.energy_saving,
            on_values={"ENERGY SAVING"},
            off_values=MODE_STATE_OFF,
        )

    @property
    def powerful_mode_enabled(self) -> bool | None:
        """Return whether powerful mode is enabled."""
        return coerce_status_flag(
            self.powerful_mode,
            on_values={"POWERFUL MODE"},
            off_values=MODE_STATE_OFF,
        )

    @property
    def mode_3d_auto_enabled(self) -> bool | None:
        """Return whether 3D auto is enabled."""
        return coerce_status_flag(
            self.mode_3d_auto,
            on_values={"ON"},
            off_values=MODE_STATE_OFF,
        )

    @property
    def left_right_swing_enabled(self) -> bool | None:
        """Return whether horizontal auto swing is enabled."""
        return coerce_status_flag(
            self.left_right_swing,
            on_values={"ON"},
            off_values=MODE_STATE_OFF,
        )

    @property
    def louver_swinging_enabled(self) -> bool | None:
        """Return whether vertical auto swing is enabled."""
        return coerce_status_flag(
            self.louver_swinging,
            on_values={"ON"},
            off_values=MODE_STATE_OFF,
        )
