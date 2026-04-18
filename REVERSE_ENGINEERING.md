# Reverse Engineering Notes

## APK layout

- Base APK unpacked in current directory
- Native Flutter AOT payload found in `../config.arm64_v8a.apk`
- AOT binary: `lib/arm64-v8a/libapp.so`

## App identity

- Android package: `com.upyoung.airmon`
- App label: `AIRMON iLIVING`
- Flutter source path strings indicate project namespace `package:mitsubishi_app/...`

## Confirmed backend endpoints from `libapp.so`

### REST

- `https://api.wificontrolbox.com`
- `/v1/users/auth`
- `/v1/users/check`
- `/v1/users/register`
- `/v1/users/auth`
- `/v1/users/avatar`
- `/v1/users/verify-phone`
- `/v1/users/resend-verification`
- `/v1/users/resend-phone-verification`
- `/v1/users/forgot-password`
- `api/refresh_token`
- `/v1/devices`
- `/v1/devices/mac/`
- `/v1/devices/power-usage`
- `/v1/devices/firmware`
- `/v1/families`
- `/v1/families/share`
- `/v1/families/share/`
- `/v1/families/confirm-action/`
- `/v1/families/reject-action/`
- `/v1/messages`
- `/v1/messages/has-unread-message`
- `/v1/schedules`
- `/v1/fcm-tokens`
- `/geofence`
- `/geofence-notification`

### MQTT

- Broker host: `appbroker.wificontrolbox.com`
- Topic pattern string: `devices/([a-fA-F0-9]+)/#`
- Related method strings:
  - `publishJsonMessage`
  - `connectToMqttServer`
  - `queryDeviceStatus`
  - `createDeviceStatusPacket`
  - `startDeviceOperation`
  - `handleJsonMessage`

## Feature surface inferred from translations and AOT strings

- AC on/off
- Cool / Heat / Dry / Fan / Auto
- Set temperature
- Fan speed
- Swing up/down and left/right
- Weekly / one-shot schedules
- Power usage history
- Firmware query / update hints
- BLE pairing and Wi-Fi provisioning
- Geofence / Home Leave mode
- Multi-split grouping

## Home Assistant mapping strategy used in this scaffold

### Integration

- Domain: `airmon_iliving`
- Platforms:
  - `climate`
  - `sensor`
  - `switch`
- Auth:
  - POST `/v1/users/auth`
  - fallback payload variants based on field names seen in AOT strings
- Refresh:
  - POST `api/refresh_token`
- Polling:
  - GET `/v1/devices`
  - optional GET `/v1/devices/power-usage`
- Push:
  - optional MQTT subscribe flow to `devices/+/#` and `devices/<mac>/#`
  - broker default set to `appbroker.wificontrolbox.com`
  - if no MQTT password is configured, integration will try API access token as a fallback password

### Control

Current implementation treats control as experimental because the APK strongly suggests that live control may rely on MQTT packets rather than a single documented REST write endpoint.

Implemented fallback attempts:

- `PATCH /v1/devices/mac/{mac}`
- `PUT /v1/devices/mac/{mac}`
- `PATCH /v1/devices`
- `PUT /v1/devices`

Exposed in Home Assistant services:

- `airmon_iliving.refresh`
- `airmon_iliving.send_command`
- `airmon_iliving.raw_api_request`

## What is still needed for a production-ready integration

1. Real login response sample
2. Real device list response sample
3. Real device detail response sample
4. A capture of:
   - power on
   - power off
   - mode change
   - set temperature
   - fan speed change
   - home leave mode
   - silent mode
5. MQTT connect details:
   - port
   - auth type
   - TLS requirement
   - topic naming for commands vs status
