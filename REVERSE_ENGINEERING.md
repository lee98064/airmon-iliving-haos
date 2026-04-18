# Reverse Engineering Notes

## APK layout

- Base APK unpacked in current directory
- Native Flutter AOT payload found in `../config.arm64_v8a.apk`
- AOT binary: `lib/arm64-v8a/libapp.so`
- Language/resource split also unpacked in `../config.zh.apk`

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

## Split APK follow-up

- `config.zh` only adds locale/resource files and mostly generic Android or Google sign-in strings.
- `config.zh` does not expose API credentials, MQTT settings, or device protocol payloads.
- `config.arm64_v8a/lib/arm64-v8a/libapp.so` confirms the auth/token flow strings are compiled into Flutter AOT:
  - `client_id`
  - `grant_type`
  - `access_token`
  - `refresh_token`
  - `/v1/users/auth`
  - `/v1/users/check`
  - `api/refresh_token`
  - `ApiService`
  - `set:clientIdentifier`
- Flutter AOT decompilation with `blutter` recovered the hard-coded app client ID from `ApiService._internal()`:
  - `client_id = "cngP1ABZCe96KmyE"`
- `ApiService.login()` builds auth payloads in this shape:
  - `{"email"|"phone": "...", "password": "...", "grant_type": "password", "client_id": "cngP1ABZCe96KmyE"}`
- `ApiService.refreshTokenIfNeeded()` refreshes by POSTing to `/v1/users/auth` again with:
  - `{"grant_type": "refresh_token", "refresh_token": "...", "client_id": "cngP1ABZCe96KmyE"}`
- Live curl verification against the production backend succeeded with the recovered client ID and returned `access_token` / `refresh_token`.
- A `performAuthorizationRequest` method exists in smali, but it belongs to the `com.aboutyou.dart_packages.sign_in_with_apple` plugin and does not explain the normal email/password login flow.
- Current conclusion: normal email/password login is fully explained by Flutter AOT, and the previous `Invalid client_id` error was caused by the missing app client ID.

## Android shell analysis

- `com.upyoung.airmon.MainActivity` is an empty `FlutterActivity` shell and does not add custom login logic on the Android side.
- The generated plugin list only shows standard third-party plugins such as:
  - `firebase_auth`
  - `firebase_core`
  - `firebase_messaging`
  - `sign_in_with_apple`
  - `flutter_secure_storage`
  - `google_maps_flutter`
  - `webview_flutter`
  - `flutter_background_geolocation`
- No app-specific Android plugin was found that injects a REST `clientId` or `clientSecret`.
- No explicit `networkSecurityConfig` or certificate pinning metadata was found in the manifest or resources.

## Dart AOT service-layer hints

- The Flutter AOT strings confirm the app contains an API request logger with pieces such as:
  - `[REQ][`
  - `[RES][`
  - `Path: `
  - ` - Data: `
  - ` - Headers: `
  - `] Body: `
- The login and token flow appears to live in Dart service classes such as:
  - `package:mitsubishi_app/service/api_service.dart`
  - `package:mitsubishi_app/common/services/config.dart`
  - `package:mitsubishi_app/service/secure_storage_service.dart`
  - `package:mitsubishi_app/common/services/user.dart`
  - `package:mitsubishi_app/common/api/user.dart`
- Token-related strings found in AOT:
  - `accessToken`
  - `refreshToken`
  - `getToken`
  - `getRefreshToken`
  - `saveRefreshToken`
  - `refreshTokenIfNeeded`
  - `no_time_refreshTokenIfNeeded`
  - `JWT-Checker`
  - `JWT_EXPIRED`
  - `Api_auth_token_invalid`
- Environment/config hints found in AOT:
  - `_productionApiProvider`
  - `baseUrl`
  - `user-agent`
  - `_RequestConfig`
- Current interpretation: the official app builds auth requests inside Dart code with a shared `ApiService` object, and that object hard-codes the production `client_id`.

## Home Assistant mapping strategy used in this scaffold

### Integration

- Domain: `airmon_iliving`
- Platforms:
  - `climate`
  - `sensor`
  - `switch`
- Auth:
  - POST `/v1/users/auth`
  - payload shape now matched to the real Flutter app:
    - `email` or `phone`
    - `password`
    - `grant_type=password`
    - `client_id=cngP1ABZCe96KmyE`
- Refresh:
  - primary: POST `/v1/users/auth` with `grant_type=refresh_token`
  - fallback: POST `api/refresh_token`
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

1. Real device list response sample
2. Real device detail response sample
3. A capture of:
   - power on
   - power off
   - mode change
   - set temperature
   - fan speed change
   - home leave mode
   - silent mode
4. MQTT connect details:
   - port
   - auth type
   - TLS requirement
   - topic naming for commands vs status
