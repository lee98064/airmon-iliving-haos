# AIRMON iLIVING for HAOS

這份目錄已經整理成一個可直接帶進 Home Assistant OS 的完整雛形，不是單純分析筆記。

它包含兩個實際可用的部分：

1. `custom_components/airmon_iliving`
   Home Assistant 自訂整合。負責登入 AIRMON iLIVING 雲端、同步裝置、建立 entity、提供服務呼叫，並支援可選的 MQTT 推送同步。
2. `airmon_bridge`
   Home Assistant local add-on。提供一個本地 HTTP bridge，方便在 HAOS 裡直接驗證登入、讀取 `/v1/devices` 真實回應、測試實驗性控制 payload。

另外也補了：

- `hacs.json`
  可作為 HACS 自訂儲存庫的 metadata。
- `repository.yaml`
  可作為 Home Assistant add-on repository 的 metadata。

## 這版已確認的 APK 情報

- Android package: `com.upyoung.airmon`
- Flutter app package path: `package:mitsubishi_app/...`
- Cloud API base URL: `https://api.wificontrolbox.com`
- MQTT broker host: `appbroker.wificontrolbox.com`
- 已發現 REST 路徑：
  - `/v1/users/auth`
  - `api/refresh_token`
  - `/v1/devices`
  - `/v1/devices/mac/{mac}`
  - `/v1/devices/power-usage`
  - `/v1/devices/firmware`
  - `/v1/schedules`
  - `/v1/messages`
- 已發現 MQTT 相關字串：
  - `devices/([a-fA-F0-9]+)/#`
  - `publishJsonMessage`
  - `createDeviceStatusPacket`
  - `queryDeviceStatus`
  - `startDeviceOperation`

## 已實作內容

- Config Flow 與 Options Flow
- Cloud login 與 token refresh
- Device polling
- Climate entity
- Outdoor temperature / power usage / firmware / connection sensors
- Home Leave Mode / Silent Mode switches
- 實驗性 REST control fallback
- MQTT push client
- `refresh` / `send_command` / `raw_api_request` 三個 Home Assistant service
- HAOS local add-on bridge

## 安裝方式

### 方式 1: 當成自訂整合

把 `custom_components/airmon_iliving` 複製到 Home Assistant 的 `/config/custom_components/`。

重啟 Home Assistant 後，到「設定 > 裝置與服務」新增 `AIRMON iLIVING`。

若你是用 HACS 管理，自訂儲存庫指向這個 repo 即可，HACS metadata 已經補好。

如果你要把這份目錄發布成遠端 add-on repository，記得把 `repository.yaml` 裡的 `url` 改成你自己的 Git 倉庫網址。

### 方式 2: 當成 local add-on

把 `airmon_bridge` 複製到 HAOS 的 `/addons/local/`。

重載 Add-on Store 後會看到 `AIRMON Bridge`，可以用來驗證：

- `POST /auth/test`
- `GET /devices`
- `POST /devices/<mac>/command`

## MQTT 推送設定

整合裡已加入可選的 MQTT 參數：

- `enable_push`
- `mqtt_host`
- `mqtt_port`
- `mqtt_username`
- `mqtt_password`
- `mqtt_tls`

另外 auth 設定已補上：

- `auth_client_id`
- `auth_client_secret`
- `auth_grant_type`
- `auth_provider`

目前 integration 已內建從 Flutter `libapp.so` 挖出的正式 app `client_id`:
`cngP1ABZCe96KmyE`

預設登入 payload 已改成 app 實際使用的格式：
`{"email"|"phone": "...", "password": "...", "grant_type": "password", "client_id": "cngP1ABZCe96KmyE"}`

通常不需要再手動填 `auth_provider`，保留它只是作為後端行為變動時的覆寫入口。

預設 broker 會帶入 APK 內找到的 `appbroker.wificontrolbox.com`。如果你沒有填 MQTT 密碼，整合會先嘗試以 API access token 當作 MQTT 密碼。

這個邏輯是依照 APK 字串與常見雲端 IoT 做法補上的 best-effort 實作，但因為目前沒有真實 broker 連線樣本，仍然可能需要你之後用實帳修正 port、認證方式或 topic 細節。

## 目前已確認的登入限制

直接對真實後端測試後，`/v1/users/auth` 目前已可確認不是單純 `email + password` 就能登入。

後端在 `grantType=password` 流程下會要求有效的 `clientId`。也就是說，如果沒有 app 內建的 OAuth client 參數，就會被後端拒絕，而且這不是帳號密碼錯。

我已經把整合與 bridge 都補成可手動輸入這些 auth 參數的版本，避免再把這類錯誤誤判成「帳密錯誤」。

## 目前限制

- 控制端點仍屬實驗性推斷，尚未有真實封包驗證
- MQTT 連線參數與 topic ACL 也仍是逆向推測
- 若 broker 只允許特定 topic、特定 token 型式或自訂 TLS，仍需再依實機封包調整

## 什麼時候用 integration，什麼時候用 add-on

如果你的目標是把裝置整進 HAOS，核心是 `custom_components/airmon_iliving`。

`airmon_bridge` 主要是輔助除錯與封包驗證，不是主 entity 層。它存在的價值是讓你在 HAOS 本機環境裡直接驗證 API 與控制 payload，而不用先改 integration 本體。
