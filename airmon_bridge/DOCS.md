# AIRMON Bridge

這個 local add-on 提供一個很小的 HTTP bridge，目的是在 HAOS 上直接驗證 AIRMON iLIVING 的雲端登入與裝置 API。

它的定位是 integration 的輔助層，不是取代 Home Assistant entity 的主控制邏輯。

## 提供的路徑

- `GET /health`
- `POST /auth/test`
- `GET /devices`
- `POST /devices/<mac>/command`

## 用途

- 驗證帳號是否能登入
- 直接檢查 `/v1/devices` 的真實回應格式
- 在不改 Home Assistant integration 的情況下，先測試實驗性控制 payload
- 幫你在 HAOS 環境裡先確認 APK 逆向出的端點是否真的可用
- 預設已帶入 app 真實 `client_id` `cngP1ABZCe96KmyE` 與 `grant_type=password`
- 一般情況不需要填 `auth_provider`
- 只有當原廠後端改動時，才需要手動 override `auth_client_id` / `auth_client_secret` / `auth_grant_type` / `auth_provider`

## 注意

這個 bridge 目前是除錯工具，不是最終控制層。真正對 Home Assistant 呈現 entity 的仍然是 `custom_components/airmon_iliving`。
