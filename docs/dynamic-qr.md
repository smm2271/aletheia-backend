# W10 動態 QR

實作順序：#44 Token schema / issuer → #45 Redis 狀態機 → #47 API → #46 整合驗收。

## Token 與輪替

動態 JWT 的 header `typ` 與 claim `typ` 均為 `aletheia.qr.dynamic`。固定 claims：
`v=1`、`typ`、`iss=SSO_ISSUER`、`sub`（內部 UUID）、
`aud=argus-qr-dynamic-verifier`、`jti`（256-bit 隨機值）、`iat`、`nbf=iat`、`exp=iat+30`。
只允許 Ed25519／EdDSA，沿用 key provider 的 `qr` purpose，與 `sso` purpose 隔離。
不包含姓名、Email、學號。JWT 為簽章而非加密；持有者可以讀取 `sub`，不得將 token 寫入 log。

前端每 25 秒重新呼叫 issue，直接將 `token` 編碼成 QR。每次取得獨立 jti，
舊 token 不延長、不自動撤銷，最多有 5 秒並存。`expires_at` 為 UTC 的權威期限。
30 秒與 25 秒均為固定契約，不受靜態 `QR_TOKEN_TTL_SECONDS` 影響。

## API

所有回應 `Cache-Control: no-store`，成功回應另含 `Pragma: no-cache`。
不接受 query parameters。所有 request model 拒絕額外欄位，422 不回顯 token。
OpenAPI `/docs` 包含 schema、認證、Origin 與錯誤碼。

| POST endpoint | 認證與 body | 成功回應 |
| --- | --- | --- |
| `/api/v1/qr/dynamic/issue` | 有效 Browser Session、精確 Origin；省略 body 或 `{}` | `{token, token_type, expires_at, refresh_after:25}` |
| `/api/v1/qr/dynamic/verify` | SSO Access Token，`SSO_ACCESS_AUDIENCE`（預設 `argus-api`）、`qr:dynamic:verify`；`{token}` | `{valid:true}`，QR 失敗為 HTTP 200 `{valid:false}` |
| `/api/v1/qr/dynamic/revoke` | 有效 Browser Session、精確 Origin；`{token}` | `{revoked:true}`，已終止或不存在為 `{revoked:false}` |

scanner 的使用者與 client 必須仍啟用，scope 同時須存在於 Access Token 與 client 目前授權。
管理員可透過既有 client API 授予 `qr:dynamic:verify`；Discovery 已宣告此 scope。
認證失敗為 401，scope 不足／Origin 錯誤／非本人撤銷為 403。
revoke 驗證完整簽章與 `sub`，不能用任意 jti 撤銷；過期或無效 token 為 400。
金鑰、資料庫或 Redis 故障為 503，從不退回僅驗簽模式。

## Redis 一次性狀態

key：`qr:dyn:state:{sha256(jti)}`。Hash 僅存 `state`、`exp`、`typ`、`v`，
不存原始 token、jti、sub 或其他身份資料。註冊以 Lua 原子確認不存在、尚未到期，
建立 ISSUED 並設定絕對 EXPIREAT。只有確認註冊成功才將簽好的 token 回傳。

consume / revoke 各使用單次 Lua：比對 state、exp、type、version，使用 Redis TIME
確認未過期，再將 ISSUED 轉成 CONSUMED 或 REVOKED。終止狀態不能恢復成 ISSUED。
終止紀錄保留至 exp，正常到期由 Redis 刪除，缺失紀錄一律拒絕；如果存續的
ISSUED key 已到期，腳本會標成 EXPIRED 並拒絕。失去 Redis 狀態會使相關 token 失效。
跨 client 共用同一消耗狀態，每個 token 全域最多一次成功。

逾時可能發生於寫入已提交但回覆遺失之後，API 回 503；呼叫方不能據此認定尚未使用。
驗證不重試，也不回傳成功；可重新簽發新 token 後重新進行業務流程。
此處不提供業務交易、永久稽核、付款冪等性或跨 Redis 區域一致性。

靜態 verifier 與動態 verifier 嚴格區分用途、schema 與 audience，無法互用。
動態 QR 不提供離線驗證、不判定學生資格或入場權限；有效期間內的轉傳仍可能搶先消耗。

測試、覆蓋率及限制見 [W10 驗收報告](week10-qr-report.md)。
