# SSO Client 管理

所有 `/api/v1/admin/clients` API 都需既有 Browser Session 與 is_admin。
寫入請求另需 `Origin` 與 `SESSION_PUBLIC_ORIGIN` 精確相符。

| Endpoint | 用途 |
| --- | --- |
| POST /api/v1/admin/clients | 建立 Client，Confidential secret 只在此回應顯示一次 |
| GET /api/v1/admin/clients | 分頁列表，offset 預設 0、limit 預設 50，最多 100 |
| GET /api/v1/admin/clients/{client_id} | 查詢基本資料，不包含 secret 或 hash |
| PATCH /api/v1/admin/clients/{client_id} | 更新 name、trust_level、enabled、redirect_uris、allowed_scopes |
| POST /api/v1/admin/clients/{client_id}/rotate-secret | 重新產生 secret，舊 secret 立即失效，新值只回傳一次 |
| DELETE /api/v1/admin/clients/{client_id} | 刪除 Client |

建立範例：

```json
{
  "name": "Campus",
  "client_type": "confidential",
  "trust_level": "first_party",
  "redirect_uris": ["https://campus.example/callback"],
  "allowed_scopes": ["openid", "profile"]
}
```

client_id 由系統產生。client_type 在建立後不可修改，需要不同類型時重新建立。
public / confidential 與 first_party / external 可任意組合；Trust 必須由管理員
明確設定，不依網域推定。Public 不產生 secret，Confidential 使用 256-bit 隨機
secret 與隨機 salt 的 scrypt hash，DB 不保存原文，管理 API 不能取回原 secret。

Redirect URI 原始字串完整保存，授權時採精確匹配，不做 prefix / wildcard 比對。
只接受 HTTPS 與 loopback HTTP，拒絕 credentials、fragment、wildcard，以及預先
插入 code / state / error 等回應參數。Allowed scope 需為 OAuth scope token，
要求的 scope 必須全部存在於 Client allowlist。

`sso.clients.validate_client_request` 提供啟用狀態、URI 與 scope 共用驗證；
`verify_client_secret` 提供 confidential secret 的 hash 比對，停用 Client 無法通過。
此 PR 尚未提供 Token Endpoint 或 Consent UI。
