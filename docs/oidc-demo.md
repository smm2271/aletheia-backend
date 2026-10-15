# OIDC Discovery 與示範 Client

Backend 提供：

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /authorize`、`POST /token`

Discovery 以固定 `SSO_ISSUER` 建立 Endpoint URL，不使用來自 HTTP Host 的值。
部署在子路徑時，反向代理必須將該 prefix 下的請求映射至 Backend 路由；Issuer
字串仍精確比對。支援 Code Flow、Query response、PKCE S256、EdDSA，以及目前可用
的 Scopes。Client 實際可請求的 Scope 仍由 Client 註冊資料限制。

## 啟動示範 Client

先依 [金鑰文件](signing-keys.md) 啟用 Backend，再以管理員 Session 透過
`POST /api/v1/admin/clients` 註冊：

```json
{
  "name": "OIDC Demo",
  "client_type": "confidential",
  "trust_level": "first_party",
  "redirect_uris": ["http://127.0.0.1:8001/callback"],
  "allowed_scopes": ["openid"]
}
```

將回傳的 Client ID / Secret 設定於示範 Client 的環境；Secret 僅保存於伺服器端，
不要加入瀏覽器 URL 或 Git。Client 與 Backend 使用同一份 Python dependencies。

```text
DEMO_ISSUER=http://localhost:8000
DEMO_CLIENT_ID=<registered client ID>
DEMO_CLIENT_SECRET=<one-time returned secret>
DEMO_PUBLIC_ORIGIN=http://127.0.0.1:8001
DEMO_REDIS_URL=redis://localhost:6380/1
```

```sh
python -m uvicorn demo_client.app:app --host 127.0.0.1 --port 8001 --no-access-log
```

以瀏覽器開啟 `http://127.0.0.1:8001`，選擇 Login with Argus。若已在
`http://localhost:8000` 有效登入，First-party Client 直接完成授權，不再呼叫 Google。
否則由 Argus 的 Google OAuth 登入與既有 continuation 返回授權流程。
正式使用須另配真實 Google credentials 與 HTTPS；自動化測試使用受控 Google 回應。

Cookie 不以 Port 隔離，因此示範設定刻意使用不同 Hostname（Argus 為 localhost、
Client 為 127.0.0.1），Client 設定也會拒絕與 Issuer 共用 Hostname。正式環境使用
獨立網域、host-only cookie、HTTPS。Client 不讀取或轉送 Argus Session Cookie。

## Callback 與獨立 Session

登入入口產生獨立隨機 state、nonce、PKCE verifier 與 Browser Cookie。短期紀錄放在
Redis `argus-demo:flow:<SHA-256(cookie)>`，五分鐘過期；Callback 原子消耗紀錄，
驗證 state、瀏覽器綁定、過期與參數重複。拒絕 Callback 中的 User ID / Email / Role。

Client 透過後端 Basic Authentication 交換 Code，從可信固定 Issuer Discovery 取得
Endpoint，並限制為預期的同 Issuer 路徑，避免 Discovery 將 Secret 導向其他站點。
HTTP 呼叫有 timeout、不跟隨重新導向。Client 透過公開 JWKS 獨立驗證 Ed25519 ID
Token 的簽章、kid、Issuer、Client audience、用途、時效與原始 nonce。

成功後產生新的 HttpOnly / SameSite=Lax / host-only `argus_demo_session` Cookie，
Redis 僅保存 Subject 與固定一小時有效期，不保留 Access / ID Token。`GET /me`
展示登入結果；`POST /logout` 要求 Client Origin，撤銷 Client Session，不撤銷 Argus
Session。Redis 故障回傳 503，驗證失敗不建立 Session。兩個服務皆應停用 access log，
避免 Code / State 出現在 URL 日誌。

External Client 仍回傳 `consent_required` / 403；此版本沒有 Consent UI，不會視為
使用者已同意。沒有 UserInfo、Refresh Token、動態註冊或完整 OIDC 認證宣告。

測試 `tests/test_oidc_integration.py` 使用獨立 Client App、真實 PostgreSQL / Redis、
Ed25519 簽章與公開 JWKS 驗證。HTTP 在測試程序內路由至 Backend；Google 上游為
測試回應，並非真實 Google 瀏覽器授權。

`python tests/smoke_oidc.py` 另啟動兩個真實 Uvicorn HTTP 服務，驗證 Discovery、
JWKS、Code 交換、Client Callback／Session、資格 API 與登出隔離，已加入 CI。
它要求 `TEST_DATABASE_URL` 指向專用空白 PostgreSQL，以及專用 `TEST_REDIS_URL`；
會直接建立測試 Browser Session，不呼叫 Google。結束後清除測試資料庫 schema，
只適用於隔離測試環境。

參考：[OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)、
[OIDC Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)。
