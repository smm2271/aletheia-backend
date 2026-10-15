# SSO JWT 與 OIDC ID Token

`sso/jwt.py` 提供 `JWTIssuer`（實作 `/token` 的 `TokenIssuer` 介面）與
`JWTValidator`。Browser Session 繼續使用 HttpOnly Cookie + Redis；JWT 到期
不會撤銷 Browser Session。此階段不提供 Refresh Token、Revocation 或 UserInfo。

## 設定與金鑰介面

| 設定 | 用途 |
| --- | --- |
| `SSO_ISSUER` | 固定 Issuer Identifier，精確比對，含路徑或尾斜線亦不正規化 |
| `SSO_ACCESS_AUDIENCE` | 目前唯一受支援的 Resource Server 識別碼，例如 `argus-api` |
| `SSO_ACCESS_TOKEN_TTL_SECONDS` | Access Token TTL，預設 300 秒 |
| `SSO_ID_TOKEN_TTL_SECONDS` | ID Token TTL，預設 300 秒 |

Issuer 必須使用 HTTPS；僅 loopback 開發環境允許 HTTP。兩種 TTL 均限制為
1～3600 秒。Audience 不從授權請求或 Token Header 推導；Client ID 僅作為 ID
Token 的 audience。目前不支援 Client 自選 Resource，也不會向其他 API 簽發 Token。

金鑰管理是 [issue #16](https://github.com/smm2271/aletheia-backend/issues/16)
的工作；#15 內文的 #12 是舊編號。此變更定義以下介面，沒有產生、載入或保存
正式私鑰，也沒有實作 JWKS Endpoint：

```python
class SSOKeyProvider:
    def signing_key(self, purpose: str) -> tuple[str, Ed25519PrivateKey]: ...
    def verification_key(self, purpose: str, kid: str) -> Ed25519PublicKey | None: ...
```

Provider 必須根據 `purpose="sso"` 隔離金鑰，僅讓 Active key 簽章，讓 Active /
Verify Only key 驗證；未知、Retired 或 QR key 回傳 `None`。舊公鑰至少保留到
舊 Token 全部到期。每次簽發／驗證均重新查詢 Provider，以支援輪替。

部署組裝層在 FastAPI lifespan 啟動前注入 Provider：

```python
from main import app

app.state.sso_key_provider = provider  # 由金鑰管理模組建立
```

啟動時會依環境設定建立 `app.state.token_issuer`。已有 Provider 但設定錯誤時
啟動失敗；尚未注入 Provider 時其他服務可啟動，`/token` 保持回傳 OAuth
`temporarily_unavailable` / HTTP 503。既有 Code 仍會被消耗，Client 需重新授權。
因此，單純設定環境變數尚不能在預設 Compose 部署中啟用簽發；須先接上 #16。
也可直接以 `JWTIssuer(settings, provider)` 與 `JWTValidator(settings, provider)`
組裝服務。僅負責驗證的 Client／Resource Server 不需要實作 `signing_key`。

## Token 格式與用途

兩類 Token 一律以 Ed25519 / `EdDSA` 簽署，Header 包含 `alg`、`typ`、`kid`。

| 欄位 | Access Token | ID Token |
| --- | --- | --- |
| `typ`（Header） | `at+jwt` | `JWT` |
| `token_use`（Claim） | `access_token` | `id_token` |
| `iss` | `SSO_ISSUER` | `SSO_ISSUER` |
| `sub` | Argus User UUID | Argus User UUID |
| `aud` | 設定的 Resource Server | 取得授權的 Client ID |
| `iat` / `exp` | 整數 Unix 秒，明確短效 TTL | 整數 Unix 秒，明確短效 TTL |
| `scope` | 授權 Scope，以空格分隔 | 不輸出 |
| `client_id` / `jti` | Client ID / 隨機唯一 Token ID | 不輸出 |
| `nonce` | 不輸出 | 原始授權請求有提供時原樣帶入 |

只有授權 Scope 包含 `openid` 才簽發 ID Token。預設不輸出 Email、姓名、學號、
班級或 Google Token；即使 Scope 為 `profile` 也不會自動揭露個資。其他屬性
須日後另訂 Scope 與揭露政策。`jti` 目前不提供撤銷功能。

## 驗證端

```python
validator = JWTValidator(settings, trusted_public_key_provider)

# Resource Server 使用自己的固定 audience，不接受呼叫者指定。
claims = validator.validate_access_token(
    bearer_token, audience="argus-api", required_scopes=("student:read",),
)

# OIDC Client 使用本身 Client ID 及授權時保存的 nonce。
identity = validator.validate_id_token(
    id_token, client_id="registered-client-id", nonce=saved_nonce,
)
```

驗證失敗拋出 `JWTValidationError`，錯誤不含 Token。驗證端固定使用 `EdDSA`
與 Ed25519 公鑰，檢查精確 Issuer、單一 Audience、簽章、必要 Claims、整數時效、
UUID Subject、TTL 上限與 Token Type；Access Token 另檢查 Scope、Client ID 與 jti。
拒絕未來 `iat` 與過期 Token，無額外時間寬限，部署主機應同步時鐘。
`kid` 僅查詢可信 Provider，不跟隨 Token Header 的 URL 或內嵌公鑰。
不支援 critical JOSE extensions 或 detached payload。

ID Token 僅供 Client 確認登入，不能作為 API Bearer Token。即使兩者 Audience
字串相同，驗證服務仍以 `typ` 與 `token_use` 阻止混用。Client 必須傳入原始 nonce
才能檢查請求綁定；原請求未使用 nonce 時可省略。API 仍須根據 Scope 與本身政策
決定授權，JWT 驗證本身不會查詢帳號停用或 Session 撤銷狀態，Token 在 TTL 內有效。

## 驗證方式與參考

`python -m pytest tests/test_jwt.py -q` 不需外部服務，使用即時產生的測試金鑰，
涵蓋簽發、公鑰驗證、時效、必要 Claims、用途／Scope／Nonce 隔離、不安全演算法、
錯誤簽章與金鑰輪替。`tests/test_token.py` 另使用隔離 PostgreSQL／Redis，測試啟動
注入 Provider 後的真實 JWT Code 交換、Nonce 與 Cookie 不變，以及 Code 不可重播。

格式與驗證參考 [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)、
[JWT Access Token Profile](https://www.rfc-editor.org/rfc/rfc9068.html) 與
[PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html)。此處未宣告完整 OIDC Provider
相容性，Discovery、公開 JWKS 與其他 OIDC 功能另行實作。
