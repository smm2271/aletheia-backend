# SSO Authorization Endpoint

`GET /authorize` 支援 response_type=code，client_id、redirect_uri、scope 必填，
state / nonce 可選；nonce 若提供，長度須為 1 至 512 個字元，空值會在發碼前回傳 400。
要求先驗證已註冊且啟用的 Client、Redirect URI 完全相符，以及
所有 Scope 均在 allowlist 內；未知 / 停用 Client、URI / Scope 不符及不支援的
response_type 都在 Argus 本地回傳 400，不導向未信任的 URI。

```text
/authorize?response_type=code&client_id=<id>&redirect_uri=<exact-uri>&scope=openid%20profile&state=<opaque-state>
```

已登入的 first_party 使用既有 Browser Session，不需再登入 Google，直接回到
已註冊 URI，附上 code 與原樣的 state。原 URI 的非保留 query 參數也會保留。
Session cookie 不共享 Domain，也不傳給 Client。

未登入時，原始請求以十分鐘 TTL 存入 Redis，瀏覽器只保存 opaque HttpOnly
continuation cookie。Google OAuth state 綁定該 cookie 的 hash，callback 建立
Session 後導向 `/authorize/resume`，原子消耗 context，再重新驗證目前的 Client
狀態、URI、Scope 及 Trust Policy。登入中 Client 被停用或設定改變時不發碼。
獨立 Google 登入不會自動接回未綁定的 continuation。

external Client 採獨立 Consent Policy：目前回傳 403、policy=consent_required，
不發 Authorization Code；完整 Consent UI 與核准動作由後續功能提供。
first_party 身份只由管理員設定，不由 URI 網域判斷。

## Authorization Code

Code 是 256-bit 隨機 opaque 值，不包含使用者身份。Redis 使用 SHA-256 key，
資料綁定 user_id、client_id、redirect_uri、scope、nonce、expires_at 與選用 PKCE。
預設 TTL 為 120 秒，可透過 AUTHORIZATION_CODE_TTL_SECONDS 設定 1 至 600 秒。

Public 與 Confidential Client 均必須提供 PKCE S256 的 code_challenge 與
code_challenge_method=S256；plain 或格式錯誤的 challenge 會被拒絕。

`sso.authorization.consume_code` 提供內部原子交換 primitive：
Client / URI / PKCE 符合後才原子刪除並取得授權資料，重播與併發交換僅一次成功。

## Token Endpoint

`POST /token` 支援以短效、一次性的 Authorization Code 交換 Token，Content-Type 必須為
`application/x-www-form-urlencoded`。

```text
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=authorization_code&code=<authorization-code>&redirect_uri=<exact-uri>&code_verifier=<pkce-verifier>
```

### 驗證規則

1. **Grant Type**：僅支援 `authorization_code`；其他值回傳 `400 unsupported_grant_type`。
2. **參數防護**：重複參數、不合法編碼或超長 Request Body 回傳 `400 invalid_request`。
3. **Client 驗證**：
   - 支援 HTTP Basic Auth 標頭與 Form Body（`client_id` 與 `client_secret`）。
   - 同時使用 Basic 與 Form 憑證傳遞一律拒絕（`400 invalid_request`）。
   - Confidential Client 必須通過 scrypt 雜湊比對；認證失敗回傳 `401 invalid_client`
     （若使用 Basic 則附帶 `WWW-Authenticate: Basic realm="Argus"`）。
   - Public Client 僅需傳遞 `client_id`，不要求 `client_secret`。
4. **PKCE S256 驗證**：所有 Client 換碼時均必須提供 `code_verifier`，驗證失敗回傳 `400 invalid_grant`。
5. **原子消耗與故障語義**：
   - 透過 Redis Lua 腳本原子核對 Client ID、Redirect URI 與 PKCE S256，全部相符才刪除 Code。
   - 驗證不相符時不刪除鍵值，避免惡意試探銷毀合法 Code。
   - Code 一旦被成功刪除消耗，若後續步驟（如 User 停用、Token 簽發服務異常）失敗，絕不復原 Code。
6. **Token 簽發責任分離**：
   - Argus 定義 `TokenIssuer` 介面，實際 JWT / ID Token 簽發留交 #15。
   - 正式環境未配置有效 Issuer 時回傳 `503 temporarily_unavailable`，不簽發偽造 Token。
   - 成功回應回傳 `access_token`、`token_type=Bearer`、`expires_in`、以及 `openid` scope 存在時之 `id_token`。

回應設定 `Cache-Control: no-store`、`Pragma: no-cache`、`Referrer-Policy: no-referrer`；
日誌與錯誤訊息不得包含 Code、Verifier、Token 或 Client Secret。

參考：[OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html)、
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)。
