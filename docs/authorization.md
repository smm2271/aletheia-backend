# SSO Authorization Endpoint

`GET /authorize` 支援 response_type=code，client_id、redirect_uri、scope 必填，
state / nonce 可選。要求先驗證已註冊且啟用的 Client、Redirect URI 完全相符，以及
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

Public Client 必須提供 PKCE S256 的 code_challenge / code_challenge_method；
Confidential 可選用，但一旦提供就會綁定。plain 或格式錯誤的 challenge 會被拒絕。

`sso.authorization.consume_code` 為後續 Token Endpoint 提供內部交換 primitive：
Client / URI / PKCE 符合後才原子刪除並取得資料，重播與併發交換僅一次成功。
呼叫端必須先驗證 Client 身份並重新確認啟用狀態；目前不對外提供 Token Endpoint、
JWT、Refresh Token、JWKS 或 UserInfo。

回應設定 no-store / no-referrer；存取紀錄不得包含 code、state、Cookie 或 Secret。
實際 Google 登入需先設定 Google Client，測試使用簽署的測試 token 與真正 Redis。

參考：[OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html)、
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)。
