# Google OAuth 登入

## 設定與操作

在 Google Cloud Console 建立 OAuth 2.0 **Web application** client，設定同意畫面；
若 App 處於 Testing，將測試帳號加入允許名單。Authorized redirect URI 必須與
`GOOGLE_REDIRECT_URI` 完全相同，包括 scheme、host、port、path。

在本機 `.env` 設定：

```env
GOOGLE_CLIENT_ID=<your-web-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
GOOGLE_HOSTED_DOMAIN=
```

執行 `docker compose up --build -d --wait` 後，在瀏覽器開啟
http://localhost:8000/auth/google/login。完成 Google 授權後，callback 回傳
內部 User 的 `id`、email、username、avatar_url 與 affiliation。
這次回傳只代表當次身份驗證成功，不建立持續登入狀態，也不發行 Argus JWT。
Google 的 access / ID token 不會存入 DB 或回傳給瀏覽器。

OAuth 設定未提供時，登入入口回傳 503，其他 API 仍可使用。
非 localhost 的 redirect URI 必須使用 HTTPS，握手 cookie 也會設為 Secure。
Docker 啟動命令停用 Uvicorn access log，避免 callback query 中的 code / state
出現在 log。自行啟動請使用 `uvicorn main:app --no-access-log`；若有反向代理，
callback 的 query string 也應從代理存取紀錄排除。

## 可修改的校園身份規則

修改 [`auth/affiliation.py`](../auth/affiliation.py) 中的 `determine_affiliation()`
即可調整首次登入身份；函式只接收已驗證的 Google claims。
修改後重新建置 / 啟動 Backend，讓新規則生效：

```sh
docker compose up --build -d --wait
```

本版規則以 email 的 `@` 前方完整比對：

| 條件 / 範例 | 首次登入 affiliation |
| --- | --- |
| 小寫 `s` 或 `j` 接恰好七碼 ASCII 數字，例如 `s1234567`、`j7654321` | student |
| 其他，例如 `teacher`、`s123456`、`s12345678` | teacher |

既有使用者保留 DB 中的 affiliation，不在每次登入覆寫。
後續可修改函式以查詢名冊、增加 alumni 規則，或回傳 `None` 拒絕建立帳號。
此規則是部署者設定的身份分類，不是 Google 提供的校園身份認證。

`GOOGLE_HOSTED_DOMAIN` 非空時，只允許 ID token 中經簽章驗證的 `hd` 完全相符；
不能以 email 尾碼或 authorization request 的 `hd` 提示取代驗證。
留空時不限制 Workspace 網域。

## 驗證與身份映射

- 透過 Google 官方 `google-auth` library 驗證 ID token 的簽章、issuer、audience、
  時效；另驗證 nonce、email_verified、sub、email、azp 與選用的 Workspace 網域。
- 使用一次性隨機 state、瀏覽器綁定 cookie、nonce 與 PKCE S256。
- PostgreSQL 的 `oauth_attempts` 僅保存有效十分鐘的握手資料；callback 原子刪除
  state，拒絕跨瀏覽器、失效及重播請求；下一次登入會清除過期資料。
- 瀏覽器暫存 cookie 為 HttpOnly / SameSite=Lax，callback 結束時清除；這不是
  Browser Login Session。重新啟動與多個 worker 共用 PostgreSQL 的一次性狀態。
- 身份僅以 `(provider='google', subject=Google sub)` 查找；新 User 與身份同交易建立。
  重複 / 併發登入不重複建立，既有身份的 email / 顯示資料可以更新。
- email 若與其他使用者衝突，回傳 409，要求另外處理帳號連結，不自動合併。
  停用帳號回傳 403；Google 拒絕授權回傳 400；token 驗證失敗回傳 401；
  上游連線失敗回傳 502。驗證失敗不建立身份資料，錯誤不包含 token 或 secret。

本版不包含 Argus OAuth / OIDC Server、Browser Session、Redis 或 SSO 功能。

## 測試

先執行 `python -m pip install -r requirements-dev.txt`，沿用 `TEST_DATABASE_URL`
專用空白 PostgreSQL 資料庫，執行 `python -m pytest -q`。
OAuth 測試使用測試 RSA 金鑰簽署 ID token，保留真正的 google-auth 驗證，只替換
Google token / certificate HTTP 回應，涵蓋正常登入與失效 token 等情境。
不需要真實 Google client secret。真實 Google 瀏覽器授權須由部署者提供 client
設定後依上述步驟驗證。

參考：[Google OpenID Connect server flow](https://developers.google.com/identity/openid-connect/openid-connect)、
[Google ID token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)。
