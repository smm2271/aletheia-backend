# 瀏覽器 Session

Google OAuth callback 成功後，Backend 會建立 Redis Session 並設定
`aletheia_session` cookie。瀏覽器只保存 256-bit 隨機 Session Identifier，
不包含 User ID、email、affiliation、Google token 或 JWT。

Redis key 為 `aletheia:session:<SHA-256(session_id)>`，資料為：

```json
{"user_id": "<Aletheia UUID>", "created_at": 0, "expires_at": 28800}
```

時間以 Unix seconds 記錄。每筆 Session 有 Redis TTL，預設固定有效八小時，
讀取不會延長期限。Redis key 過期、資料不存在 / 格式錯誤，或 metadata 已過期
時回傳 401 並清除 cookie。Redis 無法連線時回傳 503，不放行身份驗證。
Redis 服務重啟後，開發環境中的所有 Session 都會失效。

## 環境設定

`.env.example` 提供本機 HTTP 開發設定：

```env
SESSION_TTL_SECONDS=28800
SESSION_PUBLIC_ORIGIN=http://localhost:8000
SESSION_COOKIE_SECURE=false
```

Python 預設 `SESSION_COOKIE_SECURE=true`。Cookie 使用 HttpOnly、SameSite=Lax、
Path=/，不設定 Domain，因此僅傳回建立 cookie 的 host。HTTP 開發例外只允許
localhost / 127.0.0.1 / ::1；遠端服務需 HTTPS 與 Secure cookie。
使用 HTTPS 時將 `SESSION_PUBLIC_ORIGIN` 改為實際對外 origin，並將 Secure 設為 true。
`SESSION_PUBLIC_ORIGIN` 只包含 scheme、host、port，不包含 API path；未設定時
會使用 `GOOGLE_REDIRECT_URI` 的 origin。TTL 可設定為 1 至 2592000 秒。

更新 `.env` 後執行 `docker compose up --build -d --wait` 套用設定。

## API

| Endpoint | 行為 |
| --- | --- |
| `GET /auth/google/login` | 啟動 Google OAuth |
| `GET /auth/google/callback` | 驗證身份，建立新 Session；原 browser Session 在同一個 Redis 原子操作中撤銷 |
| `GET /auth/me` | 以 cookie 驗證 Session，回傳目前 DB 中的 User 基本資料 |
| `POST /auth/logout` | 驗證 Origin，立即撤銷 Redis Session 並清除 cookie，回傳 204 |

每次讀取目前使用者都會確認 PostgreSQL 中的 User 存在且未停用。
因此 DB 中的基本資料更新可立即反映，停用 / 刪除使用者後，Session 即拒絕使用。
API 不接受 query string 或 Authorization header 作為 Session Identifier。
Session 相關回應使用 `Cache-Control: no-store`。

登出必須提供與 `SESSION_PUBLIC_ORIGIN` 完全相同的 `Origin` header，缺少、null
或其他 origin 時回傳 403；GET 登出不支援。這可避免跨網站請求強制登出。
Session 不存在時，同來源登出仍回傳 204；Redis 故障時回傳 503，保留 cookie，
避免在尚未撤銷伺服器資料前宣告成功。

同來源網頁範例：

```javascript
const currentUser = await fetch('/auth/me', { credentials: 'same-origin' });
await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
```

命令列驗收：

```sh
curl -i http://localhost:8000/auth/me
curl -i -X POST -H 'Origin: http://localhost:8000' http://localhost:8000/auth/logout
```

實際瀏覽器登入需先完成 [Google OAuth 設定](google-oauth.md)。HttpOnly cookie
不能透過 JavaScript 讀取，請透過 `/auth/me` 查詢身份。

## 共用驗證與主動撤銷

其他 FastAPI 路由可使用 `auth.session.get_current_user`：

```python
from fastapi import Depends
from auth.session import get_current_user
from models import User

@router.get('/protected')
async def protected(user: User = Depends(get_current_user)):
    return {'user_id': str(user.id)}
```

Backend 內可呼叫 `await revoke_session(redis_client, session_id)` 主動撤銷指定
Session。此 helper 不需要 cookie 到期，不對外提供任意使用者 Session 撤銷 API。
同一使用者不同瀏覽器的 Session 獨立管理；重新登入只撤銷該瀏覽器先前的 Session。

## 測試

設定 `TEST_DATABASE_URL` 與 `TEST_REDIS_URL` 後執行 `python -m pytest -q`。
測試涵蓋 OAuth Session 整合、cookie 屬性、TTL / metadata 過期、Session 輪替、
登出 / 撤銷、CSRF Origin、無效 Session、停用 / 刪除 User 及 Redis 故障。
OAuth 上游使用測試 RSA token；Session 使用真正的 Redis 讀寫。

參考：[OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)。
