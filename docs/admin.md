# 管理員權限

User 的 `is_admin` 預設為 false，與 student / teacher / alumni 的 affiliation 分離。
管理員使用相同 Google OAuth 與 Redis Browser Session，沒有另設密碼或登入流程。

先以 Google 登入，再由 `/auth/me` 取得 User UUID。在伺服器執行：

```sh
docker compose exec backend python -m admin.bootstrap --user-id <user-uuid>
docker compose exec backend python -m admin.bootstrap --user-id <user-uuid> --revoke
```

命令只能更新既有 User，不能建立帳號，也不以 email 連結身份。停用帳號不能被
提升為管理員。CLI 需要伺服器 / DB 存取權，管理 API 不提供自行提升權限的入口。

`GET /api/v1/admin/me` 驗證管理員身份；未登入回傳 401，一般使用者回傳 403，
管理員回傳目前的 User UUID。權限每次從 DB 讀取，因此撤銷後不需重新登入即生效。

其他管理 API 使用 `Depends(auth.admin.require_admin)` 共用驗證即可。
寫入 API 另需驗證同來源 Origin，不能將身份驗證視為 CSRF 防護。
