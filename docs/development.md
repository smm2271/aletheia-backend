# Docker 開發環境

需要 Docker Engine / Docker Desktop（Linux containers）與 Docker Compose v2 以上。
Backend 使用 Python 3.12，資料庫使用 PostgreSQL 18，短期狀態服務使用 Redis 8。

## 啟動

在 repository 根目錄複製環境設定，並修改本機密碼：

```powershell
Copy-Item .env.example .env
```

macOS / Linux 可使用 `cp .env.example .env`。`.env` 不會提交至 Git，
也不會進入 Docker build context。

```sh
docker compose up --build -d --wait
docker compose ps
```

Compose 先等待 PostgreSQL 與 Redis 健康檢查成功，Backend 再執行 `alembic upgrade head`，
成功後才啟動 Uvicorn。Migration 失敗會中止 Backend 啟動。
API 位於 http://localhost:8000，Swagger UI 位於 http://localhost:8000/docs。
`/health` 檢查 API；`/health/db` 實際查詢 PostgreSQL，無法連線時回傳 503。
`/health/redis` 實際 PING Redis，無法連線時回傳 503。Backend 啟動時也會
確認 Redis 可用，關閉時釋放 Redis 連線池。

```sh
curl http://localhost:8000/health/db
curl http://localhost:8000/health/redis
docker compose exec backend python -m redis_connection
docker compose exec backend python -m alembic current
docker compose exec backend python -m alembic check
docker compose logs backend db redis
```

修改程式後執行 `docker compose up --build -d --wait` 重新建置並啟動。
映像以非 root 使用者執行 Backend。本設定供開發用途，不包含 production 部署。

## 環境變數與連線

Compose 自動讀取 `.env` 的 `POSTGRES_USER`、`POSTGRES_PASSWORD`、`POSTGRES_DB`。
Backend 與 Alembic 共用 `database.get_database_url()`：有非空白 `DATABASE_URL`
時優先使用；否則以 PostgreSQL 環境變數建立 URL，會自動處理密碼中的 URL 特殊字元。
未提供必要設定時直接報錯，不使用寫死的帳號或密碼。

| 設定 | 用途 |
| --- | --- |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | 新資料庫初始化與 Backend 連線設定 |
| `POSTGRES_HOST_PORT` | 本機資料庫 port，預設 5433，避免和既有 5432 衝突 |
| `BACKEND_PORT` | 本機 API port，預設 8000 |
| `DATABASE_URL` | 選用完整連線 URL 覆寫；密碼特殊字元須 URL encode |
| `REDIS_URL` | Redis 連線 URL，Compose 內為 `redis://redis:6379/0` |
| `REDIS_HOST_PORT` | 本機 Redis port，預設 6380，僅綁定 localhost |

Container 內連線使用 `db:5432`；本機工具使用 `localhost:5433`。
Compose 固定傳入 `POSTGRES_HOST=db`、`POSTGRES_PORT=5432`。
API 與 DB 的 host port 僅綁定 `127.0.0.1`。
Redis 的 host port 同樣僅綁定 `127.0.0.1`；本機工具使用
`redis://localhost:6380/0`。程式從 `REDIS_URL` 讀取 host、port、database，
沒有寫死的 Redis 連線設定；缺少 URL 時 Backend 無法啟動。

若在 Docker 外執行 Python / Alembic，需自行匯出 `DATABASE_URL` 或 PostgreSQL
環境變數；程式不會自動讀取 `.env`。例如 PowerShell：

```powershell
$env:DATABASE_URL = 'postgresql+psycopg://aletheia:local-development-only@localhost:5433/aletheia'
python -m alembic current
```

若在 Docker 外啟動 Backend，還需匯出 Redis 設定：

```powershell
$env:REDIS_URL = 'redis://localhost:6380/0'
python -m redis_connection
```

## Redis 短期狀態

Redis 停用 RDB snapshot 與 AOF，`/data` 使用 tmpfs。重啟 Redis container
就會清除記憶體中的資料。使用者身份等持久化資料由 PostgreSQL 保存。
後續寫入 Browser Session、Nonce 等短期資料時必須指定 TTL。
Browser Session 已使用 Redis，詳見 [browser-session.md](browser-session.md)。
SSO 邏輯會由後續功能接入。

`python -m redis_connection` 會 PING，再以隨機測試 key 寫入 60 秒 TTL 的值，
讀回並驗證 TTL，最後刪除測試 key；失敗時回傳非零 exit code。
健康檢查只執行 PING，不會持續寫入測試資料。連線與讀寫 timeout 為 3 秒，
不自動重試，故障可由健康檢查及呼叫端處理。

## 停止與資料保留

```sh
docker compose down
```

資料存放於 named volume `postgres_data`，停止與重新建立 container 都會保留。
PostgreSQL 18 的 volume 掛載位置為 `/var/lib/postgresql`。
既有 volume 初始化後，修改 `.env` 不會自動更改資料庫帳號、密碼或名稱；
請透過 SQL 修改既有資料庫，或在不需要資料時重建。

以下命令會刪除開發資料庫的所有資料，只在需要完全重建時使用：

```sh
docker compose down -v
```

## 驗證

GitHub Actions 會使用 `.env.example` 建置映像、啟動 Compose、檢查 API / DB
健康狀態、執行 Alembic check，並確認 DB container 重建後資料仍存在。
同時驗證 Redis 讀寫與 TTL、Redis 停止時的 503，以及重新啟動後恢復健康。
獨立的 PostgreSQL 身份模型測試請參閱 [identity-model.md](identity-model.md)。
Google 登入與可修改的校園身份規則請參閱 [google-oauth.md](google-oauth.md)。
管理權限、Client 註冊、授權流程與 Token 交換請參閱 [admin.md](admin.md)、
[sso-clients.md](sso-clients.md) 與 [authorization.md](authorization.md)。
Argus Token Endpoint 遵循 OAuth 2.0 與 PKCE S256 規範，在尚未配置實體 Token Issuer
前（#15 完成前）會於合法換碼時回傳 503，測試環境可使用 MockTokenIssuer 驗證。

本機整合測試先安裝 `requirements-dev.txt`，設定 `TEST_DATABASE_URL` 為專用
空白 PostgreSQL 資料庫、`TEST_REDIS_URL` 為專用 Redis database，再執行
`python -m pytest -q`。測試只建立與清除自己的 Redis key，不執行 FLUSHDB。

參考：[Compose 啟動順序](https://docs.docker.com/compose/how-tos/startup-order/)、
[PostgreSQL 官方映像](https://hub.docker.com/_/postgres)。
