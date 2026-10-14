# Docker 開發環境

需要 Docker Engine / Docker Desktop（Linux containers）與 Docker Compose v2 以上。
Backend 使用 Python 3.12，資料庫使用 PostgreSQL 18。

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

Compose 先等待資料庫健康檢查成功，Backend 再執行 `alembic upgrade head`，
成功後才啟動 Uvicorn。Migration 失敗會中止 Backend 啟動。
API 位於 http://localhost:8000，Swagger UI 位於 http://localhost:8000/docs。
`/health` 檢查 API；`/health/db` 實際查詢 PostgreSQL，無法連線時回傳 503。

```sh
curl http://localhost:8000/health/db
docker compose exec backend python -m alembic current
docker compose exec backend python -m alembic check
docker compose logs backend db
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

Container 內連線使用 `db:5432`；本機工具使用 `localhost:5433`。
Compose 固定傳入 `POSTGRES_HOST=db`、`POSTGRES_PORT=5432`。
API 與 DB 的 host port 僅綁定 `127.0.0.1`。

若在 Docker 外執行 Python / Alembic，需自行匯出 `DATABASE_URL` 或 PostgreSQL
環境變數；程式不會自動讀取 `.env`。例如 PowerShell：

```powershell
$env:DATABASE_URL = 'postgresql+psycopg://aletheia:local-development-only@localhost:5433/aletheia'
python -m alembic current
```

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
獨立的 PostgreSQL 身份模型測試請參閱 [identity-model.md](identity-model.md)。

參考：[Compose 啟動順序](https://docs.docker.com/compose/how-tos/startup-order/)、
[PostgreSQL 官方映像](https://hub.docker.com/_/postgres)。
