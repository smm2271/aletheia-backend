# 使用者與外部身份

`User.id` 是 Aletheia 內部永久 UUID。`ExternalIdentity` 透過 `user_id`
與 User 建立雙向一對多關聯，以 `(provider, subject)` 唯一識別外部登入身份。
Google 身份使用 `provider = 'google'`、`subject = Google sub`；新增其他
OIDC Provider 時，provider 必須能區分其 issuer。Email 的 UNIQUE 僅為業務限制，
不可用於判定外部身份或自動連結帳號。校園身份欄位統一使用 `affiliation`。

設定 `DATABASE_URL` 後執行 `python -m alembic upgrade head`。第二版遷移會將
既有 `users.google_sub` 搬至 `external_identities`，保留原有 User UUID。
回復舊版要求每個使用者恰有一個 Google 身份，且沒有其他 Provider；不符合時
遷移會拒絕回復，避免遺失身份資料。`updated_at` 的自動更新由 SQLAlchemy
處理，直接 SQL 更新時需自行設定。

PostgreSQL 整合測試：安裝 `requirements-dev.txt` 並將 `TEST_DATABASE_URL` 指向專用
空白測試資料庫，再執行 `python -m pytest tests/test_identity_model.py -q`。
測試會升級、回復及清除該資料庫的 schema。執行完整測試時還需設定
`TEST_REDIS_URL`，請參閱 [development.md](development.md)。
