# 第六週身分驗證整合測試報告

驗收依據：[Issue #20](https://github.com/smm2271/aletheia-backend/issues/20)。
報告日期：2026-10-15（Asia/Taipei）。本報告將既有主線 CI 證據與本次工作目錄驗證分開記錄。

## 版本與執行環境

| 項目 | 版本或範圍 |
| --- | --- |
| 本次修改基線 | `bb8f261`，PR #35 合併後的 main；本次驗證使用尚未提交的整合工作樹（提交前快照） |
| 已確認成功的遠端版本 | `1b14e2383ca4e4110da8c2df52b9f1b562948e40`（PR #35 head） |
| GitHub Actions | Ubuntu runner、Python 3.12、PostgreSQL 18、Redis 8 Alpine |
| Backend Docker image | `python:3.12-slim`；非 root 執行，啟動先執行 Alembic upgrade |
| 本機 Windows Python | 3.14.6 |
| 本機 Python 套件 | FastAPI 0.141.1、SQLAlchemy 2.0.52、PyJWT 2.13.0、cryptography 49.0.0、pytest 8.4.2 |
| 本次 Linux Docker 實測 | Python 3.12.15、PostgreSQL 18.6、Redis server 8.10.2、Docker 29.7.2、Compose 5.5.0 |
| Linux 實測 Python 套件 | FastAPI 0.143.1、SQLAlchemy 2.1.4、PyJWT 2.15.1、cryptography 49.0.0、pytest 9.1.1、Pydantic 2.14.1、redis-py 8.1.0、psycopg 3.3.6 |
| 本次 QR 測試套件 | segno 1.6.6、zxing-cpp 3.1.1、Pillow 12.3.0 |
| 依賴重現限制 | `requirements*.txt` 使用版本範圍，Docker image 使用可變 tag；不同時間解析出的 patch 版可能不同 |

CI 現在會保存 commit、Python、pip freeze、Docker、PostgreSQL 與 Redis 實際版本，以及 pytest JUnit XML、測試輸出與 Compose logs，保留 30 天。這項證據保存修改尚待新 CI run 驗證；不代表舊 run 已有 artifacts。

## 實測結果與證據界線

| 執行範圍 | 實際結果 | 證據與限制 |
| --- | --- | --- |
| PR #35 遠端 CI | completed / success | [Actions run 38660822100](https://github.com/smm2271/aletheia-backend/actions/runs/38660822100)，已由 GitHub connector 查驗；證明的是上表 PR #35 head |
| 本次受控完整登入鏈 | 通過 | `test_identity_integration.py`：從 Demo Client 發起登入，到受控 Google callback、Argus Session、Code、同一次 Token Exchange、Client ID Token 驗證及 Access Token 資格查詢 |
| 本次 Linux 全套 pytest | **334 passed，0 failed / errors / skipped**；54.40 秒 | `bb8f261` + 本次未提交工作樹；開始時間 2026-10-15 08:47:17（Asia/Taipei）；JUnit 時間 54.394 秒 |
| 本次真實 HTTP smoke | W6 與 W7 QR 擴充均通過 | 兩個 Uvicorn 行程；W6 為預建 Session 的 SSO／Client／資格流程；QR 另見附錄 |
| 本次 Compose 重建與故障恢復 | 全部通過；三個服務 healthy；fresh migration head `20261015_0008`、Alembic check 無差異、Redis TTL 通過 | DB／Redis 停機 readiness 503、liveness 200，復原 healthy；Redis 重啟後 marker=0；DB volume 重建後查回原值 42，三個服務恢復 healthy |
| 真實 Google 帳號外部登入 | 未執行 | 本次未使用正式 Google credentials、真實帳號、Google token endpoint 或 Google JWKS 網路呼叫 |
| 正式校方學籍查詢 | 未實作／未測試 | 以明確標記 `test_fixture`、`verified=false` 的證據測試狀態與授權 |

本次完整 pytest 中，W6 相關 **250 passed**，W7 QR 附錄 **84 passed**（Token 66、發放 API 18），不以總數混充 W6 覆蓋。另有 193 則 Starlette／Alembic deprecation warnings，未造成失敗；未在本次修改中宣稱已清除相容性警告。原始 JUnit 與 packages 證據輸出於忽略追蹤的 `test-results/`，不提交測試資料。這是提交前的本機驗證快照；新 PR 的遠端 CI 應以其 Actions run 實際結果為準，不由本報告預先宣稱成功。

| pytest 模組 | passed |
| --- | ---: |
| Admin / Authorization / Browser Session | 3 / 32 / 28 |
| Database config / Google OAuth / Identity chain / Identity model | 3 / 38 / 1 / 5 |
| JWT / OIDC integration / Redis | 50 / 18 / 6 |
| Signing keys / SSO clients / Student eligibility / Token endpoint | 15 / 14 / 15 / 22 |
| W7 QR credentials / QR tokens | 18 / 66 |
| 合計 | **334** |

以下矩陣對應本次已通過的測試斷言。參數化案例數會隨實作更新，不將函式數當作測試通過數。

## 驗收與案例矩陣

| 驗收範圍 | 測試來源 | 預期結果／實際檢查內容 |
| --- | --- | --- |
| 全新資料庫、Identity mapping | `test_identity_model.py`、`test_database_config.py` | Alembic upgrade/downgrade、外部身份唯一性、關聯與有損 downgrade 拒絕；共用安全 DB 設定 |
| Google 首登與重登 | `test_google_oauth.py` | 有效受控簽章建立 User + ExternalIdentity；相同 Google sub 維持同一 User；Email 碰撞不自動綁定 |
| Google callback 錯誤與競態 | `test_google_oauth.py` | 無效簽章／issuer／audience／時效／nonce／state、缺少 code、重複參數、Provider 失敗拒絕登入；並行 state 僅使用一次 |
| Session 全生命週期 | `test_browser_session.py` | 建立、讀取、重登輪替、TTL 過期、撤銷／登出；停用或刪除 User 即失效；Cookie secure、HttpOnly、SameSite 與 Origin 防護 |
| Session 儲存故障 | `test_browser_session.py` | Redis 失敗時拒絕授權；登出失敗不假報撤銷成功；OAuth 建立 Session 失敗不設定有效 Cookie |
| 管理員權限 | `test_admin.py` | 一般使用者拒絕；管理員降權立即生效；bootstrap 要求既存有效 User；migration 預設一般權限 |
| SSO Client 管理 | `test_sso_clients.py` | 管理權與 Origin 保護；Client type / trust level、精確 redirect URI、Scope allowlist；secret hash、輪替與停用 |
| Authorization Request | `test_authorization.py` | 從 Session 授權、匿名登入後綁定原請求、重新檢查 Client；無效 URI／Scope／nonce／重複參數拒絕；external consent 尚未完成時不發 Code |
| Code／PKCE／Token endpoint | `test_authorization.py`、`test_token.py` | 所有 Client 必須使用 PKCE S256；Code 與 Client、URI、verifier 綁定，過期／重播／競態僅一次成功；Basic/body Client 驗證與錯誤格式處理 |
| Ed25519 JWT／ID Token | `test_jwt.py`、`test_token.py` | 真實 Ed25519 簽發與公鑰驗證；必填 claims、issuer、audience、時間、kid、演算法、nonce、Scope；Access Token 與 ID Token 不混用 |
| 金鑰檔與 JWKS | `test_signing_keys.py`、`test_oidc_integration.py` | SSO/QR 用途隔離；JWKS 只公開 SSO 公鑰；輪替保留舊公鑰，退休後拒絕；無效／寬鬆權限金鑰檔失敗且不洩密 |
| 第三方 Client callback | `test_oidc_integration.py` | Discovery、JWKS、Code Exchange、ID Token、state / nonce 綁定及獨立 Session；偽造 Token、錯誤 PKCE／metadata redirect、儲存故障拒絕登入 |
| 學生資格狀態 | `test_student_eligibility.py` | eligible / ineligible / unknown；缺失、過期、未驗證或未來證據為 unknown；測試資料明確不具正式驗證效力 |
| 學生資格授權與揭露 | `test_student_eligibility.py` | 僅有效 Access Token 本人查詢；401/403、Scope 與即時 Client/User 狀態；拒絕 Cookie、ID Token、任意 User query；最小欄位與 no-store |
| 跨模組單一授權鏈 | `test_identity_integration.py` | Google identity → Argus User/Session → Code/PKCE → 同次交換的 ID Token + Access Token → Client Session + eligibility；Client 登出不撤銷 Argus Session |
| 真實 HTTP Client 流程 | `smoke_oidc.py` | 啟動兩個 Uvicorn 行程，以 HTTP 走 Discovery、JWKS、Code、Token、callback、Client Session、資格查詢與登出；登入前直接建立測試 Argus Session，未測 Google 外部連線 |
| Compose 基礎設施 | `.github/workflows/tests.yml` compose job | build/up、API/DB/Redis health、Alembic current/check、真實 Redis TTL、管理／Code／Session、DB 與 Redis 停機及復原、DB volume 重建仍保留資料 |

Compose 預設不載入簽章私鑰，故其 `/token` 檢查預期為 503 `temporarily_unavailable`；真實簽發成功路徑由帶有臨時 Ed25519 金鑰的 pytest 與 HTTP smoke 驗證。

## 必要安全負面測試對照

| Issue #20 必要案例 | 直接測試依據 | 預期 |
| --- | --- | --- |
| Authorization Code Replay | `test_code_single_use_and_second_use_rejected` | 第二次交換 400 |
| Expired Authorization Code | `test_expired_code_rejected` | 過期 Code 拒絕 |
| Concurrent Code Exchange | `test_atomic_concurrent_exchange` | 恰有一次成功 |
| Invalid Redirect URI | `test_invalid_request_rejected_before_login`、`test_mismatched_client_or_redirect_uri_does_not_burn_code` | 拒絕無效 URI／不錯發 Code |
| Invalid PKCE Verifier | `test_pkce_verification_failures` | 拒絕不匹配 verifier |
| Disabled Client | `test_disabled_client_cannot_authorize`、資格 API 授權案例 | 停用即拒絕 |
| Invalid JWT Signature | `test_signature_tampering_and_algorithms`、`test_api_rejects_invalid_identity_or_token[signature]` | 拒絕簽章錯誤 |
| Invalid JWT Audience | `test_invalid_claims_rejected`、資格 API audience 案例 | 拒絕錯誤 audience |
| Expired JWT | JWT claims 與資格 API expired 案例 | 拒絕過期 Token |
| Invalid State / Nonce | Google state/nonce、OIDC callback、JWT nonce 案例 | 拒絕錯誤綁定／重播 |
| Revoked Session | `test_logout_immediately_revokes_and_clears_cookie` | 舊 Cookie 無法再授權 |
| Unauthorized Admin Access | `test_admin_boundary_and_immediate_revocation` | 無管理權拒絕 |

## 可重複執行方式

完整自動化入口是 `.github/workflows/tests.yml`，包含獨立的 test 與 compose job。test job 提供全新 PostgreSQL / Redis service；pytest 與 smoke 必須依序執行。

本機請準備**專用且空白**的 PostgreSQL 資料庫與專用 Redis instance/database，安裝 `requirements-dev.txt` 後，使用 PowerShell：

```powershell
$env:TEST_DATABASE_URL = 'postgresql+psycopg://TEST_USER:TEST_PASSWORD@localhost:5432/aletheia_test'
$env:TEST_REDIS_URL = 'redis://localhost:6379/15'
New-Item -ItemType Directory -Force test-results | Out-Null
python -m pip freeze > test-results/packages.txt
python -m pytest -q --junitxml=test-results/pytest.xml
if ($LASTEXITCODE -ne 0) { throw 'pytest failed' }
python tests/smoke_oidc.py
if ($LASTEXITCODE -ne 0) { throw 'HTTP smoke failed' }
```

資料庫 fixture 會 assert 為空，結束時 DROP / CREATE public schema；**不可使用開發或正式資料庫**。pytest 未配置 `TEST_DATABASE_URL` 時會 skip 整合案例，因此只見綠色退出碼不足以驗收，須同時檢查 passed / failed / skipped。Redis 案例使用各自 key 並清理，不執行 FLUSHDB。HTTP smoke 使用 localhost 18000/18001，測試前須確保 port 可用，且不可與另一份 smoke 並行。

Compose 使用專用 project name 與未占用 host ports，先依 [development.md](development.md) 複製 `.env.example`，再執行：

```powershell
$env:COMPOSE_PROJECT_NAME = 'aletheia-week6-verification'
docker compose config --quiet
docker compose up --build -d --wait --wait-timeout 180
docker compose exec -T backend python -m alembic current
docker compose exec -T backend python -m alembic check
docker compose exec -T backend python -m redis_connection
curl.exe --fail http://localhost:8000/health/db
curl.exe --fail http://localhost:8000/health/redis
docker compose down
```

這段是啟動／migration／連線驗證；停機、重建、volume 與真實管理流程的完整步驟以 workflow compose job 為準。結束只清理此專用 project；保留資料時不要加 `-v`。

## 已知限制與後續改善

- Google 測試使用受控 Provider 與本地簽章 JWT，資料庫、Redis、PKCE、簽章驗證與應用路由仍為實際實作；不能據此宣稱真實 Google 帳號已驗證。後續以受控測試帳號與獨立 secrets 執行外部 smoke，另留不含 Token／Cookie 的證據。
- 學生資格目前沒有校方同步；Google 網域、Email 與 User affiliation 不代表在學。後續串接受信資料源、定義更新與失效政策。
- 外部 Client consent 目前以拒絕發碼保護邊界；示範 Client 為已註冊 first-party，不能宣稱已完成任意第三方 consent 產品流程。
- `.env.example` 預設未配置 Google 與簽章檔，Compose 可啟動基礎設施，但啟用正式登入／Token 仍需依各功能文件配置 secrets。
- 本次同批 QR 功能屬 #27–#29，額外測試可納入全套總數，但不屬 #20 的 W1–6 驗收範圍；QR Nonce 去重、動態 QR、NFC、正式高可用部署未在此驗收。
- 目前沒有宣稱程式碼行數 coverage、負載、滲透測試或正式環境可靠度達標。後續可固定 lockfile／image digest、加入外部整合與負載測試。

## 附錄：W7 QR 額外驗證範圍

本次同批 #27–#29 的測試程式涵蓋 QR Token 用途／金鑰隔離、最小 claims、簽章／時效驗證、PNG 產生與獨立 ZXing 解碼；固定憑證發放另驗證 Session／Origin、重複請求沿用同一 Token、並行首次發放、到期替換、金鑰輪替及 DB 約束。QR 單元／整合測試 **84 passed**。HTTP smoke 亦已通過真實 QR API 簽發、重複同 Token、PNG 解碼及 QR 簽章驗證。這些屬 W7 額外驗證，並非 #20 的 W1–6 驗收項目。

W1–6 狀態另見 [week1-6-progress.md](week1-6-progress.md)。
