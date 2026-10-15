# 第七至八週靜態 QR 文件與測試報告

驗收依據：[Issue #33](https://github.com/smm2271/aletheia-backend/issues/33)。
日期：2026-10-15（Asia/Taipei）。範圍限靜態 QR，不包含第十週動態 QR。

## Swagger 操作與 API 契約

依 [development.md](development.md) 啟動 Backend 後，開啟
http://localhost:8000/docs；原始 Schema 為 http://localhost:8000/openapi.json。
有設定不同 `BACKEND_PORT` 時請同步修改 URL。Swagger UI 預設從 CDN 載入資源，
離線環境仍可取得 OpenAPI JSON，但 UI 需要可存取其 CDN。
`tests/test_qr_openapi.py` 檢查文件頁可取得、Schema reference 可解析、授權分離、
必填欄位、錯誤格式及範例；不是人工瀏覽器視覺或 CDN 可用性測試。

| 端點 | 授權／輸入 | 成功回應 |
| --- | --- | --- |
| `POST /api/v1/qr/credentials` | 本人的 `aletheia_session` Cookie、精確符合 `SESSION_PUBLIC_ORIGIN` 的 Origin；省略 body 或 `{}` | `token`、不透明 `credential_id`、`format_version`、UTC `issued_at`／`expires_at` |
| `POST /api/v1/qr/static/verify` | Scanner 的 SSO Access Token；`aud=SSO_ACCESS_AUDIENCE`（預設 `argus-api`）、`qr:static:verify` Scope；body 必填 `token`、`nonce` | 僅 `{"valid":true}`，不回傳 User ID、Email、學籍或入場資格 |

簽發：先在同一瀏覽器透過 `/auth/google/login` 登入，並從設定的 Origin 開啟 `/docs`。
瀏覽器自動送出 Cookie 與 POST 的 Origin；Swagger 的 Authorize 無法用 JavaScript
設定 Cookie。僅持有 Access Token 不能簽發。簽發成功回應 `no-store`／`no-cache`，
未過期時重複或並行請求回傳同一張 Token，過期後才更新；沒有任意指定 User 或強制刷新參數。
金鑰設定見 [signing-keys.md](signing-keys.md) 與 `compose.sso.yaml`；未設定時簽發回傳 503。

驗證：Client 必須先經管理員允許 `qr:static:verify`，以 Authorization Code + PKCE
交換 Access Token，再於 Authorize 貼上 Token 本體。Cookie、ID Token、QR Token
都不能當作 Scanner 的 Bearer。每次操作以 `qr.nonces.generate_nonce()` 產生新 Nonce：

```python
from qr.nonces import generate_nonce
nonce = generate_nonce()  # v1.<Unix seconds>.<32 random bytes encoded as 43 base64url characters>
```

將實際簽發回傳的 `token` 及這次產生的 `nonce` 填入 Swagger body。文件中的 Token
是佔位字串、Nonce 是固定舊值，不能直接拿範例送出後期待成功。Nonce 最長 64 字元、
Token 最長 1024 字元；多餘 body 欄位與 query 參數均拒絕。Nonce TTL 預設 300 秒，
`QR_NONCE_TTL_SECONDS` 可設 1–600 秒，所有 worker 必須一致並校時，不接受未來時間。
驗證先完成 Scanner 授權、QR 簽章與目前 DB mapping／User 狀態，再以 Redis 原子 claim
Nonce；所有驗證回應均為 `no-store`。相同 Client／Nonce 跨不同 QR 仍衝突，不同 Client 各自去重。

| HTTP | 簽發 | 驗證 |
| --- | --- | --- |
| 200 | 取得目前憑證 | QR 目前有效且已 claim Nonce |
| 400 | 不支援 query 參數 | QR 無效、Nonce 格式／時效錯誤或 query 參數 |
| 401 | Session 不存在／過期、User 刪除／停用 | Scanner Token 無效或 Scanner／Client 刪除／停用 |
| 403 | Origin 不符合 | Token 缺少 Scope 或目前 Client 已撤銷 Scope |
| 409 | 未過期的既有憑證無法驗證，須等到期 | 同 Client 已消耗該 Nonce |
| 422 | FastAPI `HTTPValidationError`（`detail` 為陣列） | `VerificationError`（`detail` 為通用字串，不反射憑證） |
| 503 | 設定、金鑰、Session store 或 DB 不可用 | 設定、金鑰、DB 或 Redis 不可用，拒絕驗證 |

除簽發的 422 外，錯誤 body 為 `{"detail":"..."}`。驗證的 401／403 帶 Bearer
challenge。授權、body validation 與依賴檢查的先後會影響多重錯誤的回應；不保證固定優先序。
完整格式及政策見 [static-qr.md](static-qr.md)、[qr-api.md](qr-api.md)、
[qr-verification.md](qr-verification.md)、[qr-nonces.md](qr-nonces.md)。

## 覆蓋率重現方法

在專用 Python 環境安裝 `python -m pip install -r requirements-dev.txt`。
需要空白 PostgreSQL 18 測試 DB 與專用 Redis 8 instance。pytest fixture 會重建測試 DB
schema；HTTP smoke 的 `CLIENT PAUSE` 會暫停同一 Redis instance 的所有 DB，不能只換 index 隔離。
可另開一組測試服務（以下 port 必須未被占用）：

```sh
docker run -d --rm --name argus-w8-test-pg -p 127.0.0.1:15433:5432 -e POSTGRES_PASSWORD=w8-local-test-only -e POSTGRES_DB=aletheia_test postgres:18
docker run -d --rm --name argus-w8-test-redis -p 127.0.0.1:16333:6379 redis:8-alpine
docker exec argus-w8-test-pg pg_isready -U postgres -d aletheia_test
docker exec argus-w8-test-redis redis-cli ping
```

等待 ready／PONG 後設定連線。PowerShell：

```powershell
$env:TEST_DATABASE_URL = 'postgresql+psycopg://postgres:w8-local-test-only@localhost:15433/aletheia_test'
$env:TEST_REDIS_URL = 'redis://localhost:16333/0'
$env:TEST_QR_NONCE_REDIS_URL = $env:TEST_REDIS_URL
```

macOS／Linux：

```sh
export TEST_DATABASE_URL='postgresql+psycopg://postgres:w8-local-test-only@localhost:15433/aletheia_test'
export TEST_REDIS_URL='redis://localhost:16333/0'
export TEST_QR_NONCE_REDIS_URL="$TEST_REDIS_URL"
```

在 repository 根目錄逐一執行，確認各步 exit code 為 0：

```sh
python -c "from pathlib import Path; Path('test-results').mkdir(exist_ok=True)"
python -m pip freeze > test-results/packages.txt
python -m pytest -q --cov --cov-config=.coveragerc --cov-report=term-missing --cov-report=xml:test-results/coverage.xml --cov-report=html:test-results/htmlcov --cov-report=json:test-results/coverage.json --junitxml=test-results/pytest.xml
python tests/smoke_oidc.py
python tests/smoke_qr_verification.py
```

PowerShell 每步後可用 `if ($LASTEXITCODE -ne 0) { throw 'Validation failed' }` 中止。
缺少環境變數時部分測試會 skip；含 skip 的結果不能視為此報告的完整重現。
完成後可停止上面專用測試服務：`docker stop argus-w8-test-pg argus-w8-test-redis`。

HTML 入口為 `test-results/htmlcov/index.html`，XML 供工具讀取，JSON 可查每個檔案的
`missing_lines`、`missing_branches`。以同一份 coverage data 查看 QR 小計：

```sh
python -m coverage report --include="qr/*,routes/qr.py,routes/qr_verification.py,models/qr_credential.py"
```

`.coveragerc` 收集 Backend runtime、Demo Client 與模型，啟用 branch coverage；
未用 `omit` 或 `pragma: no cover` 隱藏 QR 的錯誤路徑。來源清單排除測試／smoke 程式本身、
Alembic migrations、第三方套件、Compose YAML 與 Swagger JavaScript；migration 行為仍由完整
pytest／Compose job 測試。HTTP smoke 是另外的獨立行程，本次 coverage 數字只計 pytest，
不把 smoke 的行數混入分母或分子。總百分比是 `(已覆蓋行 + 已覆蓋分支) / (可執行行 + 分支)`，
不是單純行覆蓋率，也不是安全保證。未設定任意最低百分比門檻。
coverage.py 7.16.2 的預設規則另排除了 20 行：模型 `TYPE_CHECKING` imports（4 行）及
SSO `Protocol` 的省略號介面宣告（16 行）；QR 檔案沒有被排除的行。6 個空白模組在終端
表格略過顯示，不是 pytest 的 skipped tests。

## 本次實測與 CI 證據

本次測試基線為 `32a31bba064d08670865b8275e05e4e34e90e6b4`（#32），加上 #33
提交前工作樹；只調整文件 metadata、coverage 設定與文件契約測試，不修改 QR 業務規則。

| 本次執行 | 結果 |
| --- | --- |
| Linux 全套 pytest + branch coverage | **449 passed、0 failed／errors／skipped**，104.85 秒；258 則 Starlette／Alembic deprecation warnings |
| QR 測試分組 | Token／圖片 66、簽發 18、Nonce 46、驗證 API 54、整合 11、Swagger 4，共 **199**；其餘身份／SSO 測試 250 |
| 真 HTTP OIDC／QR 編碼 smoke | 通過：Discovery、JWKS、Client callback／Session、資格、本人簽發及 PNG／ZXing round trip |
| 真 HTTP QR 驗證 smoke | 通過：Scanner 換碼、最小回應、重播、新 Nonce、8 並行、Redis 真實寫入逾時 503／復原 |
| 先前 #32 CI 基線 | [run 38670837428](https://github.com/smm2271/aletheia-backend/actions/runs/38670837428)，completed／success；不是本次新增 coverage 設定的執行結果 |
| 本次原始本機證據 | `test-results/issue33/`：`pytest.xml`／`pytest.log`、`coverage.xml`／`coverage.json`／`htmlcov`、版本及兩份 HTTP smoke log（忽略 Git 追蹤） |

本次 Docker 實測版本：Python 3.12.15、PostgreSQL 18.6、Redis 8.10.2、Docker 29.7.2、
Compose 5.5.0；pytest 9.1.1、pytest-cov 7.1.0、coverage.py 7.16.2、FastAPI 0.143.1、
Pydantic 2.14.1、SQLAlchemy 2.1.4、psycopg 3.3.6、redis-py 8.1.0。

| 計量範圍 | 行覆蓋 | 分支覆蓋 | 行＋分支合計 |
| --- | ---: | ---: | ---: |
| `.coveragerc` 全部 runtime 來源 | 1878／2026（92.69%） | 350／414（84.54%） | **91.31%** |
| QR 套件＋兩個 QR route＋QR model | 372／381（97.64%） | 73／78（93.59%） | **96.95%** |

QR 小計不包含共用 Session／SSO／key provider，因此同時列出全來源總計，避免只看 QR 百分比。
以下為同一次完整 pytest 的逐檔數據（空白 `qr/__init__.py` 無可執行行）：

| 檔案 | 可執行行／未覆蓋行 | 分支／未覆蓋分支 | 行＋分支合計 |
| --- | ---: | ---: | ---: |
| `models/qr_credential.py` | 14／0 | 0／0 | 100.00% |
| `qr/credentials.py` | 38／0 | 10／0 | 100.00% |
| `qr/encoding.py` | 15／3 | 2／1 | 76.47% |
| `qr/nonces.py` | 67／3 | 20／1 | 95.40% |
| `qr/tokens.py` | 94／2 | 26／2 | 96.67% |
| `qr/verification.py` | 67／0 | 12／0 | 100.00% |
| `qr/verification_flow.py` | 16／1 | 2／1 | 88.89% |
| `routes/qr.py` | 38／0 | 4／0 | 100.00% |
| `routes/qr_verification.py` | 32／0 | 2／0 | 100.00% |

### 未覆蓋路徑與風險

行號對應本次工作樹，往後重現請以 JSON／HTML 的當次行號為準。未以刪除防禦程式碼或
加入 coverage exclusion 來提升百分比：

| 檔案／未覆蓋行 | 尚未直接驗證的邊界與影響 |
| --- | --- |
| `qr/encoding.py:16,20–21` | Segno 產生超出版本上限或拋出容量例外的錯誤轉換；有效 payload 的最大尺寸 round trip 已測，但供應商失敗路徑尚未強制注入 |
| `qr/nonces.py:70,83–84` | 內部傳錯 settings 類型、Client ID 無法 UTF-8 編碼的拒絕；正常 API 使用已建構 settings／DB Client ID，helper 直接呼叫的異常仍有缺口 |
| `qr/tokens.py:59,126` | 非 object 的 JSON header／claims，以及 signing provider 回傳錯誤私鑰類型；一般錯誤格式與簽章負面案例不代表這兩條防禦路徑已測 |
| `qr/verification_flow.py:12` | 獨立缺少 `qr_nonce_settings` 時的 503；正常 lifespan 建構 settings，其他設定缺失與 Redis 503 測試未直接涵蓋此分支 |
| 共用服務 | `signing_keys.py` 合計 82.16%、`redis_connection.py` 70.59%、`student/fixtures.py` 0%；CLI、檔案／連線例外與開發 fixture 路徑仍有缺口，完整位置由 HTML／JSON 查閱 |

coverage 不等同於條件組合、需求或攻擊情境的全部覆蓋；100% 的 route 也不能取代外部系統、
多節點或現場使用測試。

CI 的 `test` job 使用同一份 `.coveragerc` 與完整 pytest 命令，接著跑兩個 HTTP smoke。
`backend-test-results-<run_id>-<attempt>` artifact 包含 commit、Python／套件／服務版本、
JUnit、pytest log、coverage XML／JSON／HTML 與兩份 smoke log，保留 30 天。
`compose` job 另外保存服務建置、health、migration、停機復原與資料持久化證據。
下載當次 artifact 可對照確切 commit 及版本；requirements 使用範圍、映像使用可變 tag，
因此不同時間或作業系統的數字可能不同。未來 CI 結果應以實際 run 為準，不由本報告預先宣稱成功。

## 安全負面測試與已知限制

| 邊界 | 主要測試／證據 |
| --- | --- |
| 簽章／格式／用途隔離 | `test_qr_tokens.py`：竄改、錯誤演算法／kid／purpose／issuer／audience／時效、額外或重複 claims、非 canonical encoding；QR／SSO Token 不混用，PNG → ZXing round trip |
| 僅本人簽發 | `test_qr_credentials.py`：匿名、停用／刪除、Origin、額外 body／query、並行首次與更新、輪替後重用、損毀 mapping、金鑰／DB 故障 |
| Scanner 即時授權 | `test_qr_verification.py`：Cookie／ID／QR Bearer 拒絕、Access Token 簽章／audience／issuer／Scope、Client／Scanner 停用、Scope 撤銷 |
| QR 即時有效性／最小揭露 | `test_qr_verification.py`：過期／刪除／替換／不一致 mapping、持有人停用或刪除、精確 timestamp 比對、通用錯誤、不反射 credential、no-store |
| 原子去重與時效 | `test_qr_nonces.py`：格式／熵／時間邊界／TTL、真 Redis 100 並行僅一次成功、Client 隔離、key 過期後舊 Nonce 仍拒絕、例外與不明回應拒絕驗證 |
| 完整掃描鏈 | `test_qr_verification_flow.py`：持有人 Session 發碼、不同 Scanner Code + PKCE 換碼、24 並行一成功、同 Client 跨 QR 去重、不同 Client 各自成功、壞 QR／無權限不消耗 Nonce、新 Nonce 重用 QR |
| 真實 HTTP 與故障復原 | `smoke_qr_verification.py`：Uvicorn、8 並行一成功、重播 409、Redis 寫入暫停使 socket timeout 回 503、恢復後新 Nonce 成功；不依賴 mock Redis outage |
| Swagger 與實作契約 | `test_qr_openapi.py`：Cookie／Bearer 分離、Origin、必填 Nonce、成功最小欄位、兩種 422 schema、各錯誤碼與範例 |

Google callback 在 pytest 使用受控回應，HTTP smoke 直接預建測試 Session；
未測真實 Google 帳號登入、正式校方學籍、真實相機／手機辨識、瀏覽器跨站部署或 production 負載。
並行測試不是吞吐量基準；不涵蓋多節點 Redis failover、記憶體淘汰、DB／Redis 共同交易或長時間壓力。

**靜態 QR 不能防複製。** 合法 Scanner 可拿同一張截圖搭配新 Nonce 再次成功。
Nonce 是 Client 範圍的請求去重，不是單次 QR、持有人簽出的 challenge，也不證明本人或現場存在。
Redis timeout 可能已寫入 claim，重試應用新 Nonce；Redis 重啟／淘汰／failover 丟失 key
則可能讓仍在時效內的 Nonce 再次被接受。離線驗簽也不能即時觀察 DB 停用／撤銷。
正式入場、人臉／實體查核、動態 QR 或額外身分 challenge 仍需獨立設計。

## 第七至八週成果摘要

| Issue | 成果與驗收來源 |
| --- | --- |
| #27／#28 | 專用 Ed25519 QR Token、無個資 claims、嚴格格式與生命週期、PNG 編碼及解碼 round trip；`static-qr.md`、`test_qr_tokens.py` |
| #29（既有實作） | 本人 Session 簽發、DB mapping、到期更新／並行鎖／輪替重用；`qr-api.md`、`test_qr_credentials.py`；本次只補 Swagger 文件 |
| #30 | 受 Access Token／Scope 保護的線上驗證、即時狀態與最小揭露；`qr-verification.md` |
| #31 | Redis Client-scoped Nonce、原子 claim／TTL／fail-closed；`qr-nonces.md` |
| #32 | 授權 → QR／mapping 檢查 → claim Nonce 的整合順序、真 HTTP 故障與並行證據；`qr-verification-flow.md` |
| #33 | Swagger 請求／回應／錯誤範例、授權操作說明、文件契約測試、可重現 coverage 與本報告 |

第六週身份鏈證據另見 [week6-test-report.md](week6-test-report.md)，不以 QR 測試總數替代其驗收。
