# W10 Dynamic QR 驗收與覆蓋率報告

## 範圍與版本

- 日期：2026-10-22（Asia/Taipei）。
- 實作與測試 commit：`d4c38c807f4eef46e8b220987e83c3bd7165a4a9`；報告補入於後續文件 commit。
- PR：[W10 Dynamic QR #48](https://github.com/smm2271/aletheia-backend/pull/48)。
- 順序：#44 schema／簽發 → #45 原子狀態機 → #47 HTTP API → #46 整合驗收。
- W8 相依：#40～#42 原先合併於各自堆疊分支，本次將既有 `issue-33-qr-docs` 併入，讓 main 具備完整回歸基線。
- API 與狀態契約：[dynamic-qr.md](dynamic-qr.md)。不涉及學生資格、入場授權、付款、NFC 或前端顯示頁。

## 環境與重現

本機：Windows、Python 3.14.6、pytest 8.4.2、pytest-cov 7.1.0／coverage 7.16.2；
Docker Desktop 的 Linux PostgreSQL 18.6、Redis 8.10.2。測試使用本次建立的獨立容器與空資料庫，未使用既有服務資料。
CI：Ubuntu runner、Python 3.12、PostgreSQL 18、Redis 8；確切套件與服務版本由 artifacts 記錄。

```powershell
$env:TEST_DATABASE_URL='postgresql+psycopg://postgres:<password>@127.0.0.1:15432/aletheia_w10_test'
$env:TEST_REDIS_URL='redis://127.0.0.1:16379/0'
$env:TEST_QR_NONCE_REDIS_URL=$env:TEST_REDIS_URL
python -m pip install -r requirements-dev.txt
python -m pytest -q --cov --cov-config=.coveragerc --cov-report=term-missing --cov-report=json:test-results/w10-coverage.json --cov-report=xml:test-results/w10-coverage.xml --cov-report=html:test-results/w10-htmlcov --junitxml=test-results/w10-pytest.xml
python tests/summarize_w10_coverage.py test-results/w10-coverage.json
python tests/smoke_oidc.py
python tests/smoke_qr_verification.py
```

每個 DB fixture 與 smoke 都會清理 public schema，必須使用專用空資料庫。
`smoke_qr_verification.py` 會呼叫 `smoke_dynamic_qr.py`，在同一組獨立服務上同時驗證 W8 與 W10。
CI 自動產出全來源 XML／HTML／JSON、JUnit、pytest log、W10 覆蓋率摘要、兩個 smoke log 與 Compose 證據。

## 本機結果與安全驗收

完整測試 **534 passed、1 skipped、286 warnings，110.00 秒**。唯一 skip 為 Windows 不適用的 POSIX signing-key 檔案模式測試，Linux CI 仍執行。
W10 專用檔案包含 86 個案例，全部執行於完整 suite 中。
Warnings 來自既有依賴的相容性／棄用通知，無失敗案例。

| 驗收項目 | 證據與結果 |
| --- | --- |
| Schema／簽章 | 固定必要 claims、Ed25519、QR／SSO key 隔離、256-bit jti、無額外個資；缺失 claims／非法型別均拒絕 |
| 時間邊界 | age=0／25／29 秒可驗證，30／31 秒及未生效 token 拒絕；固定 TTL=30 |
| 輪替並存 | 模擬第 25 秒換發，舊新 jti 不同，Redis 舊 exp 不變，兩張均各成功一次；回應 refresh_after=25 |
| 一次性狀態 | 真實 Redis Lua 100 個併發 consume，恰好一個成功，最終 CONSUMED；不能重註冊或撤銷後重啟 |
| API 併發 | 修訂版使用 100 個 worker 與 101 方 Barrier（含主執行緒）同步釋放；100 個 verify 全部 HTTP 200，恰好一次 valid=true、99 次 valid=false，最終 CONSUMED |
| 真實 HTTP 併發 | 修訂版使用 Uvicorn、HTTPX 與不同 holder／scanner，100 個 worker 經 Barrier 同步釋放；斷言 100 次 HTTP 200、一次 valid=true、99 次 valid=false、最終 CONSUMED，並輸出耗時 |
| 撤銷與期限 | ISSUED→REVOKED、重複撤銷、已消耗、已撤銷、過期與缺失 state 均拒絕；獨立 token 狀態互不影響 |
| 偽造與篡改 | 錯誤簽章／payload／issuer／audience／type／kid、過期／未生效 token、未註冊 jti 均拒絕 |
| scanner 授權 | 缺少或無效 Access Token、錯 audience、缺 scope、目前 client／scanner 停用或移除 scope，均先拒絕且不消耗 |
| Browser 與所有權 | 未登入無法簽發／撤銷；缺 Origin、錯 Origin、額外 query／欄位均拒絕；非本人撤銷為 403 且 state 不變 |
| Redis 故障 | issue／consume／revoke 分別測連線失敗與逾時；未確認註冊不回 token，未知回覆不接受，錯誤不洩露連線細節 |
| 實際 socket 逾時 | HTTP smoke 使用 Redis CLIENT PAUSE WRITE 6 秒，dynamic consume 回 503；恢復後新 token 可驗證，未宣稱不確定 token 成功 |
| 最小揭露與快取 | verify 僅 valid 布林值；422 不回顯 token；所有回應 no-store；state 不保存 token、jti 或身份資訊 |
| 用途隔離 | Static／Dynamic 雙向拒絕，SSO key 簽出的 dynamic token 亦拒絕 |
| OpenAPI | 三條路由的 cookie／bearer、Origin、request／response schema 與 200／400／401／403／422／503 契約測試通過 |
| W6–W8 回歸 | 完整 suite 涵蓋 SSO／OIDC、身份整合、靜態 QR、verification／nonce；OIDC 與 QR 真實 HTTP smoke 均通過 |

## 覆蓋率

`.coveragerc` 列出的所有 runtime 來源納入分母，包含未執行的 CLI／fixture 程式。
排除 tests、migrations、文件及外部依賴。W10 範圍為三個新增 runtime 模組，
整合接線的 main／Discovery 仍計入全來源。Python coverage 不會量測 Lua 內部分支；
Lua 的一次性、撤銷、缺失、期限、metadata 不符及併發由真實 Redis 測試驗證。

| 範圍 | 行覆蓋率 | 分支覆蓋率 |
| --- | --- | --- |
| 全來源 | 2045 / 2197 = **93.08%** | 383 / 450 = **85.11%** |
| W10 | 184 / 190 = **96.84%** | 34 / 36 = **94.44%** |

Linux CI 全來源：2067 / 2221 行（93.07%）、384 / 450 分支（85.33%）；
W10 與本機相同（96.84%／94.44%）。跨環境分母依各 run 的 coverage JSON 為準。

行＋分支合計：全來源 91.73%，W10 96.46%。此數值不替代上述安全驗收。

未覆蓋 W10 路徑（以測試 commit 行號為準）：

- `qr/dynamic_tokens.py:63,81`：key provider 回傳非 Ed25519 公鑰，以及驗證時 key-management 基礎設施錯誤重拋。正常 key provider 有型別約束；相關失敗仍會拒絕／503，但此兩條未直接注入。
- `routes/qr_dynamic.py:69,75-76,82`：SSO issuer 未配置、scanner 驗證金鑰故障與即時 DB 查詢故障的 503 路徑。動態 issuer 未配置、Redis 故障均有測試；這幾條沿用既有錯誤政策，未直接注入。
- 全來源其餘未覆蓋以 artifacts JSON／HTML 為準，主要為 CLI bootstrap／student fixture loader、啟動／清理錯誤、配置與 defensive branches；既有 W8 報告亦說明其風險。

## CI 證據

[CI run 39712474206](https://github.com/smm2271/aletheia-backend/actions/runs/39712474206)
對應實作與測試 commit `d4c38c8`，**completed / success**。
test job **535 passed、0 skipped、285 warnings，60.91 秒**；兩個真實 HTTP smoke 均成功，
包含 dynamic 100 次請求（最多 20 個 worker，無同步閘門）與 Redis 真實 socket 逾時／恢復；此舊 run 不能作為 100 同時起跑的 HTTP 證據。compose job 亦成功，
涵蓋建置、健康檢查、Session／授權、DB／Redis 故障恢復與 volume persistence。

Run 頁面的 `backend-test-results-39712474206-1` 包含原始 coverage XML／HTML／JSON、
W10 摘要、JUnit、pytest 與 smoke logs、commit 與套件版本；
`compose-results-39712474206-1` 包含 Compose 服務、logs 與版本。Artifacts 保留 30 天，
本報告保留摘要以供過期後追溯。後續報告 commit 僅補文件，最終 head 的 CI 狀態以 PR checks 為準。

## 限制與後續

2026-10-29 PR #48 審查修訂：API 與真實 HTTP 競態改為 100 個 worker 等待同一個同步閘門，
worker 建立後才簽發新的 30 秒 token，再由主執行緒釋放全部請求。測試要求競態於 15 秒內完成，
並以 Redis TIME 斷言最後完成時尚未到 exp，避免把過期拒絕當成一次性競態證據。
所有請求均須正常回傳精確的布林結果與 no-store，最終 Redis state 必須為 CONSUMED。
修訂版本機結果：專用 PostgreSQL 18／Redis 8 上 **86 passed、0 skipped（16.75 秒）**；
真實 HTTP smoke **100/100 完成、1 true／99 false、CONSUMED、3.377 秒、完成時未到期**，
W8／W10 HTTP smoke 與真實 Redis 逾時／恢復均通過。
上述歷史覆蓋率與 CI 數值仍對應原始 commit；修訂版 CI 請見 PR 最新 head checks。

- 驗證依賴單一 Redis 的原子性與可用性，非跨區域協定。Redis 資料遺失會安全拒絕尚未過期的 token。
- 應用與 Redis 時鐘須同步。JWT 的 iat／nbf／exp 與 Redis TIME 共同限制期限，沒有寬限期。
- CLIENT PAUSE 造成的逾時可能已提交消耗；服務不重試接受，前端應以新 token 重新開始受控業務流程。
- 一次性 QR 不能防止有效期內被轉傳後搶先使用，也不等於支付／入場交易的冪等性。
- 可後續補入 key provider／DB 故障的直接注入與跨多個 backend worker 的負載測試。
- 動態 verify 不重新查詢持有人停用／刪除狀態；既有 token 仍受原本 30 秒期限與 Redis 狀態限制。即時失效要求需另行設計。
- 既有 Compose 驗收預設未配置 signing keys，不代表 Compose 已啟用動態 QR；多 worker 部署仍須以共享金鑰及 Redis 另行驗證。
