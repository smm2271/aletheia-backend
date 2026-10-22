# 靜態 QR 掃描驗證與 Nonce 語義

持有人以 Argus Browser Session 呼叫 `POST /api/v1/qr/credentials` 取得靜態簽章 Token。掃描端另以已註冊 Client 的 Authorization Code + PKCE 流程，取得 audience `argus-api`、Scope `qr:static:verify` 的 Access Token。掃描 API 不接受持有人 Cookie 或 ID Token 作為掃描授權。

```http
POST /api/v1/qr/static/verify
Authorization: Bearer <scanner-access-token>
Content-Type: application/json

{"token":"<signed-static-qr>","nonce":"<fresh-scanner-nonce>"}
```

掃描端使用 `qr.nonces.generate_nonce()` 產生 `v1.<Unix timestamp>.<256-bit random>` Nonce；每次新的掃描驗證應產生新值，不從 QR 內取得。`QR_NONCE_TTL_SECONDS` 預設為 300 秒，允許 1～600 秒；Nonce 時間須滿足 `now - TTL < issued_at <= now`，不接受未來時間。Redis `SET NX EX` 保存至這個 Nonce 的剩餘有效期限。回應成功僅為 `{"valid":true}`，不回傳持有人 User UUID、Email、學號、姓名、資格證據或原始 Token。成功與錯誤回應均不應快取。

## 驗證順序與狀態

1. 檢查掃描端 Access Token 的簽章、用途、audience、issuer、有效期與 Scope；即時檢查掃描端 User 與 Client 仍啟用，Client 仍獲准 Scope。
2. 檢查 QR 簽章、QR 專用金鑰與用途、有效期，再確認資料庫目前 credential mapping、對應持有人存在且啟用。
3. 驗證 Nonce 版本、時間與隨機格式，依 Client 與功能 namespace 在 Redis 原子 claim；此前的失敗不得消耗 Nonce。
4. claim 成功才回傳 `valid=true`。這表示此次已授權的請求通過目前憑證與去重檢查，不代表入場、正式學籍或實體本人核驗已完成。

| 情況 | 預期 HTTP 結果 |
| --- | --- |
| 有效掃描端、QR、全新 Nonce | 200，僅 `valid=true` |
| 同 Client 重複相同 Nonce | 409；即使換另一個 QR 也拒絕 |
| 同 Client、相同靜態 QR、換新 Nonce | 可以再次成功 |
| 不同 Client、相同 Nonce | 各自獨立，可以各成功一次 |
| Nonce 不合法或已過期 | 400，不執行有效 claim |
| 無效或缺少 Access Token | 401；瀏覽器 Cookie 不足以授權 |
| 缺少 Scope 或 Client Scope 已移除 | 403 |
| QR 無效、mapping 不符或失效 | 400 |
| Redis 故障 | 503；不得在未完成原子去重時放行 |

Nonce 去重的範圍是「Client + 驗證功能 namespace + Nonce」，不是「QR + Nonce」或全域所有 Client。Redis 僅保存有期限的去重記錄，不永久禁用靜態 QR。Nonce 時間窗與 Redis TTL 必須配合，避免時間窗尚有效時已遺失 claim；helper 的具體格式、時鐘容許值及錯誤型別以 `qr/nonces.py` 為準。

## 可證明與不可證明的能力

原子 claim 保證在同一 Client、同一 Nonce 的並行驗證中，至多一次回應成功。拒絕未授權或錯誤 QR 後，該 Nonce 仍能用於一個有效請求。若 Redis 在回覆途中斷線，即使客戶端得到 503，也可能已寫入 claim；應以新 Nonce 重試，不保證所有故障重試會沿用原 Nonce 成功。

這個機制**不防靜態 QR 截圖或複製**。取得有效 QR 的人若同時具備合法掃描端權限，可以換新 Nonce 再送出；Nonce 由掃描端產生，並非伺服器向持有人發出、再由持有人簽署的 challenge。它亦不能區分「合法第二次掃描」與「複製 QR 後搭配 fresh Nonce 的請求」。不宣稱防截圖、活體、持有人在場或持有人對此次交易的意圖。

沒有管理員豁免：Client、掃描端 User 與 QR 持有人狀態都需要即時檢查。憑證刪除／換發、到期與停用應影響後續請求。靜態 QR 只有其既有有效期；這次沒有加入動態 QR、NFC、入場策略或學籍決策。

## 測試方式與證據界線

`tests/test_qr_verification_flow.py` 使用真實隔離 PostgreSQL / Redis，透過受控 Google callback 建立不同的持有人與掃描端身份。持有人 Session 經 API 簽發 QR，掃描端經 `/authorize` 與 `/token` 取得真實 Ed25519 Access Token。整合案例涵蓋完整成功鏈、最小揭露、未授權／錯誤 QR 不消耗 Nonce、Client namespace、同 Client 跨 QR 去重、新 Nonce 重用靜態 QR、24 個並行請求、即時身份／Client／mapping 變更與 Redis 寫入故障。

`tests/smoke_qr_verification.py` 啟動真實 Uvicorn，使用 HTTP 執行持有人簽發、掃描端 Code Exchange、驗證、重播、新 Nonce 重試及 8 個 HTTP 請求的原子競態。接著對專用 Redis 執行 `CLIENT PAUSE 6000 WRITE`，確認真實 socket 寫入等待超時後 API 回傳 503；自動復原後以新 Nonce 成功。不要求故障期間使用的 Nonce 能再用，因為超時的寫入仍可能提交。為避免外部帳號依賴，HTTP smoke 直接建立測試 Browser Session；不呼叫真實 Google。

本次 Windows 專項實測 `test_qr_verification_flow.py` 與 `test_qr_verification.py` 合計 **65 passed**（整合 11、API 54），30.43 秒、67 則相依套件 deprecation warnings；上述真實 HTTP smoke 亦通過。這是本機驗證記錄，不代表遠端 CI 已成功；最新完整套件與 CI 結果以本次 PR 為準。

整合後 Linux 完整回歸為 **445 passed、0 skipped**，80.97 秒，258 則相依套件 warnings。執行時設定 `TEST_QR_NONCE_REDIS_URL`，包含真實 Redis 的 100 並行 nonce claim 案例；既有 OIDC／資格／QR 往返 HTTP smoke 與本次掃描驗證 HTTP smoke 均通過，後者包含真實 Redis 寫入逾時 503 與復原 200。此處仍為本機驗證證據；本 PR 遠端 CI 須以其實際 run 為準。

執行前安裝 `requirements-dev.txt`，設定 `TEST_DATABASE_URL` 為專用空白 PostgreSQL 資料庫、`TEST_REDIS_URL` 為**專用 Redis instance**；不可連正式資料庫。`CLIENT PAUSE` 影響該 Redis instance 的所有 database，因此只更換 database index 不構成 HTTP smoke 的完整隔離。測試會清理其測試 schema，不支援與另一個共用 DB 測試並行。

```powershell
$env:TEST_QR_NONCE_REDIS_URL = $env:TEST_REDIS_URL
python -m pytest -q tests/test_qr_verification_flow.py
if ($LASTEXITCODE -ne 0) { throw 'QR flow tests failed' }
python tests/smoke_qr_verification.py
if ($LASTEXITCODE -ne 0) { throw 'QR HTTP smoke failed' }
```

`TEST_QR_NONCE_REDIS_URL` 供 Nonce 模組的真實 Redis 案例使用，完整執行 `python -m pytest -q` 時亦須設定，避免該整合案例被 skip。HTTP smoke 使用 localhost 18002；須確保 port 可用。Redis 測試只清理本次建立的 key，不執行 FLUSHDB。
