# 自主學習計畫第 1～6 週完成情況

整理日期：2026-10-15（Asia/Taipei）。此表依已知 Issue 週次與現有模組整理，**未取得原始學習計畫全文與逐週實際完成紀錄**，不推定各功能在某個日曆週如期完成。已知 #16 為第三週、#17 為第四週、#19 為第五週、#20 為第六週；W1–2 為基礎功能的整理分類。

| 週次 | 已知目標／整理範圍 | 目前成果 | 驗證與完成界線 |
| --- | --- | --- | --- |
| W1（依模組歸類） | Backend 與身份資料基礎 | FastAPI health、PostgreSQL、Alembic、User 與 ExternalIdentity 分離、Docker Compose | 具全新 migration、唯一性／關聯／回滾與 Compose 自動化測試；無原始週次紀錄可證實完成日期 |
| W2（依模組歸類） | Google 身份與瀏覽器登入基礎 | Google OAuth Authorization Code + PKCE、User mapping、Redis、Browser Session、登出、管理員與 Client 管理 | 受控 Google callback 與真實 DB/Redis 測試；未執行真實 Google 帳號登入；無原始週次紀錄可證實完成日期 |
| W3（#16） | SSO Token 與金鑰管理 | Authorization Code、Client authentication、PKCE、Ed25519 Access/ID Token、用途隔離、金鑰檔、輪替、JWKS | #9、#14–#16 已有實作與負面案例；主線 PR #35 CI 成功；正式金鑰／Google secrets 須部署者配置 |
| W4（#17） | 第三方 Client 串接 | Discovery、示範 Client、state / nonce / PKCE、JWKS ID Token 驗證、獨立 Client Session | first-party 示範 Client 整合與雙 Uvicorn HTTP smoke；外部 Client consent UI／核准流程未完成，現採拒絕發碼 |
| W5（#19） | 學生資格 API | 本人 Access Token + Scope 查詢、eligible / ineligible / unknown、來源／有效期／驗證標記、fixture CLI | 測試資料明確 `verified=false`；不由登入或 Email 推定在學；正式校方學籍同步未實作 |
| W6（#20） | 身份系統整合與成果驗證 | 受控 Google → Argus Session → SSO Code → 同次 ID/Access Token → Demo Client → 資格查詢、案例矩陣、執行方式與 CI 證據保存 | 本機 W6 250 passed，另 W7 QR 84 passed；HTTP／Compose 驗證通過；新 PR CI 以其 Actions run 為準，既有 PR #35 success 僅代表其 commit |

## 可核對成果

- 架構與啟動：[README](../README.md)、[development.md](development.md)、[identity-model.md](identity-model.md)。
- 登入與授權：[google-oauth.md](google-oauth.md)、[browser-session.md](browser-session.md)、[admin.md](admin.md)、[sso-clients.md](sso-clients.md)、[authorization.md](authorization.md)。
- Token 與串接：[jwt.md](jwt.md)、[signing-keys.md](signing-keys.md)、[oidc-demo.md](oidc-demo.md)、[student-eligibility.md](student-eligibility.md)。
- 第六週結果、完整案例對照、重現步驟與限制：[week6-test-report.md](week6-test-report.md)。
- 已確認的遠端成功證據：[PR #35 head 的 Actions run](https://github.com/smm2271/aletheia-backend/actions/runs/38660822100)，commit `1b14e2383ca4e4110da8c2df52b9f1b562948e40`。

## 未完成或不在此階段範圍

尚未完成：真實 Google 帳號外部 smoke、正式學籍同步、外部 Client consent 產品流程；本次新 PR 的遠端 CI 結果須另以其 Actions run 核對。這些不能以受控測試成功代替。

#27–#29 的 QR 簽章、編碼與固定憑證發放為本次另行處理的功能，不回填為 W1–6 已驗收成果。QR Nonce 去重、動態 QR、NFC、品牌與正式高可用部署仍不在 #20 驗收範圍。
