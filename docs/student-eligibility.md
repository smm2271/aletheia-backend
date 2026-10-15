# 學生資格 API

`GET /api/v1/student/eligibility` 僅查詢 Bearer Access Token 的 Subject，拒絕任何
query 參數，不接受 Argus Browser Cookie 或 ID Token 作為 API 授權。

需要有效 Ed25519 簽章、Issuer、Resource audience、時效、Token Type 與
`student:eligibility:read` Scope。API 亦即時確認 User 存在且未停用、Client 存在且
啟用、Client 目前仍獲准該 Scope。Token 無效回傳 401，權限不足回傳 403；Swagger
提供 HTTP Bearer 驗證入口。成功與授權失敗回應均為 `Cache-Control: no-store`。

```json
{
  "status": "eligible",
  "source": "test_fixture",
  "verified": false,
  "verification_status": "test",
  "updated_at": "2026-10-15T00:00:00Z",
  "valid_until": "2026-10-15T01:00:00Z"
}
```

此範例僅為測試資料，不能作為正式在學證明。API 不輸出姓名、學號、班級或完整
學籍資料。Client 必須同時考慮 `source`、`verified` 與有效期限，不能將測試結果視為
正式校方驗證。

## 判定與資料來源

Migration `20261015_0007` 新增 `student_eligibility`，以 User UUID 作為主鍵與
級聯刪除外鍵，一位使用者一筆目前的資格證據。資料包含明確的 `status`
（eligible / ineligible / unknown）、Source、Updated At、Valid Until 與 Verification
Status（test / unverified / verified）。SQL constraint 保證有效期晚於更新時間，
且 test_fixture 必須搭配 test 標記，無法標示為 verified。

Authentication、Affiliation 與 Eligibility 分開處理：既有 User Affiliation
分類不構成正式學籍證據，Google 登入、Email、姓名與網域都不會產生資格紀錄。
沒有證據、無有效期限、已過期、更新時間在未來，或僅 unverified 證據時，回傳
`unknown`，不推定為 ineligible。有效的 test_fixture 可用來測試三種狀態，但
`verified` 永遠為 false。有效且由受信管理流程標記 verified 的非測試證據，
才可能回傳 `verified=true`；目前尚未提供任何校方同步或正式資料匯入功能。

讀取 API 不會修改來源紀錄。過期後回傳 unknown，保留來源時間供 Client 判讀，
並將 verified 設為 false。正式資料只應由未來受信同步流程寫入，不能由 Client
自行回報。資料表並非授權邊界，DB 管理權限仍由部署者控制。

## 測試資料操作

提供僅供 Backend 操作者使用的 CLI，不開放 HTTP 寫入端點：

```sh
python -m student.fixtures USER_UUID eligible
python -m student.fixtures USER_UUID ineligible
python -m student.fixtures USER_UUID unknown
```

命令只建立明確標示 test_fixture / test 的一小時資料，不覆蓋非測試來源。
資料庫須先 migration，且使用者必須已存在。此 CLI 不提供正式驗證能力。

測試涵蓋三種資格狀態、來源與期限、未授權／停用 Client、停用／刪除 User、
缺少 Scope、錯誤 Token 簽章／Issuer／Audience／期限／kid，以及 ID Token 混用、
目前本人查詢限制、最小揭露、Migration check／downgrade／cascade 與 OpenAPI。
