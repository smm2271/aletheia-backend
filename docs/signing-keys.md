# Ed25519 金鑰管理

`signing_keys.py` 管理 SSO 與 QR 的獨立 Ed25519 金鑰。每組具有隨機 UUID `kid`、
`purpose`、`status`、Unix 秒 `created_at`。相同公鑰材料不得重複使用，即使用途不同。
每個用途恰好一組 Active key；Verify Only 只留公鑰；Retired 不再驗證或分發。

## 本機啟用

在 Backend 的 Python 環境執行，產生的秘密檔案不會輸出至終端：

```sh
python -m signing_keys generate secrets/keys.json
```

此命令使用 exclusive create，不會覆蓋現有檔案。Git 與 Docker build context 均忽略
`secrets/`。私鑰使用 Ed25519 raw bytes 的 base64url 編碼存入秘密檔案；這不是加密，
必須以 OS 權限與 Secret Management 保護。不要將檔案提交至 Git 或加入映像。

POSIX 新建檔案權限為 0600；載入時拒絕 group/other 有任何權限的檔案。Windows
產生器移除繼承 ACL 並僅授權目前使用者；外部提供的檔案由部署者先設定同等 ACL。
應限制父目錄修改權限，避免其他使用者置換檔案，並保護備份。正式環境可由 Secret
Manager 掛載這份 JSON，或將受信資料交給 `KeyRing.from_document()`，再透過
`app.state.sso_key_provider` 注入；業務 Token Service 不讀取私鑰檔案。

設定環境後啟動 Backend：

```text
SIGNING_KEYS_FILE=/absolute/path/to/secrets/keys.json
SSO_ISSUER=http://localhost:8000
SSO_ACCESS_AUDIENCE=argus-api
SSO_ACCESS_TOKEN_TTL_SECONDS=300
SSO_ID_TOKEN_TTL_SECONDS=300
```

未設定 `SIGNING_KEYS_FILE` 且未注入 Provider 時，SSO 簽發／Discovery／JWKS 回傳
503，其他 API 可啟動。指定檔案但內容、權限或設定錯誤時，啟動失敗，不自動建立替代
金鑰。執行期間每次簽發、驗證與 JWKS 查詢均重新讀取完整快照；檔案毀損時停止使用，
不退回舊快照。例外訊息不含私鑰內容。

## Docker 掛載

使用 `compose.sso.yaml`，額外掛載受保護的目錄，覆蓋檔案路徑：

```sh
docker compose -f compose.yaml -f compose.sso.yaml up --build -d --wait
```

先在 `.env` 設定 `SIGNING_KEYS_DIRECTORY` 為主機上的絕對目錄，內含 `keys.json`。
容器以 UID 1000 的 `app` 使用者執行；Linux 主機需讓檔案屬於 UID 1000，且維持
0600／0400。Docker Desktop 的 bind mount 權限由主機控制；若掛載呈現可公開讀取的
POSIX mode，應改由受控 Linux volume 或 Secret Manager 提供受保護檔案，勿關閉檢查。
掛載整個目錄而非單一檔案，可讓 atomic replacement 在容器中即時生效。

## 輪替與退役

```sh
python -m signing_keys rotate secrets/keys.json --purpose sso
python -m signing_keys rotate secrets/keys.json --purpose qr
python -m signing_keys retire secrets/keys.json --kid OLD_KEY_ID
```

輪替移除舊私鑰，將舊公鑰轉為 Verify Only，並建立新的 Active key。保留期限至少為
所有 JWT 的最長允許 TTL（3600 秒）；期限未到不可退役。只支援單一管理者寫入，
請序列化管理命令。寫入以同目錄暫存檔 + atomic replace 完成，讀者不會讀到半份資料。
QR 輪替亦使用相同保留期限；未來 QR 長效憑證需在引入時調整獨立的保留政策。
本次靜態 QR Token 的有效期上限同為 3600 秒，詳見 [static-qr.md](static-qr.md)。

`GET /.well-known/jwks.json` 只分發 SSO Active / Verify Only 公鑰，格式為
`kty=OKP`、`crv=Ed25519`、`x`、`kid`、`use=sig`、`alg=EdDSA`，不含 `d` 或 QR key。
目前採 `Cache-Control: no-store`，示範 Client 每次 Callback 重新取得公鑰。
QR key 用於獨立的靜態 QR 憑證；尚未提供 QR 公鑰 HTTP API，不能從 SSO JWKS 取得。

參考：[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)。
