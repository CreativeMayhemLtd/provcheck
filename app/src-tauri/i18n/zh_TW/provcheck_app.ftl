# provcheck-app GUI 訊息，英文為權威來源。此處僅本地化以 ApiResult ok/err
# 文字形式回傳給 GUI 的完整使用者可讀語句；技術性的 { $err }／記錄檔路徑
# 診斷資訊與 IPC 錯誤標籤仍維持英文。品牌與技術用語字面（provcheck、
# provcheck-kit、Backfire、Mellin、C2PA、atproto、LOCALAPPDATA、
# BACKFIRE_PY、Yubikey、PIV PIN、DID、旗標、檔案名稱）在每個語系中皆維持原文不變。

## Backfire keyed-image tab (backfire_read + install_backfire).
backfire-read-needs-key = 讀取 Backfire 標記需要提供金鑰。
backfire-folder-unresolved = 無法解析出可寫入的 Backfire 資料夾（LOCALAPPDATA 未設定）。
backfire-ready-bundled = Backfire 已就緒（已內含隨附的讀取器）。請輸入金鑰並拖入影像。
backfire-files-missing = 找不到可供安裝的 Backfire 檔案。請重新安裝 provcheck，或設定 BACKFIRE_PY。
backfire-ready = Backfire 已就緒。請輸入金鑰並拖入影像。

## Mellin keyed-marks tab (mellin_read).
mellin-needs-secret-and-work-id = 讀取 Mellin 序號需要提供密鑰檔案與作品編號。
mellin-secret-file-missing = 所選的密鑰檔案不存在（或無法讀取）。

## Sign + Keys tabs: GUI capability-limit notices returned as ApiResult errors.
identity-already-exists = 此資料目錄已存在身分；請傳入 force=true 以重新產生（此舉將使先前已發布的 atproto 紀錄成為孤兒紀錄）
rotate-yubikey-unsupported = 目前尚不支援在 GUI 中輪替以 Yubikey 為基礎的身分。請在終端機執行 `provcheck-kit init --yubikey --force`，完成後再回到此處進行發布與撤銷。
rotate-agefile-unsupported = 目前尚未串接以 age 檔案為基礎之身分的 GUI 輪替功能。請在終端機使用 `provcheck-kit rotate`。
sign-keychain-only = 目前 GUI 簽署僅支援作業系統金鑰鏈中的身分。若為 age 檔案身分，請於終端機以 CLI 使用 `provcheck-kit sign`。
sign-yubikey-unsupported = 以 Yubikey 為基礎之身分的 GUI 簽署功能將於 v0.5.0 P3 與 P4 推出。目前請於終端機透過 `provcheck-kit sign` 進行簽署，該工具會在每次簽署時提示輸入 PIV PIN。
