# provcheck-cli 執行期輸出，英文為權威來源。此處僅本地化人類可讀的輸出；
# --json 輸出與結束代碼（exit code）永遠不會本地化。佔位符 { $name } 會在
# 呼叫端填入，翻譯時請保持原樣不變。品牌與技術用語字面（provcheck、
# C2PA、Backfire、Mellin、BUSL、Apache-2.0、JSON、PowerShell、bash、旗標、檔案名稱）
# 在每個語系中皆維持原文不變。

## Mellin keyed-audio forensic block (print_mellin_human).
mellin-header = Mellin（實驗性功能，具金鑰音訊鑑識序號）：
mellin-serial-full = 序號：   { $serial }（已還原全部 64 位元，最低位元票數為 { $votes }）
mellin-serial-partial = 序號：   未完全還原（{ $bits }/64 位元，最低位元票數為 { $votes }）
mellin-erasures = 抹除率：佔位置的 { $pct }%
mellin-expected-match = 預期結果：相符
mellin-expected-no-match = 預期結果：不相符

## Backfire keyed-image watermark block (print_backfire_human).
backfire-header = Backfire（實驗性功能，具金鑰影像浮水印）：
backfire-mark-valid = 標記：   有效（編號 { $id }，邊際值 { $margin }）
backfire-mark-none = 標記：   未偵測到（邊際值 { $margin }）
backfire-tamper-detected = 竄改：偵測到頻帶凹陷（統計值 { $stat }），此影像極有可能遭到凹陷攻擊
backfire-tamper-none = 竄改：無（頻帶凹陷統計值 { $stat }）

## Backfire setup (--install-backfire).
backfire-folder-not-found = provcheck：找不到 backfire 資料夾。請設定 BACKFIRE_PY 指向 backfire.py，或從包含 backfire/backfire.py 的目錄執行。
backfire-ps1-not-found = provcheck：在 { $dir } 中找不到 setup_backfire.ps1
backfire-sh-not-found = provcheck：在 { $dir } 中找不到 setup_backfire.sh
backfire-setup-start = 正在設定 Backfire 讀取環境（僅需執行一次）。此步驟會下載一份獨立封裝的 Python。
backfire-setup-ready = Backfire 已就緒。請使用以下指令驗證已標記的影像：  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck：Backfire 設定程序以狀態碼 { $status } 結束
backfire-setup-run-failed = provcheck：無法執行 Backfire 設定指令碼（{ $err }）。Windows 需要 PowerShell，Linux/macOS 則需要 bash。

## Model install (--install-models).
install-models-start = 正在安裝 { $count } 個浮水印偵測模型檔案（共 { $mb } MB）。
install-models-item = { $family }/{ $variant }（{ $mb } MB） ……
install-models-ok = 完成
install-models-item-failed = 失敗：{ $err }
install-models-done = 所有模型皆已安裝完成，浮水印偵測功能已就緒。
install-models-summary-failed = provcheck：{ $count } 個模型安裝失敗（詳情請見上方）。

## Main verify path: errors, notices, and hints.
require-attested-needs-identity = provcheck：--require-attested 需要搭配 --bsky-handle、--did 或 --auto-identity 使用
trust-store-read-failed = provcheck：無法讀取信任儲存庫「{ $path }」：{ $err }
auto-identity-no-assertion = provcheck：已指定 --auto-identity，但此檔案並未附帶 app.provcheck.identity 聲明。請先使用 `provcheck-kit sign --embed-identity` 簽署，或直接傳入 --bsky-handle 或 --did。
backfire-needs-key = provcheck：--backfire-read 需要搭配 --backfire-key 使用
backfire-experimental-notice = provcheck：Backfire 為實驗性功能，採用 BUSL 授權（非商業用途免費），與 Apache-2.0 核心分開發布。它會驗證您所嵌入的具金鑰標記，並標示出頻帶凹陷竄改；其穩健程度視個別影像而定。
backfire-read-failed = provcheck：backfire 讀取失敗：{ $err }
mellin-needs-args = provcheck：--mellin-read 需要搭配 --mellin-secret-file 與 --mellin-work-id 使用
mellin-experimental-notice = provcheck：Mellin 為實驗性功能，採用 BUSL 授權（非商業用途免費），與 Apache-2.0 核心分開發布。它會讀取您所嵌入、每份拷貝專屬的具金鑰序號；若沒有您的密鑰與作品編號，將無法讀取任何內容。
mellin-read-failed = provcheck：mellin 讀取失敗：{ $err }
json-serialize-failed = provcheck：JSON 序列化失敗：{ $err }
hint-models-missing = [提示] 有 { $count } 個浮水印偵測模型尚未安裝，因此對應項目會顯示「未安裝」。執行以下指令即可啟用完整偵測功能：  provcheck --install-models （僅需執行一次，共 { $mb } MB）。C2PA 驗證並不需要這些模型。
hint-claims-identity = [提示] 此檔案聲明的身分為 { $who }。請加上 --auto-identity 重新執行，即可對照其公開發布的簽署金鑰紀錄進行驗證。
