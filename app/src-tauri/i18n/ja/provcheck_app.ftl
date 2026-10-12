# provcheck-app の GUI メッセージ、英語(原文)。ここでローカライズするのは、GUI に
# ApiResult の ok/err テキストとして返される、完全なユーザー向けの文のみです。技術的な
# { $err }/ログパスの診断情報や IPC エラーラベルは英語のままとします。ブランド名や技術
# 用語のリテラル(provcheck、provcheck-kit、Backfire、Mellin、C2PA、atproto、
# LOCALAPPDATA、BACKFIRE_PY、Yubikey、PIV PIN、DID、フラグ、ファイル名)は、すべての
# ロケールでそのまま(原文表記)を維持します。

## Backfire の鍵付き画像タブ(backfire_read + install_backfire)。
backfire-read-needs-key = Backfire のマークを読み取るには鍵が必要です。
backfire-folder-unresolved = 書き込み可能な Backfire フォルダーを解決できませんでした(LOCALAPPDATA が未設定です)。
backfire-ready-bundled = Backfire の準備が整いました(同梱のリーダーが存在します)。鍵を入力し、画像をドロップしてください。
backfire-files-missing = インストールに必要な Backfire のファイルが見つかりません。provcheck を再インストールするか、BACKFIRE_PY を設定してください。
backfire-ready = Backfire の準備が整いました。鍵を入力し、画像をドロップしてください。

## Mellin の鍵付きマークタブ(mellin_read)。
mellin-needs-secret-and-work-id = Mellin のシリアルを読み取るには、シークレットファイルとワークIDが必要です。
mellin-secret-file-missing = 選択されたシークレットファイルが存在しないか、読み取れません。

## 署名タブと鍵タブ: GUI の機能制限に関する通知(ApiResult エラーとして返されます)。
identity-already-exists = このデータディレクトリには既にアイデンティティが存在します。再生成するには force=true を指定してください(この操作により、以前に公開した atproto のレコードは孤立します)。
rotate-yubikey-unsupported = Yubikey に紐づいたアイデンティティの GUI からのローテーションには、まだ対応していません。ターミナルで `provcheck-kit init --yubikey --force` を実行してから、ここに戻って公開と失効を行ってください。
rotate-agefile-unsupported = age ファイルに紐づいたアイデンティティの GUI からのローテーションは、まだ実装されていません。ターミナルで `provcheck-kit rotate` を使用してください。
sign-keychain-only = GUI での署名は、現在 OS キーチェーンに保存されたアイデンティティのみに対応しています。age ファイルのアイデンティティには、CLI で `provcheck-kit sign` を使用してください。
sign-yubikey-unsupported = Yubikey に紐づいたアイデンティティの GUI での署名は、v0.5.0 の P3 と P4 で対応予定です。それまでは、ターミナルで `provcheck-kit sign` を使用して署名してください。署名のたびに PIV PIN の入力を求められます。
