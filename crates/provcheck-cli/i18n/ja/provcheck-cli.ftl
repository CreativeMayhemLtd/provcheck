# provcheck-cli のランタイム出力、英語(原文)。人間が読むための出力のみを対象とし、
# --json 出力と終了コードはローカライズしません。プレースホルダー { $name } は呼び出し
# 箇所で埋め込まれるため、翻訳内でもそのまま保持してください。ブランド名や技術用語の
# リテラル(provcheck、C2PA、Backfire、Mellin、BUSL、Apache-2.0、JSON、PowerShell、bash、
# フラグ、ファイル名)は、すべてのロケールでそのまま(原文表記)を維持します。

## Mellin による鍵付きオーディオのフォレンジックブロック(print_mellin_human)。
mellin-header = Mellin(実験的機能、鍵付きオーディオのフォレンジック・シリアル):
mellin-serial-full = シリアル:   { $serial }(64ビットすべてを復元、最小ビット投票数 { $votes })
mellin-serial-partial = シリアル:   完全には復元できませんでした({ $bits }/64ビット、最小ビット投票数 { $votes })
mellin-erasures = 消失: 全体の { $pct }%の位置
mellin-expected-match = 期待値: 一致
mellin-expected-no-match = 期待値: 不一致

## Backfire による鍵付き画像の電子透かしブロック(print_backfire_human)。
backfire-header = Backfire(実験的機能、鍵付き画像の電子透かし):
backfire-mark-valid = マーク:   有効(id { $id }、マージン { $margin })
backfire-mark-none = マーク:   検出されませんでした(マージン { $margin })
backfire-tamper-detected = 改ざん: バンドノッチを検出(統計値 { $stat })。この画像はノッチ攻撃を受けた可能性が非常に高いです
backfire-tamper-none = 改ざん: なし(バンドノッチ統計値 { $stat })

## Backfire のセットアップ(--install-backfire)。
backfire-folder-not-found = provcheck: backfire フォルダーが見つかりませんでした。BACKFIRE_PY を backfire.py に設定するか、backfire/backfire.py を含むディレクトリから実行してください。
backfire-ps1-not-found = provcheck: setup_backfire.ps1 が { $dir } に見つかりません
backfire-sh-not-found = provcheck: setup_backfire.sh が { $dir } に見つかりません
backfire-setup-start = Backfire の読み取り環境をセットアップしています(初回のみ)。これにより、自己完結型の Python がダウンロードされます。
backfire-setup-ready = Backfire の準備が整いました。マーク付き画像を検証するには次のように実行してください:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire のセットアップがステータス { $status } で終了しました
backfire-setup-run-failed = provcheck: Backfire のセットアップスクリプトを実行できませんでした({ $err })。Windows では PowerShell、Linux/macOS では bash が必要です。

## モデルのインストール(--install-models)。
install-models-start = 電子透かし検出モデルファイルを { $count } 件インストールしています(合計 { $mb } MB)。
install-models-item = { $family }/{ $variant }({ $mb } MB)...
install-models-ok = 完了
install-models-item-failed = 失敗: { $err }
install-models-done = すべてのモデルのインストールが完了しました。電子透かし検出の準備が整いました。
install-models-summary-failed = provcheck: { $count } 件のモデルのインストールに失敗しました(詳細は上記を参照)。

## メイン検証パス: エラー、通知、ヒント。
require-attested-needs-identity = provcheck: --require-attested には --bsky-handle、--did、または --auto-identity が必要です
trust-store-read-failed = provcheck: トラストストア「{ $path }」を読み込めませんでした: { $err }
auto-identity-no-assertion = provcheck: --auto-identity が指定されましたが、このファイルには app.provcheck.identity アサーションが含まれていません。先に `provcheck-kit sign --embed-identity` で署名するか、--bsky-handle / --did を直接指定してください。
backfire-needs-key = provcheck: --backfire-read には --backfire-key が必要です
backfire-experimental-notice = provcheck: Backfire は実験的機能であり、Apache-2.0 のコア部分とは別に BUSL ライセンス(非商用利用は無料)で提供されています。埋め込んだ鍵付きマークを検証し、バンドノッチによる改ざんを検出します。堅牢性は画像ごとに異なります。
backfire-read-failed = provcheck: backfire の読み取りに失敗しました: { $err }
mellin-needs-args = provcheck: --mellin-read には --mellin-secret-file と --mellin-work-id が必要です
mellin-experimental-notice = provcheck: Mellin は実験的機能であり、Apache-2.0 のコア部分とは別に BUSL ライセンス(非商用利用は無料)で提供されています。埋め込んだコピーごとの鍵付きシリアルを読み取ります。シークレットとワークIDがなければ読み取る対象がありません。
mellin-read-failed = provcheck: mellin の読み取りに失敗しました: { $err }
json-serialize-failed = provcheck: JSON のシリアライズに失敗しました: { $err }
hint-models-missing = [ヒント] { $count } 件の電子透かし検出モデルがインストールされていないため、該当行は「未インストール」と表示されます。すべての検出を有効にするには次を実行してください:  provcheck --install-models (初回のみ、{ $mb } MB)。C2PA の検証にはこれらのモデルは不要です。
hint-claims-identity = [ヒント] このファイルはアイデンティティ { $who } を主張しています。公開されている署名鍵の記録と照合するには、--auto-identity を付けて再実行してください。
