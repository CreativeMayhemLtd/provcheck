# provcheck-cli 运行时输出，简体中文译文（源文本为英文）。仅本地化面向人类阅读的输出；
# --json 输出和退出代码从不进行本地化。占位符 { $name } 会在
# 调用处被填充；翻译时请保持占位符原样不变。品牌与技术性字面量（provcheck、
# C2PA、Backfire、Mellin、BUSL、Apache-2.0、JSON、PowerShell、bash、flags、文件名）
# 在所有语言环境中均保持原文不译。

## Mellin 密钥音频取证信息块（print_mellin_human）。
mellin-header = Mellin（实验性，密钥音频取证序列号）：
mellin-serial-full = 序列号：   { $serial }（全部 64 位均已恢复，最小比特投票数 { $votes }）
mellin-serial-partial = 序列号：   未完全恢复（{ $bits }/64 位，最小比特投票数 { $votes }）
mellin-erasures = 擦除：占位置的 { $pct }%
mellin-expected-match = 预期：匹配
mellin-expected-no-match = 预期：不匹配

## Backfire 密钥图像水印信息块（print_backfire_human）。
backfire-header = Backfire（实验性，密钥图像水印）：
backfire-mark-valid = 标记：   有效（id { $id }，余量 { $margin }）
backfire-mark-none = 标记：   未检测到（余量 { $margin }）
backfire-tamper-detected = 篡改：检测到带阻陷波（统计值 { $stat }），该图像极有可能遭受了陷波攻击
backfire-tamper-none = 篡改：无（带阻陷波统计值 { $stat }）

## Backfire 安装设置（--install-backfire）。
backfire-folder-not-found = provcheck：未能定位到 backfire 文件夹。请将 BACKFIRE_PY 设置为 backfire.py 的路径，或在包含 backfire/backfire.py 的目录中运行。
backfire-ps1-not-found = provcheck：在 { $dir } 中未找到 setup_backfire.ps1
backfire-sh-not-found = provcheck：在 { $dir } 中未找到 setup_backfire.sh
backfire-setup-start = 正在设置 Backfire 读取环境（一次性操作）。此过程将下载一个独立的 Python 环境。
backfire-setup-ready = Backfire 已就绪。使用以下命令验证已标记的图像：  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck：Backfire 安装程序以状态码 { $status } 退出
backfire-setup-run-failed = provcheck：无法运行 Backfire 安装脚本（{ $err }）。该脚本在 Windows 上需要 PowerShell，在 Linux/macOS 上需要 bash。

## 模型安装（--install-models）。
install-models-start = 正在安装 { $count } 个水印检测模型文件（共 { $mb } MB）。
install-models-item = { $family }/{ $variant }（{ $mb } MB）……
install-models-ok = 完成
install-models-item-failed = 失败：{ $err }
install-models-done = 所有模型均已安装完成。水印检测功能已就绪。
install-models-summary-failed = provcheck：{ $count } 个模型安装失败（详见上方信息）。

## 主验证流程：错误、提示和帮助信息。
require-attested-needs-identity = provcheck：--require-attested 需要配合 --bsky-handle、--did 或 --auto-identity 使用
trust-store-read-failed = provcheck：无法读取信任存储“{ $path }”：{ $err }
auto-identity-no-assertion = provcheck：已请求 --auto-identity，但该文件不包含 app.provcheck.identity 断言。请先使用 `provcheck-kit sign --embed-identity` 进行签名，或直接传入 --bsky-handle / --did。
backfire-needs-key = provcheck：--backfire-read 需要配合 --backfire-key 使用
backfire-experimental-notice = provcheck：Backfire 为实验性功能，采用 BUSL 许可（非商业用途免费），独立于 Apache-2.0 核心代码。它用于验证你所嵌入的密钥标记，并标记出带阻陷波篡改；其鲁棒性因图像而异。
backfire-read-failed = provcheck：backfire 读取失败：{ $err }
mellin-needs-args = provcheck：--mellin-read 需要配合 --mellin-secret-file 和 --mellin-work-id 使用
mellin-experimental-notice = provcheck：Mellin 为实验性功能，采用 BUSL 许可（非商业用途免费），独立于 Apache-2.0 核心代码。它用于读取你所嵌入的按副本加密序列号；若没有你的密钥文件和作品 ID，将无法读取任何内容。
mellin-read-failed = provcheck：mellin 读取失败：{ $err }
json-serialize-failed = provcheck：JSON 序列化失败：{ $err }
hint-models-missing = [提示] 有 { $count } 个水印检测模型尚未安装，因此相应行显示为“未安装”。可通过以下命令启用全部检测功能：  provcheck --install-models  （一次性操作，{ $mb } MB）。C2PA 验证不依赖这些模型。
hint-claims-identity = [提示] 该文件声称的身份为 { $who }。请使用 --auto-identity 重新运行，以对照其公开发布的签名密钥记录进行验证。
