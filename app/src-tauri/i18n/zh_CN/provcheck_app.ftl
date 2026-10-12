# provcheck-app 图形界面消息，简体中文译文（源文本为英文）。仅将作为 ApiResult ok/err 文本
# 返回给图形界面的完整面向用户的句子在此本地化；技术性的
# { $err }/日志路径诊断信息以及 IPC 错误标签保持英文。品牌与技术性
# 字面量（provcheck、provcheck-kit、Backfire、Mellin、C2PA、atproto、LOCALAPPDATA、
# BACKFIRE_PY、Yubikey、PIV PIN、DID、flags、文件名）在所有语言环境中均保持原文不译。

## Backfire 密钥图像标签页（backfire_read + install_backfire）。
backfire-read-needs-key = 读取 Backfire 标记需要提供密钥。
backfire-folder-unresolved = 无法解析出可写的 Backfire 文件夹（LOCALAPPDATA 未设置）。
backfire-ready-bundled = Backfire 已就绪（内置读取器已存在）。请输入密钥并拖入图像。
backfire-files-missing = 未找到可供安装的 Backfire 文件。请重新安装 provcheck，或设置 BACKFIRE_PY。
backfire-ready = Backfire 已就绪。请输入密钥并拖入图像。

## Mellin 密钥标记标签页（mellin_read）。
mellin-needs-secret-and-work-id = 读取 Mellin 序列号需要提供密钥文件和作品 ID。
mellin-secret-file-missing = 所选密钥文件不存在（或不可读）。

## 签名和密钥标签页：以 ApiResult 错误形式返回的图形界面功能限制提示。
identity-already-exists = 该数据目录下已存在身份；如需重新生成，请传入 force=true（这将使此前已发布的 atproto 记录成为孤立记录）
rotate-yubikey-unsupported = 图形界面尚不支持轮换基于 Yubikey 的身份。请在终端中运行 `provcheck-kit init --yubikey --force`，然后返回此处进行发布和吊销操作。
rotate-agefile-unsupported = 图形界面尚未支持轮换基于 age 密钥文件的身份。请在终端中使用 `provcheck-kit rotate`。
sign-keychain-only = 图形界面签名目前仅支持基于操作系统密钥链的身份。对于基于 age 密钥文件的身份，请在命令行中使用 `provcheck-kit sign`。
sign-yubikey-unsupported = 图形界面对基于 Yubikey 的身份签名将在 v0.5.0 的 P3 和 P4 阶段推出。目前请在终端中通过 `provcheck-kit sign` 进行签名，该工具会在每次签名时提示输入 PIV PIN。
