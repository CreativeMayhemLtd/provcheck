# Thông báo GUI của provcheck-app, tiếng Việt. Chỉ những câu hoàn chỉnh hướng tới người dùng
# được trả về GUI dưới dạng văn bản ApiResult ok/err mới được dịch ở đây; các chẩn đoán kỹ
# thuật { $err }/log-path và nhãn lỗi IPC vẫn giữ tiếng Anh. Các thuật ngữ thương hiệu và kỹ
# thuật (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY,
# Yubikey, PIV PIN, DID, flags, tên tệp) giữ nguyên trong mọi ngôn ngữ.

## Tab hình mờ ảnh có khóa của Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Cần một khóa để đọc dấu Backfire.
backfire-folder-unresolved = Không thể xác định thư mục Backfire có thể ghi (LOCALAPPDATA chưa được đặt).
backfire-ready-bundled = Backfire đã sẵn sàng (có sẵn trình đọc đi kèm). Nhập khóa và thả một ảnh vào.
backfire-files-missing = Không tìm thấy tệp Backfire để cài đặt. Cài đặt lại provcheck, hoặc đặt BACKFIRE_PY.
backfire-ready = Backfire đã sẵn sàng. Nhập khóa và thả một ảnh vào.

## Tab dấu có khóa của Mellin (mellin_read).
mellin-needs-secret-and-work-id = Cần một tệp secret và một work id để đọc serial Mellin.
mellin-secret-file-missing = Tệp secret đã chọn không tồn tại (hoặc không đọc được).

## Tab Sign + Keys: các thông báo giới hạn khả năng GUI trả về dưới dạng lỗi ApiResult.
identity-already-exists = danh tính đã tồn tại tại thư mục dữ liệu này; truyền force=true để tạo lại (thao tác này sẽ khiến mọi bản ghi atproto đã công bố trước đó trở thành mồ côi)
rotate-yubikey-unsupported = Xoay vòng danh tính dựa trên Yubikey qua GUI chưa được hỗ trợ. Chạy `provcheck-kit init --yubikey --force` từ terminal, sau đó quay lại đây để công bố + thu hồi.
rotate-agefile-unsupported = Xoay vòng danh tính dựa trên age-file qua GUI chưa được kết nối. Sử dụng `provcheck-kit rotate` từ terminal.
sign-keychain-only = Ký qua GUI hiện chỉ hỗ trợ danh tính dùng OS-keychain. Sử dụng `provcheck-kit sign` từ CLI cho danh tính dựa trên age-file.
sign-yubikey-unsupported = Ký qua GUI cho danh tính dựa trên Yubikey sẽ ra mắt ở v0.5.0 P3 + P4. Hiện tại, hãy ký qua `provcheck-kit sign` từ terminal -- kit sẽ yêu cầu PIV PIN cho mỗi chữ ký.
