# Đầu ra runtime của provcheck-cli, tiếng Việt. Chỉ đầu ra dễ đọc cho con người được dịch;
# đầu ra --json và mã thoát không bao giờ được bản địa hóa. Các placeholder { $name } được
# điền tại nơi gọi; giữ nguyên chúng trong bản dịch. Các thuật ngữ thương hiệu và kỹ thuật
# (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags, tên
# tệp) giữ nguyên trong mọi ngôn ngữ.

## Khối pháp y âm thanh có khóa của Mellin (print_mellin_human).
mellin-header = Mellin (thử nghiệm, số serial pháp y âm thanh có khóa):
mellin-serial-full = serial:   { $serial } (đã khôi phục đủ 64 bit, số phiếu bit tối thiểu { $votes })
mellin-serial-partial = serial:   chưa khôi phục đầy đủ ({ $bits }/64 bit, số phiếu bit tối thiểu { $votes })
mellin-erasures = xóa: { $pct }% số vị trí
mellin-expected-match = kỳ vọng: KHỚP
mellin-expected-no-match = kỳ vọng: KHÔNG KHỚP

## Khối hình mờ ảnh có khóa của Backfire (print_backfire_human).
backfire-header = Backfire (thử nghiệm, hình mờ ảnh có khóa):
backfire-mark-valid = dấu:   HỢP LỆ (id { $id }, biên độ { $margin })
backfire-mark-none = dấu:   không phát hiện (biên độ { $margin })
backfire-tamper-detected = giả mạo: PHÁT HIỆN BAND-NOTCH (thống kê { $stat }) -- ảnh rất có thể đã bị tấn công dạng notch
backfire-tamper-none = giả mạo: không có (thống kê band-notch { $stat })

## Thiết lập Backfire (--install-backfire).
backfire-folder-not-found = provcheck: không tìm thấy thư mục backfire. Đặt BACKFIRE_PY trỏ tới backfire.py, hoặc chạy từ thư mục chứa backfire/backfire.py.
backfire-ps1-not-found = provcheck: không tìm thấy setup_backfire.ps1 trong { $dir }
backfire-sh-not-found = provcheck: không tìm thấy setup_backfire.sh trong { $dir }
backfire-setup-start = Đang thiết lập môi trường đọc Backfire (một lần). Thao tác này sẽ tải về một bản Python độc lập.
backfire-setup-ready = Backfire đã sẵn sàng. Xác minh một ảnh đã đánh dấu bằng:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: thiết lập Backfire kết thúc với trạng thái { $status }
backfire-setup-run-failed = provcheck: không thể chạy script thiết lập Backfire ({ $err }). Cần PowerShell trên Windows, hoặc bash trên Linux/macOS.

## Cài đặt mô hình (--install-models).
install-models-start = Đang cài đặt { $count } tệp mô hình phát hiện hình mờ (tổng { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = THẤT BẠI: { $err }
install-models-done = Đã cài đặt tất cả mô hình. Tính năng phát hiện hình mờ đã sẵn sàng.
install-models-summary-failed = provcheck: { $count } mô hình cài đặt thất bại (xem ở trên).

## Đường dẫn xác minh chính: lỗi, thông báo, và gợi ý.
require-attested-needs-identity = provcheck: --require-attested cần --bsky-handle, --did, hoặc --auto-identity
trust-store-read-failed = provcheck: không thể đọc trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity đã được yêu cầu nhưng tệp này không mang assertion app.provcheck.identity nào. Hãy ký trước bằng `provcheck-kit sign --embed-identity`, hoặc truyền trực tiếp --bsky-handle / --did.
backfire-needs-key = provcheck: --backfire-read cần --backfire-key
backfire-experimental-notice = provcheck: Backfire là THỬ NGHIỆM và cấp phép theo BUSL (miễn phí cho mục đích phi thương mại), tách biệt khỏi lõi Apache-2.0. Nó xác minh một dấu có khóa mà bạn đã nhúng, và gắn cờ giả mạo band-notch; độ bền vững tùy theo từng ảnh.
backfire-read-failed = provcheck: đọc backfire thất bại: { $err }
mellin-needs-args = provcheck: --mellin-read cần --mellin-secret-file và --mellin-work-id
mellin-experimental-notice = provcheck: Mellin là THỬ NGHIỆM và cấp phép theo BUSL (miễn phí cho mục đích phi thương mại), tách biệt khỏi lõi Apache-2.0. Nó đọc một serial có khóa theo từng bản sao mà bạn đã nhúng; nếu không có secret và work id của bạn thì không có gì để đọc.
mellin-read-failed = provcheck: đọc mellin thất bại: { $err }
json-serialize-failed = provcheck: không thể chuyển đổi JSON: { $err }
hint-models-missing = [hint] { $count } mô hình phát hiện hình mờ chưa được cài đặt, vì vậy các dòng đó hiển thị "not installed". Bật toàn bộ tính năng phát hiện bằng:  provcheck --install-models  (một lần, { $mb } MB). Xác minh C2PA không cần đến chúng.
hint-claims-identity = [hint] tệp khai báo danh tính { $who }. Chạy lại với --auto-identity để xác minh với các bản ghi khóa ký đã công bố của họ.
