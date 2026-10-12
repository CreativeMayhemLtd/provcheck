# เอาต์พุตรันไทม์ของ provcheck-cli ภาษาไทย เฉพาะเอาต์พุตที่มนุษย์อ่านได้เท่านั้นที่แปล; เอาต์พุต
# --json และรหัสออกจะไม่ถูกแปลเป็นภาษาท้องถิ่น ตัวยึดตำแหน่ง { $name } จะถูกเติมที่จุดเรียกใช้งาน;
# คงไว้ในคำแปลโดยไม่เปลี่ยนแปลง คำศัพท์แบรนด์และเทคนิค (provcheck, C2PA, Backfire, Mellin,
# BUSL, Apache-2.0, JSON, PowerShell, bash, flags, ชื่อไฟล์) คงเดิมในทุกภาษา

## บล็อกซีเรียลนิติวิทยาศาสตร์เสียงแบบมีคีย์ของ Mellin (print_mellin_human).
mellin-header = Mellin (ทดลอง, ซีเรียลนิติวิทยาศาสตร์เสียงแบบมีคีย์):
mellin-serial-full = ซีเรียล:   { $serial } (กู้คืนครบทั้ง 64 บิต, คะแนนโหวตบิตต่ำสุด { $votes })
mellin-serial-partial = ซีเรียล:   กู้คืนไม่ครบ ({ $bits }/64 บิต, คะแนนโหวตบิตต่ำสุด { $votes })
mellin-erasures = การลบ: { $pct }% ของตำแหน่ง
mellin-expected-match = คาดหวัง: ตรงกัน
mellin-expected-no-match = คาดหวัง: ไม่ตรงกัน

## บล็อกลายน้ำภาพแบบมีคีย์ของ Backfire (print_backfire_human).
backfire-header = Backfire (ทดลอง, ลายน้ำภาพแบบมีคีย์):
backfire-mark-valid = เครื่องหมาย:   ถูกต้อง (id { $id }, มาร์จิ้น { $margin })
backfire-mark-none = เครื่องหมาย:   ไม่พบ (มาร์จิ้น { $margin })
backfire-tamper-detected = การปลอมแปลง: ตรวจพบ BAND-NOTCH (สถิติ { $stat }) -- มีความเป็นไปได้สูงว่าภาพถูกโจมตีด้วย notch
backfire-tamper-none = การปลอมแปลง: ไม่มี (สถิติ band-notch { $stat })

## การตั้งค่า Backfire (--install-backfire).
backfire-folder-not-found = provcheck: ไม่พบโฟลเดอร์ backfire ตั้งค่า BACKFIRE_PY ให้ชี้ไปที่ backfire.py หรือรันจากไดเรกทอรีที่มี backfire/backfire.py
backfire-ps1-not-found = provcheck: ไม่พบ setup_backfire.ps1 ใน { $dir }
backfire-sh-not-found = provcheck: ไม่พบ setup_backfire.sh ใน { $dir }
backfire-setup-start = กำลังตั้งค่าสภาพแวดล้อมอ่าน Backfire (ครั้งเดียว) ขั้นตอนนี้จะดาวน์โหลด Python แบบสมบูรณ์ในตัว
backfire-setup-ready = Backfire พร้อมใช้งานแล้ว ตรวจสอบภาพที่มีเครื่องหมายด้วย:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: การตั้งค่า Backfire สิ้นสุดด้วยสถานะ { $status }
backfire-setup-run-failed = provcheck: ไม่สามารถรันสคริปต์ตั้งค่า Backfire ได้ ({ $err }) ต้องใช้ PowerShell บน Windows หรือ bash บน Linux/macOS

## การติดตั้งโมเดล (--install-models).
install-models-start = กำลังติดตั้งไฟล์โมเดลตรวจจับลายน้ำ { $count } ไฟล์ (รวม { $mb } MB)
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = สำเร็จ
install-models-item-failed = ล้มเหลว: { $err }
install-models-done = ติดตั้งโมเดลทั้งหมดแล้ว การตรวจจับลายน้ำพร้อมใช้งาน
install-models-summary-failed = provcheck: โมเดล { $count } รายการติดตั้งไม่สำเร็จ (ดูด้านบน)

## เส้นทางการตรวจสอบหลัก: ข้อผิดพลาด การแจ้งเตือน และคำแนะนำ
require-attested-needs-identity = provcheck: --require-attested ต้องใช้ --bsky-handle, --did หรือ --auto-identity
trust-store-read-failed = provcheck: ไม่สามารถอ่าน trust store '{ $path }' ได้: { $err }
auto-identity-no-assertion = provcheck: มีการร้องขอ --auto-identity แต่ไฟล์นี้ไม่มี assertion app.provcheck.identity ให้เซ็นด้วย `provcheck-kit sign --embed-identity` ก่อน หรือระบุ --bsky-handle / --did โดยตรง
backfire-needs-key = provcheck: --backfire-read ต้องใช้ --backfire-key
backfire-experimental-notice = provcheck: Backfire เป็นฟีเจอร์ทดลองและอยู่ภายใต้ใบอนุญาต BUSL (ใช้ฟรีสำหรับการใช้งานที่ไม่ใช่เชิงพาณิชย์) แยกจากแกนหลัก Apache-2.0 มันตรวจสอบเครื่องหมายแบบมีคีย์ที่คุณฝังไว้ และแจ้งเตือนการปลอมแปลงแบบ band-notch; ความทนทานขึ้นอยู่กับแต่ละภาพ
backfire-read-failed = provcheck: การอ่าน backfire ล้มเหลว: { $err }
mellin-needs-args = provcheck: --mellin-read ต้องใช้ --mellin-secret-file และ --mellin-work-id
mellin-experimental-notice = provcheck: Mellin เป็นฟีเจอร์ทดลองและอยู่ภายใต้ใบอนุญาต BUSL (ใช้ฟรีสำหรับการใช้งานที่ไม่ใช่เชิงพาณิชย์) แยกจากแกนหลัก Apache-2.0 มันอ่านซีเรียลแบบมีคีย์ต่อสำเนาที่คุณฝังไว้; หากไม่มีคีย์ลับและ work id ของคุณ ก็ไม่มีอะไรให้อ่าน
mellin-read-failed = provcheck: การอ่าน mellin ล้มเหลว: { $err }
json-serialize-failed = provcheck: ไม่สามารถแปลง JSON เป็นข้อความได้: { $err }
hint-models-missing = [hint] โมเดลตรวจจับลายน้ำ { $count } รายการยังไม่ได้ติดตั้ง ดังนั้นบรรทัดเหล่านั้นจะแสดง "not installed" เปิดใช้งานการตรวจจับทั้งหมดด้วย:  provcheck --install-models  (ครั้งเดียว, { $mb } MB) การตรวจสอบ C2PA ไม่จำเป็นต้องใช้สิ่งเหล่านี้
hint-claims-identity = [hint] ไฟล์อ้างว่าเป็นตัวตน { $who } รันใหม่ด้วย --auto-identity เพื่อตรวจสอบกับบันทึกคีย์ลงนามที่เผยแพร่ของพวกเขา
