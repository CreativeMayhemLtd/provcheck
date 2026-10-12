# ข้อความ GUI ของ provcheck-app ภาษาไทย เฉพาะประโยคที่สมบูรณ์และหันหน้าเข้าหาผู้ใช้ที่ส่งกลับไปยัง
# GUI เป็นข้อความ ApiResult ok/err เท่านั้นที่แปลที่นี่; การวินิจฉัยทางเทคนิค { $err }/log-path และ
# ป้ายกำกับข้อผิดพลาด IPC ยังคงเป็นภาษาอังกฤษ คำศัพท์แบรนด์และเทคนิค (provcheck, provcheck-kit,
# Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags,
# ชื่อไฟล์) คงเดิมในทุกภาษา

## แท็บภาพลายน้ำแบบมีคีย์ของ Backfire (backfire_read + install_backfire).
backfire-read-needs-key = ต้องใช้คีย์ในการอ่านเครื่องหมาย Backfire
backfire-folder-unresolved = ไม่สามารถหาโฟลเดอร์ Backfire ที่เขียนได้ (LOCALAPPDATA ไม่ได้ตั้งค่า)
backfire-ready-bundled = Backfire พร้อมใช้งานแล้ว (มีตัวอ่านที่มาพร้อมแล้ว) ใส่คีย์แล้ววางภาพ
backfire-files-missing = ไม่พบไฟล์ Backfire สำหรับติดตั้ง ติดตั้ง provcheck ใหม่ หรือตั้งค่า BACKFIRE_PY
backfire-ready = Backfire พร้อมใช้งานแล้ว ใส่คีย์แล้ววางภาพ

## แท็บเครื่องหมายแบบมีคีย์ของ Mellin (mellin_read).
mellin-needs-secret-and-work-id = ต้องใช้ไฟล์ลับและ work id ในการอ่านซีเรียล Mellin
mellin-secret-file-missing = ไม่พบไฟล์ลับที่เลือก (หรืออ่านไม่ได้)

## แท็บ Sign + Keys: การแจ้งเตือนขีดจำกัดความสามารถของ GUI ที่ส่งกลับเป็นข้อผิดพลาด ApiResult
identity-already-exists = มีตัวตนอยู่แล้วในไดเรกทอรีข้อมูลนี้; ส่ง force=true เพื่อสร้างใหม่ (การทำเช่นนี้จะทำให้บันทึก atproto ที่เผยแพร่ไว้ก่อนหน้านี้กลายเป็นบันทึกกำพร้า)
rotate-yubikey-unsupported = การหมุนเวียนตัวตนที่ใช้ Yubikey ผ่าน GUI ยังไม่รองรับ รันคำสั่ง `provcheck-kit init --yubikey --force` จากเทอร์มินัล จากนั้นกลับมาที่นี่เพื่อเผยแพร่และเพิกถอน
rotate-agefile-unsupported = การหมุนเวียนตัวตนที่ใช้ age-file ผ่าน GUI ยังไม่ได้เชื่อมต่อ ใช้ `provcheck-kit rotate` จากเทอร์มินัล
sign-keychain-only = การลงนามผ่าน GUI ในขณะนี้รองรับเฉพาะตัวตนแบบ OS-keychain เท่านั้น ใช้ `provcheck-kit sign` จาก CLI สำหรับตัวตนแบบ age-file
sign-yubikey-unsupported = การลงนามผ่าน GUI สำหรับตัวตนที่ใช้ Yubikey จะมาใน v0.5.0 P3 + P4 ในระหว่างนี้ ให้ลงนามผ่าน `provcheck-kit sign` จากเทอร์มินัล -- kit จะถามหา PIV PIN ทุกครั้งที่ลงนาม
