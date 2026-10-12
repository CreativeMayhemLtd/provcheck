# Pesan GUI provcheck-app, Bahasa Indonesia. Hanya kalimat lengkap yang menghadap pengguna
# yang dikembalikan ke GUI sebagai teks ApiResult ok/err yang dilokalkan di sini; diagnostik
# teknis { $err }/log-path dan label kesalahan IPC tetap dalam Bahasa Inggris. Istilah merek
# dan teknis (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, nama file) tetap apa adanya di setiap bahasa.

## Tab gambar berkunci Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Diperlukan kunci untuk membaca tanda Backfire.
backfire-folder-unresolved = Tidak dapat menemukan folder Backfire yang dapat ditulis (LOCALAPPDATA tidak diatur).
backfire-ready-bundled = Backfire sudah siap (pembaca bawaan tersedia). Masukkan kunci dan seret gambar.
backfire-files-missing = Berkas Backfire untuk instalasi tidak ditemukan. Instal ulang provcheck, atau atur BACKFIRE_PY.
backfire-ready = Backfire sudah siap. Masukkan kunci dan seret gambar.

## Tab tanda berkunci Mellin (mellin_read).
mellin-needs-secret-and-work-id = Diperlukan berkas secret dan work id untuk membaca serial Mellin.
mellin-secret-file-missing = Berkas secret yang dipilih tidak ada (atau tidak dapat dibaca).

## Tab Sign + Keys: pemberitahuan batas kemampuan GUI yang dikembalikan sebagai kesalahan ApiResult.
identity-already-exists = identitas sudah ada di direktori data ini; sertakan force=true untuk membuatnya ulang (ini akan membuat semua catatan atproto yang telah dipublikasikan sebelumnya menjadi yatim)
rotate-yubikey-unsupported = Rotasi GUI untuk identitas berbasis Yubikey belum didukung. Jalankan `provcheck-kit init --yubikey --force` dari terminal, lalu kembali ke sini untuk mempublikasikan + mencabut.
rotate-agefile-unsupported = Rotasi GUI untuk identitas berbasis age-file belum terhubung. Gunakan `provcheck-kit rotate` dari terminal.
sign-keychain-only = Penandatanganan GUI saat ini hanya mendukung identitas OS-keychain. Gunakan `provcheck-kit sign` dari CLI untuk identitas berbasis age-file.
sign-yubikey-unsupported = Penandatanganan GUI untuk identitas berbasis Yubikey akan hadir di v0.5.0 P3 + P4. Untuk saat ini, tanda tangani melalui `provcheck-kit sign` dari terminal -- kit akan meminta PIV PIN pada setiap tanda tangan.
