# Keluaran runtime provcheck-cli, Bahasa Indonesia. Hanya keluaran yang dapat dibaca manusia
# yang dilokalkan; keluaran --json dan kode keluar tidak pernah dilokalkan. Placeholder
# { $name } diisi di titik pemanggilan; biarkan tetap utuh dalam terjemahan. Istilah merek
# dan teknis (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash,
# flags, nama file) tetap apa adanya di setiap bahasa.

## Blok forensik audio berkunci Mellin (print_mellin_human).
mellin-header = Mellin (eksperimental, serial forensik audio berkunci):
mellin-serial-full = serial:   { $serial } (semua 64 bit berhasil dipulihkan, suara bit minimum { $votes })
mellin-serial-partial = serial:   belum sepenuhnya dipulihkan ({ $bits }/64 bit, suara bit minimum { $votes })
mellin-erasures = penghapusan: { $pct }% dari posisi
mellin-expected-match = diharapkan: COCOK
mellin-expected-no-match = diharapkan: TIDAK COCOK

## Blok watermark gambar berkunci Backfire (print_backfire_human).
backfire-header = Backfire (eksperimental, watermark gambar berkunci):
backfire-mark-valid = tanda:   VALID (id { $id }, margin { $margin })
backfire-mark-none = tanda:   tidak terdeteksi (margin { $margin })
backfire-tamper-detected = pengubahan: BAND-NOTCH TERDETEKSI (statistik { $stat }) -- gambar ini sangat mungkin telah diserang dengan notch
backfire-tamper-none = pengubahan: tidak ada (statistik band-notch { $stat })

## Penyiapan Backfire (--install-backfire).
backfire-folder-not-found = provcheck: tidak dapat menemukan folder backfire. Atur BACKFIRE_PY ke backfire.py, atau jalankan dari direktori yang berisi backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 tidak ditemukan di { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh tidak ditemukan di { $dir }
backfire-setup-start = Menyiapkan lingkungan baca Backfire (satu kali). Ini akan mengunduh Python mandiri.
backfire-setup-ready = Backfire sudah siap. Verifikasi gambar bertanda dengan:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: penyiapan Backfire berakhir dengan status { $status }
backfire-setup-run-failed = provcheck: tidak dapat menjalankan skrip penyiapan Backfire ({ $err }). Diperlukan PowerShell di Windows, atau bash di Linux/macOS.

## Instalasi model (--install-models).
install-models-start = Menginstal { $count } berkas model deteksi watermark (total { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = GAGAL: { $err }
install-models-done = Semua model terinstal. Deteksi watermark sudah siap.
install-models-summary-failed = provcheck: { $count } model gagal terinstal (lihat di atas).

## Jalur verifikasi utama: kesalahan, pemberitahuan, dan petunjuk.
require-attested-needs-identity = provcheck: --require-attested memerlukan --bsky-handle, --did, atau --auto-identity
trust-store-read-failed = provcheck: tidak dapat membaca trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity diminta tetapi berkas ini tidak memiliki assertion app.provcheck.identity. Tanda tangani dulu dengan `provcheck-kit sign --embed-identity`, atau berikan --bsky-handle / --did secara langsung.
backfire-needs-key = provcheck: --backfire-read memerlukan --backfire-key
backfire-experimental-notice = provcheck: Backfire bersifat EKSPERIMENTAL dan berlisensi BUSL (gratis untuk penggunaan non-komersial), terpisah dari inti Apache-2.0. Ini memverifikasi tanda berkunci yang Anda sematkan, dan menandai pengubahan band-notch; ketahanan bergantung pada masing-masing gambar.
backfire-read-failed = provcheck: pembacaan backfire gagal: { $err }
mellin-needs-args = provcheck: --mellin-read memerlukan --mellin-secret-file dan --mellin-work-id
mellin-experimental-notice = provcheck: Mellin bersifat EKSPERIMENTAL dan berlisensi BUSL (gratis untuk penggunaan non-komersial), terpisah dari inti Apache-2.0. Ini membaca serial berkunci per salinan yang Anda sematkan; tanpa secret dan work id Anda, tidak ada yang bisa dibaca.
mellin-read-failed = provcheck: pembacaan mellin gagal: { $err }
json-serialize-failed = provcheck: gagal melakukan serialisasi JSON: { $err }
hint-models-missing = [hint] { $count } model deteksi watermark belum terinstal, sehingga baris-baris tersebut menampilkan "not installed". Aktifkan semua deteksi dengan:  provcheck --install-models  (satu kali, { $mb } MB). Verifikasi C2PA tidak memerlukannya.
hint-claims-identity = [hint] berkas ini mengklaim identitas { $who }. Jalankan ulang dengan --auto-identity untuk memverifikasi terhadap catatan kunci penandatanganan yang dipublikasikan mereka.
