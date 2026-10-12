# provcheck-app GUI mesajları, Türkçe (kaynak: İngilizce). Yalnızca GUI'ye ApiResult ok/err
# metni olarak dönen tam kullanıcıya yönelik cümleler burada yerelleştirilir; teknik
# { $err }/günlük yolu tanılamaları ve IPC hata etiketleri İngilizce kalır. Marka ve teknik
# terimler (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, dosya adları) her dilde olduğu gibi kalır.

## Backfire anahtarlı görüntü sekmesi (backfire_read + install_backfire).
backfire-read-needs-key = Bir Backfire işaretini okumak için anahtar gereklidir.
backfire-folder-unresolved = Yazılabilir bir Backfire klasörü çözümlenemedi (LOCALAPPDATA ayarlanmamış).
backfire-ready-bundled = Backfire hazır (paketlenmiş okuyucu mevcut). Bir anahtar girin ve bir görüntü bırakın.
backfire-files-missing = Kurulacak Backfire dosyaları bulunamadı. provcheck'i yeniden kurun veya BACKFIRE_PY ayarlayın.
backfire-ready = Backfire hazır. Bir anahtar girin ve bir görüntü bırakın.

## Mellin anahtarlı işaretler sekmesi (mellin_read).
mellin-needs-secret-and-work-id = Bir Mellin seri numarasını okumak için bir gizli dosya ve bir iş kimliği gereklidir.
mellin-secret-file-missing = Seçilen gizli dosya mevcut değil (veya okunabilir değil).

## İmzala + Anahtarlar sekmeleri: ApiResult hataları olarak dönen GUI yetenek sınırı bildirimleri.
identity-already-exists = bu veri dizininde zaten bir kimlik mevcut; yeniden oluşturmak için force=true geçirin (bu, önceden yayınlanmış tüm atproto kayıtlarını yetim bırakır)
rotate-yubikey-unsupported = Yubikey destekli bir kimliğin GUI'den döndürülmesi henüz desteklenmiyor. Bir terminalden `provcheck-kit init --yubikey --force` çalıştırın, ardından yayınlamak ve iptal etmek için buraya geri dönün.
rotate-agefile-unsupported = age-dosyası destekli kimliklerin GUI'den döndürülmesi henüz bağlanmadı. Bir terminalden `provcheck-kit rotate` kullanın.
sign-keychain-only = GUI imzalama şu anda yalnızca işletim sistemi anahtarlığı kimliklerini destekler. age-dosyası kimlikleri için CLI'den `provcheck-kit sign` kullanın.
sign-yubikey-unsupported = Yubikey destekli kimliklerin GUI imzalaması v0.5.0 P3 + P4'te geliyor. Şimdilik bir terminalden `provcheck-kit sign` ile imzalayın; kit her imza için PIV PIN'i sorar.
