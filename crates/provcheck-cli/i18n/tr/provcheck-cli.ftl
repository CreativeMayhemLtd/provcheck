# provcheck-cli çalışma zamanı çıktısı, Türkçe (kaynak: İngilizce). Yalnızca insan tarafından
# okunabilir çıktı; --json çıktısı ve çıkış kodları hiçbir zaman yerelleştirilmez. { $name }
# yer tutucuları çağrı noktalarında doldurulur; çevirilerde olduğu gibi bırakın. Marka ve
# teknik terimler (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell,
# bash, flags, dosya adları) her dilde olduğu gibi kalır.

## Mellin anahtarlı ses adli blok (print_mellin_human).
mellin-header = Mellin (deneysel, anahtarlı ses adli seri numarası):
mellin-serial-full = seri:   { $serial } (64 bitin tümü kurtarıldı, minimum bit oyu { $votes })
mellin-serial-partial = seri:   tam olarak kurtarılamadı ({ $bits }/64 bit, minimum bit oyu { $votes })
mellin-erasures = silinmeler: pozisyonların %{ $pct }'i
mellin-expected-match = beklenen: EŞLEŞME
mellin-expected-no-match = beklenen: EŞLEŞME YOK

## Backfire anahtarlı görüntü filigranı bloğu (print_backfire_human).
backfire-header = Backfire (deneysel, anahtarlı görüntü filigranı):
backfire-mark-valid = işaret:   GEÇERLİ (id { $id }, marj { $margin })
backfire-mark-none = işaret:   algılanmadı (marj { $margin })
backfire-tamper-detected = kurcalama: BANT ÇENTİĞİ ALGILANDI (istatistik { $stat }) -- görüntüye büyük olasılıkla çentik saldırısı yapılmış
backfire-tamper-none = kurcalama: yok (bant çentiği istatistiği { $stat })

## Backfire kurulumu (--install-backfire).
backfire-folder-not-found = provcheck: backfire klasörü bulunamadı. BACKFIRE_PY'yi backfire.py'ye ayarlayın veya backfire/backfire.py içeren bir dizinden çalıştırın.
backfire-ps1-not-found = provcheck: setup_backfire.ps1, { $dir } içinde bulunamadı
backfire-sh-not-found = provcheck: setup_backfire.sh, { $dir } içinde bulunamadı
backfire-setup-start = Backfire okuma ortamı kuruluyor (tek seferlik). Bu, kendi kendine yeten bir Python indirir.
backfire-setup-ready = Backfire hazır. İşaretlenmiş bir görüntüyü şununla doğrulayın:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire kurulumu { $status } durumuyla sona erdi
backfire-setup-run-failed = provcheck: Backfire kurulum betiği çalıştırılamadı ({ $err }). Windows'ta PowerShell, Linux/macOS'ta bash gerektirir.

## Model kurulumu (--install-models).
install-models-start = { $count } filigran algılama model dosyası kuruluyor (toplam { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = tamam
install-models-item-failed = BAŞARISIZ: { $err }
install-models-done = Tüm modeller kuruldu. Filigran algılama hazır.
install-models-summary-failed = provcheck: { $count } model kurulamadı (yukarıya bakın).

## Ana doğrulama yolu: hatalar, bildirimler ve ipuçları.
require-attested-needs-identity = provcheck: --require-attested, --bsky-handle, --did veya --auto-identity gerektirir
trust-store-read-failed = provcheck: güven deposu '{ $path }' okunamadı: { $err }
auto-identity-no-assertion = provcheck: --auto-identity istendi ancak dosya bir app.provcheck.identity iddiası içermiyor. Önce `provcheck-kit sign --embed-identity` ile imzalayın veya doğrudan --bsky-handle / --did geçirin.
backfire-needs-key = provcheck: --backfire-read, --backfire-key gerektirir
backfire-experimental-notice = provcheck: Backfire DENEYSELdir ve BUSL lisanslıdır (ticari olmayan kullanım için ücretsiz), Apache-2.0 çekirdeğinden ayrıdır. Gömdüğünüz anahtarlı işareti doğrular ve bant çentiği kurcalamasını bildirir; sağlamlık görüntüye göre değişir.
backfire-read-failed = provcheck: backfire okuma başarısız oldu: { $err }
mellin-needs-args = provcheck: --mellin-read, --mellin-secret-file ve --mellin-work-id gerektirir
mellin-experimental-notice = provcheck: Mellin DENEYSELdir ve BUSL lisanslıdır (ticari olmayan kullanım için ücretsiz), Apache-2.0 çekirdeğinden ayrıdır. Gömdüğünüz kopya başına anahtarlı seri numarasını okur; gizli anahtarınız ve iş kimliğiniz olmadan okunacak bir şey yoktur.
mellin-read-failed = provcheck: mellin okuma başarısız oldu: { $err }
json-serialize-failed = provcheck: JSON serileştirilemedi: { $err }
hint-models-missing = [ipucu] { $count } filigran algılama modeli kurulu değil, bu yüzden bu satırlar "not installed" gösterir. Tüm algılamayı şununla etkinleştirin:  provcheck --install-models  (tek seferlik, { $mb } MB). C2PA doğrulaması bunlara ihtiyaç duymaz.
hint-claims-identity = [ipucu] dosya { $who } kimliğini iddia ediyor. Yayınlanmış imzalama anahtarı kayıtlarına göre doğrulamak için --auto-identity ile yeniden çalıştırın.
