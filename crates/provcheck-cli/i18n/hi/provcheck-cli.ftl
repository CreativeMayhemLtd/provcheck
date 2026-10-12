# provcheck-cli रनटाइम आउटपुट, हिन्दी। केवल मानव-पठनीय आउटपुट लोकलाइज़ किया गया है; --json आउटपुट
# और एग्ज़िट कोड कभी लोकलाइज़ नहीं होते। प्लेसहोल्डर { $name } कॉल साइट पर भरे जाते हैं;
# अनुवाद में इन्हें अपरिवर्तित रखें। ब्रांड और तकनीकी शब्द (provcheck, C2PA, Backfire, Mellin,
# BUSL, Apache-2.0, JSON, PowerShell, bash, flags, फ़ाइल नाम) हर भाषा में ज्यों के त्यों रहते हैं।

## Mellin की-युक्त ऑडियो फोरेंसिक ब्लॉक (print_mellin_human).
mellin-header = Mellin (प्रायोगिक, की-युक्त ऑडियो फोरेंसिक सीरियल):
mellin-serial-full = सीरियल:   { $serial } (सभी 64 बिट्स पुनर्प्राप्त, न्यूनतम बिट वोट { $votes })
mellin-serial-partial = सीरियल:   पूरी तरह पुनर्प्राप्त नहीं हुआ ({ $bits }/64 बिट्स, न्यूनतम बिट वोट { $votes })
mellin-erasures = इरेज़र: पोज़िशनों का { $pct }%
mellin-expected-match = अपेक्षित: मेल
mellin-expected-no-match = अपेक्षित: मेल नहीं

## Backfire की-युक्त इमेज वॉटरमार्क ब्लॉक (print_backfire_human).
backfire-header = Backfire (प्रायोगिक, की-युक्त इमेज वॉटरमार्क):
backfire-mark-valid = मार्क:   मान्य (id { $id }, मार्जिन { $margin })
backfire-mark-none = मार्क:   नहीं मिला (मार्जिन { $margin })
backfire-tamper-detected = छेड़छाड़: बैंड-नॉच पाई गई (स्टैट { $stat }) -- इमेज पर बहुत संभावना है कि नॉच-अटैक हुआ है
backfire-tamper-none = छेड़छाड़: कोई नहीं (बैंड-नॉच स्टैट { $stat })

## Backfire सेटअप (--install-backfire).
backfire-folder-not-found = provcheck: backfire फ़ोल्डर नहीं मिला। BACKFIRE_PY को backfire.py पर सेट करें, या backfire/backfire.py वाली डायरेक्टरी से चलाएँ।
backfire-ps1-not-found = provcheck: setup_backfire.ps1 { $dir } में नहीं मिली
backfire-sh-not-found = provcheck: setup_backfire.sh { $dir } में नहीं मिली
backfire-setup-start = Backfire रीड एनवायरनमेंट सेट किया जा रहा है (एक बार)। इससे एक स्व-निहित Python डाउनलोड होगा।
backfire-setup-ready = Backfire तैयार है। मार्क की गई इमेज को इससे वेरिफ़ाई करें:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire सेटअप स्टेटस { $status } के साथ समाप्त हुआ
backfire-setup-run-failed = provcheck: Backfire सेटअप स्क्रिप्ट नहीं चलाई जा सकी ({ $err })। Windows पर PowerShell, या Linux/macOS पर bash चाहिए।

## मॉडल इंस्टॉल (--install-models).
install-models-start = { $count } वॉटरमार्क-डिटेक्शन मॉडल फ़ाइल(एँ) इंस्टॉल की जा रही हैं (कुल { $mb } MB)।
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ठीक
install-models-item-failed = विफल: { $err }
install-models-done = सभी मॉडल इंस्टॉल हो गए। वॉटरमार्क डिटेक्शन तैयार है।
install-models-summary-failed = provcheck: { $count } मॉडल इंस्टॉल नहीं हो सके (ऊपर देखें)।

## मुख्य वेरिफ़ाई पथ: त्रुटियाँ, सूचनाएँ, और संकेत।
require-attested-needs-identity = provcheck: --require-attested के लिए --bsky-handle, --did, या --auto-identity चाहिए
trust-store-read-failed = provcheck: ट्रस्ट स्टोर '{ $path }' नहीं पढ़ी जा सकी: { $err }
auto-identity-no-assertion = provcheck: --auto-identity का अनुरोध किया गया था, लेकिन फ़ाइल में कोई app.provcheck.identity एसर्शन नहीं है। पहले `provcheck-kit sign --embed-identity` से साइन करें, या सीधे --bsky-handle / --did दें।
backfire-needs-key = provcheck: --backfire-read के लिए --backfire-key चाहिए
backfire-experimental-notice = provcheck: Backfire प्रायोगिक है और BUSL-लाइसेंस्ड है (गैर-व्यावसायिक उपयोग के लिए निःशुल्क), Apache-2.0 कोर से अलग। यह आपके द्वारा एम्बेड की गई की-युक्त मार्क को वेरिफ़ाई करता है और बैंड-नॉच छेड़छाड़ को फ़्लैग करता है; रोबस्टनेस हर इमेज पर निर्भर है।
backfire-read-failed = provcheck: backfire रीड विफल: { $err }
mellin-needs-args = provcheck: --mellin-read के लिए --mellin-secret-file और --mellin-work-id चाहिए
mellin-experimental-notice = provcheck: Mellin प्रायोगिक है और BUSL-लाइसेंस्ड है (गैर-व्यावसायिक उपयोग के लिए निःशुल्क), Apache-2.0 कोर से अलग। यह आपके द्वारा एम्बेड की गई प्रति-कॉपी की-युक्त सीरियल को पढ़ता है; आपके सीक्रेट और work id के बिना पढ़ने के लिए कुछ नहीं है।
mellin-read-failed = provcheck: mellin रीड विफल: { $err }
json-serialize-failed = provcheck: JSON सीरियलाइज़ नहीं हो सका: { $err }
hint-models-missing = [hint] { $count } वॉटरमार्क-डिटेक्शन मॉडल इंस्टॉल नहीं हैं, इसलिए वे लाइनें "not installed" दिखाती हैं। पूरी डिटेक्शन सक्षम करें:  provcheck --install-models  (एक बार, { $mb } MB)। C2PA वेरिफ़िकेशन को इनकी ज़रूरत नहीं है।
hint-claims-identity = [hint] फ़ाइल पहचान { $who } का दावा करती है। उनके प्रकाशित साइनिंग-की रिकॉर्ड के विरुद्ध वेरिफ़ाई करने के लिए --auto-identity के साथ फिर से चलाएँ।
