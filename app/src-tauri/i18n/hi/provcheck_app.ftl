# provcheck-app GUI संदेश, हिन्दी। केवल पूर्ण उपयोगकर्ता-फ़ेसिंग वाक्य जो ApiResult ok/err टेक्स्ट के
# रूप में GUI को वापस भेजे जाते हैं, यहाँ लोकलाइज़ किए गए हैं; तकनीकी { $err }/लॉग-पाथ डायग्नोस्टिक्स
# और IPC एरर लेबल अंग्रेज़ी में रहते हैं। ब्रांड और तकनीकी शब्द (provcheck, provcheck-kit, Backfire,
# Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, फ़ाइल नाम) हर
# भाषा में ज्यों के त्यों रहते हैं।

## Backfire की-युक्त इमेज टैब (backfire_read + install_backfire).
backfire-read-needs-key = Backfire मार्क पढ़ने के लिए एक की चाहिए।
backfire-folder-unresolved = कोई लिखने-योग्य Backfire फ़ोल्डर नहीं मिला (LOCALAPPDATA सेट नहीं है)।
backfire-ready-bundled = Backfire तैयार है (बंडल्ड रीडर मौजूद है)। एक की डालें और इमेज ड्रॉप करें।
backfire-files-missing = इंस्टॉल के लिए Backfire फ़ाइलें नहीं मिलीं। provcheck फिर से इंस्टॉल करें, या BACKFIRE_PY सेट करें।
backfire-ready = Backfire तैयार है। एक की डालें और इमेज ड्रॉप करें।

## Mellin की-युक्त मार्क्स टैब (mellin_read).
mellin-needs-secret-and-work-id = Mellin सीरियल पढ़ने के लिए एक सीक्रेट फ़ाइल और एक work id चाहिए।
mellin-secret-file-missing = चुनी गई सीक्रेट फ़ाइल मौजूद नहीं है (या पढ़ी नहीं जा सकती)।

## Sign + Keys टैब: GUI क्षमता-सीमा सूचनाएँ जो ApiResult त्रुटियों के रूप में वापस जाती हैं।
identity-already-exists = इस डेटा डायरेक्टरी में पहले से एक पहचान मौजूद है; इसे फिर से बनाने के लिए force=true दें (इससे पहले प्रकाशित सभी atproto रिकॉर्ड अनाथ हो जाएँगे)
rotate-yubikey-unsupported = Yubikey-आधारित पहचान का GUI रोटेशन अभी समर्थित नहीं है। टर्मिनल से `provcheck-kit init --yubikey --force` चलाएँ, फिर पब्लिश + रिवोक करने के लिए यहाँ वापस आएँ।
rotate-agefile-unsupported = age-file-आधारित पहचानों का GUI रोटेशन अभी नहीं जोड़ा गया है। टर्मिनल से `provcheck-kit rotate` का उपयोग करें।
sign-keychain-only = GUI साइनिंग फ़िलहाल केवल OS-keychain पहचानों का समर्थन करती है। age-file पहचानों के लिए CLI से `provcheck-kit sign` का उपयोग करें।
sign-yubikey-unsupported = Yubikey-आधारित पहचानों की GUI साइनिंग v0.5.0 P3 + P4 में आएगी। फ़िलहाल, टर्मिनल से `provcheck-kit sign` से साइन करें -- kit हर सिग्नेचर पर PIV PIN माँगता है।
