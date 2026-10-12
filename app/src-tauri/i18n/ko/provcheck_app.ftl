# provcheck-app GUI 메시지, 영어(원본 기준). GUI에 ApiResult ok/err 텍스트로 반환되는
# 완전한 사용자 대상 문장만 여기서 번역합니다. 기술적인 { $err }/로그 경로 진단 정보와
# IPC 오류 레이블은 영어로 유지됩니다. 브랜드 및 기술 용어(provcheck, provcheck-kit,
# Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID,
# 플래그, 파일 이름)는 모든 로케일에서 원문 그대로 유지합니다.

## Backfire 키드 이미지 탭 (backfire_read + install_backfire).
backfire-read-needs-key = Backfire 마크를 읽으려면 키가 필요합니다.
backfire-folder-unresolved = 쓰기 가능한 Backfire 폴더를 확인할 수 없습니다 (LOCALAPPDATA가 설정되지 않음).
backfire-ready-bundled = Backfire 준비가 완료되었습니다 (번들 리더가 있음). 키를 입력하고 이미지를 놓으십시오.
backfire-files-missing = 설치할 Backfire 파일을 찾을 수 없습니다. provcheck를 다시 설치하거나 BACKFIRE_PY를 설정하십시오.
backfire-ready = Backfire 준비가 완료되었습니다. 키를 입력하고 이미지를 놓으십시오.

## Mellin 키드 마크 탭 (mellin_read).
mellin-needs-secret-and-work-id = Mellin 시리얼을 읽으려면 시크릿 파일과 작업 ID가 필요합니다.
mellin-secret-file-missing = 선택한 시크릿 파일이 존재하지 않거나 읽을 수 없습니다.

## 서명 + 키 탭: ApiResult 오류로 반환되는 GUI 기능 제한 알림.
identity-already-exists = 이 데이터 디렉터리에는 이미 신원이 존재합니다. 다시 생성하려면 force=true를 전달하십시오 (이전에 게시된 atproto 기록은 연결이 끊어집니다)
rotate-yubikey-unsupported = Yubikey 기반 신원의 GUI 교체는 아직 지원되지 않습니다. 터미널에서 `provcheck-kit init --yubikey --force`를 실행한 다음, 여기로 돌아와 게시 및 폐기를 진행하십시오.
rotate-agefile-unsupported = age 파일 기반 신원의 GUI 교체는 아직 연결되지 않았습니다. 터미널에서 `provcheck-kit rotate`를 사용하십시오.
sign-keychain-only = 현재 GUI 서명은 OS 키체인 기반 신원만 지원합니다. age 파일 기반 신원은 CLI에서 `provcheck-kit sign`을 사용하십시오.
sign-yubikey-unsupported = Yubikey 기반 신원의 GUI 서명은 v0.5.0 P3 및 P4에서 제공될 예정입니다. 지금은 터미널에서 `provcheck-kit sign`을 통해 서명하십시오. 해당 도구는 서명할 때마다 PIV PIN 입력을 요청합니다.
