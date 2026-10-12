# provcheck-cli 런타임 출력, 영어(원본 기준). 사람이 읽는 출력만 번역 대상이며,
# --json 출력과 종료 코드는 로케일화하지 않습니다. 자리표시자 { $name }는 호출 지점에서
# 채워지므로 번역문에서도 그대로 유지하십시오. 브랜드 및 기술 용어(provcheck,
# C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, 플래그, 파일 이름)는
# 모든 로케일에서 원문 그대로 유지합니다.

## Mellin 키드 오디오 포렌식 블록 (print_mellin_human).
mellin-header = Mellin (실험적 기능, 키드 오디오 포렌식 시리얼):
mellin-serial-full = 시리얼:   { $serial } (전체 64비트 복구됨, 최소 비트 투표 수 { $votes })
mellin-serial-partial = 시리얼:   완전히 복구되지 않음 ({ $bits }/64비트, 최소 비트 투표 수 { $votes })
mellin-erasures = 소거: 위치의 { $pct }%
mellin-expected-match = 예상: 일치
mellin-expected-no-match = 예상: 불일치

## Backfire 키드 이미지 워터마크 블록 (print_backfire_human).
backfire-header = Backfire (실험적 기능, 키드 이미지 워터마크):
backfire-mark-valid = 마크:   유효함 (id { $id }, 마진 { $margin })
backfire-mark-none = 마크:   감지되지 않음 (마진 { $margin })
backfire-tamper-detected = 변조: 밴드 노치 감지됨 (통계값 { $stat }). 이 이미지는 노치 공격을 받았을 가능성이 매우 높습니다.
backfire-tamper-none = 변조: 없음 (밴드 노치 통계값 { $stat })

## Backfire 설정 (--install-backfire).
backfire-folder-not-found = provcheck: backfire 폴더를 찾을 수 없습니다. BACKFIRE_PY를 backfire.py로 설정하거나, backfire/backfire.py가 있는 디렉터리에서 실행하십시오.
backfire-ps1-not-found = provcheck: { $dir }에서 setup_backfire.ps1을 찾을 수 없습니다
backfire-sh-not-found = provcheck: { $dir }에서 setup_backfire.sh를 찾을 수 없습니다
backfire-setup-start = Backfire 읽기 환경을 설정하는 중입니다 (최초 1회). 독립 실행형 Python을 다운로드합니다.
backfire-setup-ready = Backfire 준비가 완료되었습니다. 다음 명령으로 마킹된 이미지를 검증하십시오:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire 설정이 상태 코드 { $status }로 종료되었습니다
backfire-setup-run-failed = provcheck: Backfire 설정 스크립트를 실행할 수 없습니다 ({ $err }). Windows에서는 PowerShell이, Linux/macOS에서는 bash가 필요합니다.

## 모델 설치 (--install-models).
install-models-start = 워터마크 감지 모델 파일 { $count }개를 설치하는 중입니다 (총 { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = 완료
install-models-item-failed = 실패: { $err }
install-models-done = 모든 모델이 설치되었습니다. 워터마크 감지를 사용할 준비가 되었습니다.
install-models-summary-failed = provcheck: 모델 { $count }개 설치에 실패했습니다 (위 내용을 참조하십시오).

## 주요 검증 경로: 오류, 알림, 힌트.
require-attested-needs-identity = provcheck: --require-attested에는 --bsky-handle, --did 또는 --auto-identity가 필요합니다
trust-store-read-failed = provcheck: 신뢰 저장소 '{ $path }'을(를) 읽을 수 없습니다: { $err }
auto-identity-no-assertion = provcheck: --auto-identity가 요청되었지만 파일에 app.provcheck.identity 어서션이 없습니다. 먼저 `provcheck-kit sign --embed-identity`로 서명하거나, --bsky-handle / --did를 직접 지정하십시오.
backfire-needs-key = provcheck: --backfire-read에는 --backfire-key가 필요합니다
backfire-experimental-notice = provcheck: Backfire는 실험적 기능이며 BUSL 라이선스(비상업적 용도로 무료 사용 가능)로 제공되며, Apache-2.0 코어와는 별개입니다. 사용자가 삽입한 키드 마크를 검증하고 밴드 노치 변조를 표시합니다. 견고성은 이미지마다 다릅니다.
backfire-read-failed = provcheck: backfire 읽기에 실패했습니다: { $err }
mellin-needs-args = provcheck: --mellin-read에는 --mellin-secret-file과 --mellin-work-id가 필요합니다
mellin-experimental-notice = provcheck: Mellin은 실험적 기능이며 BUSL 라이선스(비상업적 용도로 무료 사용 가능)로 제공되며, Apache-2.0 코어와는 별개입니다. 사용자가 삽입한 사본별 키드 시리얼을 읽습니다. 사용자의 시크릿과 작업 ID가 없으면 읽을 내용이 없습니다.
mellin-read-failed = provcheck: mellin 읽기에 실패했습니다: { $err }
json-serialize-failed = provcheck: JSON 직렬화에 실패했습니다: { $err }
hint-models-missing = [힌트] 워터마크 감지 모델 { $count }개가 설치되지 않아 해당 항목이 "설치되지 않음"으로 표시됩니다. 다음 명령으로 모든 감지 기능을 활성화하십시오:  provcheck --install-models  (최초 1회, { $mb } MB). C2PA 검증에는 필요하지 않습니다.
hint-claims-identity = [힌트] 파일이 신원 { $who }을(를) 주장합니다. --auto-identity와 함께 다시 실행하여 게시된 서명 키 기록과 대조 검증하십시오.
