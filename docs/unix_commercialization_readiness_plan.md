# OS Guard Unix 상용화 구현·검증 준비 계획

상태: 설계 및 검증 준비 전용. Central/Windows 공통 계약 확정 전까지
Agent 모델, API wire protocol, CHECK 판단 기준, HARDEN 실행 경로를 변경하지
않는다.

## 1. 목표와 경계

- 지원 대상: Ubuntu 24.04, Rocky Linux 9/10. Ubuntu 22.04는 기존 지원 회귀
  대상으로 유지하되 신규 설치 검증의 첫 기준은 Ubuntu 24.04로 한다.
- 상시 네트워크 Agent는 전용 비특권 계정으로 실행한다.
- 보호 정보 수집은 네트워크 기능이 없는 제한된 root CHECK Helper로 분리한다.
- Central은 item_id만 선택한다. 명령, argv, 경로, Shell 본문, 권한 프로필을
  전달하거나 선택하지 않는다.
- CHECK는 읽기 전용이며 HARDEN 승인·Grant·Rollback 계약과 분리한다.
- 이 문서의 오류명과 상태명은 후보이며 wire protocol이 아니다.

## 2. 설치 및 서비스 자동 구성 절차

### 2.1 공통 설치 순서

1. 배포판과 major version, systemd PID 1 여부를 확인한다.
2. 배포 패키지 서명과 payload digest를 검증한다.
3. `osguard` system user/group을 로그인 불가 상태로 만든다. `shadow`, `adm`,
   `systemd-journal` 같은 광범위한 보조 그룹은 부여하지 않는다.
4. root 소유 실행 파일, Manifest, CHECK 모듈, Helper 및 systemd unit을 배치한다.
5. 제품 전용 config/state/log/runtime 디렉터리를 설치기가 생성하고 소유권과
   모드를 적용한다.
6. 등록 토큰을 읽기 전에 비특권 Agent와 privileged Helper Preflight를 모두
   수행한다.
7. Preflight 성공 후에만 mode 0600의 registration file을 준비한다.
8. Enrollment 응답 Credential을 atomic write와 fsync로 저장하고 다시 읽어
   검증한다.
9. Credential 저장 성공 후 registration file을 폐기한다.
10. Agent 서비스를 enable/start하고 Heartbeat, Inventory, Helper readiness를
    확인한다.

### 2.2 후보 파일 배치

아래 값은 패키징 설계 후보이며 Central wire contract가 아니다.

| 경로 | 후보 소유자/모드 | 목적 |
| --- | --- | --- |
| `/opt/os-guard-agent` | root:root 0755 | Agent와 Python runtime |
| `/opt/os-guard-agent/modules` | root:root, 일반 쓰기 금지 | Manifest와 CHECK 모듈 |
| `/usr/libexec/os-guard-check-helper` | root:root 0755 | 제한된 Helper |
| `/etc/os-guard-agent` | root:osguard 0750 | 비밀이 아닌 설정과 CA bundle |
| `agent.toml` | root:osguard 0640 | Agent 설정 |
| `/var/lib/os-guard-agent` | osguard:osguard 0700 | Credential, outbox, ACK state |
| `credentials.json` | osguard:osguard 0600 | 운영 Credential |
| `/var/log/os-guard-agent` | osguard:osguard 0750 | 파일 로그 사용 시 로그 경로 |
| `/run/os-guard-agent` | root가 매 부팅 생성 | registration file과 Helper socket |

### 2.3 Ubuntu 24.04

- DEB 패키지의 `preinst/postinst/prerm`은 공통 설치기를 호출하는 얇은 계층으로
  유지한다.
- AppArmor 적용 여부와 프로필 설치 성공 여부를 Preflight에서 별도 기록한다.
- 시스템 CA store를 자동 변경하지 않는다. 제품 전용 CA bundle을 우선하고,
  시스템 신뢰 등록은 별도 관리자 정책이 확정된 경우에만 수행한다.
- `systemctl`, `/usr/sbin/sshd`, APT metadata, journald/rsyslog 경로를 실제 VM에서
  확인한다.

### 2.4 Rocky Linux 9/10

- RPM scriptlet은 공통 설치기를 호출하고 `%post`에서 임의 네트워크 등록을
  시작하지 않는다.
- SELinux enforcing/permissive/disabled를 구분한다. Helper executable, socket,
  state/log 경로의 label을 패키지 정책으로 관리하고 `chcon` 임시 변경에
  의존하지 않는다.
- 제품 전용 CA bundle을 우선하며 시스템 CA store 변경은 별도 정책으로 둔다.
- `sshd`, DNF metadata, journald/rsyslog 및 firewall backend를 실제 VM에서
  확인한다.

### 2.5 systemd 역할 분리

- Agent unit: `User=osguard`, capability 없음, 필요한 Central 주소로만 HTTPS,
  state/log/runtime 제품 경로만 쓰기 가능.
- Helper unit/socket: root 소유, 외부 네트워크 차단, 동시 실행 제한, 로컬
  peer credential 검증, root-owned allowlist만 사용.
- Agent 실패는 `Restart=on-failure`로 복구하되 Credential/outbox 손상을
  자동 삭제하지 않는다.
- Helper 실패는 Agent ONLINE과 구분해 CHECK readiness를 저하시킨다.

## 3. U-01~U-67 실제 권한 검증 계획

### 3.1 결과 라벨

VM 검증 결과는 다음 값만 사용한다.

- `USER_PASS`: 비특권 Agent 계정으로 완전 수집.
- `USER_DENIED_HELPER_PASS`: 일반 계정은 거부되고 Helper로 완전 수집.
- `ENVIRONMENT_BLOCKED`: 권한과 무관한 패키지·서비스·설정 문제.
- `PARTIAL`: 일부만 수집. GOOD으로 승격 금지.
- `TIMEOUT`: 내부 또는 Runner 시간 초과.
- `FAILED`: 수집기 결함 또는 비정상 결과.
- `NOT_TESTED`: 아직 해당 OS/profile에서 실행하지 않음.

판정 상태 GOOD/VULNERABLE/N/A/PENDING/UNCHECKABLE과 권한 검증 라벨을
혼합하지 않는다.

### 3.2 VM 매트릭스

각 항목을 최소 다음 조합으로 실행한다.

1. Ubuntu 24.04 최소 설치, `osguard` 계정, Helper 비활성.
2. Ubuntu 24.04 최소 설치, Helper 활성.
3. Rocky 9 최신 minor, SELinux enforcing, Helper 비활성/활성.
4. Rocky 10 최신 minor, SELinux enforcing, Helper 비활성/활성.
5. 서비스 적용 항목은 서비스 미설치/설치·비활성/활성 fixture를 구분한다.

각 실행은 item_id, OS image digest, 패키지 버전, Agent/Module/Helper 버전,
effective UID/GID, Helper 사용 여부, 실행시간, timeout, 부분수집 여부,
판정 상태, reason/error code를 기록한다. 비밀번호, 해시, community string,
방화벽 주소 목록과 로그 내용은 기록하지 않는다.

### 3.3 항목별 최초 예상 프로필

아래 값은 정적 분석 기반 시험 우선순위이며 구현 계약이 아니다.

| 예상 프로필 | U-code | 주요 검증 포인트 |
| --- | --- | --- |
| Helper 우선 | U-01, U-04, U-13 | sshd effective config, shadow 구조/해시 집계 |
| Helper 우선 | U-15, U-23, U-25, U-33 | root filesystem 스캔 완전성·timeout |
| Helper 우선 | U-28 | nft/iptables/ufw 조회 권한 |
| Helper 우선 | U-60 | SNMP secret의 메모리 내 집계와 비노출 |
| Helper 우선 | U-66, U-67 | 보호 로그 경로와 전체 메타데이터 스캔 |
| 조건부 | U-02, U-03, U-06, U-07, U-12, U-14, U-17 | PAM, root startup, 보호 설정 |
| 조건부 | U-20, U-21, U-24, U-26, U-27, U-30, U-31, U-32 | 보호 디렉터리, 홈, ACL, 장치 경로 |
| 조건부 | U-35, U-37, U-40, U-45~U-51 | 서비스별 config/include와 package cache |
| 조건부 | U-53, U-54, U-56, U-57, U-59, U-61, U-62, U-64, U-65 | 서비스 정책·보호 설정·기관 정책 |
| 일반 UID 우선 | U-05, U-08~U-11, U-16, U-18, U-19, U-22, U-29 | passwd/group 및 단일 stat |
| 일반 UID 우선 | U-34, U-36, U-38, U-39, U-41~U-44, U-52, U-55, U-58, U-63 | 서비스 상태 또는 공개 메타데이터 |

조건부 항목은 먼저 일반 UID로 실행하고 실제 permission failure가 확인된
수집 단계만 Helper 후보로 승격한다. 항목 전체를 불필요하게 root로 실행하지
않는다.

## 4. U-01 제한 Helper 검증

### 4.1 허용 동작

- 요청은 U-01 collector ID만 포함한다.
- Helper가 로컬에서 hostname과 loopback address를 결정한다.
- Helper가 패키지로 검증된 sshd 경로를 선택하고 고정 argv로
  `sshd -T -C user=root,host=<local>,addr=127.0.0.1`을 실행한다.
- Central, task, Agent 요청은 sshd 경로, `-f`, `-o`, Match context 또는 추가
  argv를 지정할 수 없다.
- 출력에서 U-01에 필요한 `PermitRootLogin` 값만 사용한다. host key와 config
  내용, 원본 stderr는 반환하지 않는다.

### 4.2 필수 검증 케이스

1. Ubuntu 24.04 일반 UID에서 기존 `no hostkeys available` 재현.
2. 동일 VM Helper 경로에서 effective value 수집 성공.
3. Rocky 9/10 SELinux enforcing에서 성공 또는 명확한 정책 차단 확인.
4. Ubuntu AppArmor 적용 상태에서 동작 확인.
5. SSH 미사용, sshd 미설치, config unreadable, host key 누락을 구분.
6. Include와 Match 조건이 기존 CHECK 판정으로 전달되는지 확인.
7. 임의 path/argv/environment/item_id 주입 거부.
8. 비인가 로컬 UID의 socket 요청 거부.
9. symlink 또는 일반 사용자 쓰기 가능한 sshd/module/manifest 거부.
10. timeout과 oversized output 차단.
11. 실행 전후 SSH config와 host key의 content hash, owner, mode, timestamps가
    변경되지 않았음을 확인.
12. Helper가 서비스 start/reload/restart를 호출하지 않음을 확인.

## 5. root Helper 보안 설계

### 5.1 신뢰 경계

- Helper는 Central과 통신하지 않는다.
- socket은 root 소유 runtime directory에 두고 허용된 Agent service UID만
  접근한다.
- peer PID/UID/GID를 kernel credential로 검증한다. 요청 JSON의 UID를
  신뢰하지 않는다.
- 로컬 패키지의 privilege allowlist만 신뢰한다.
- Agent가 침해돼도 Helper는 고정된 읽기 전용 collector 외 동작을 제공하지
  않아야 한다.

### 5.2 요청 검증

- 작은 최대 크기, UTF-8, 단일 객체, 중복 키 거부.
- 알려진 internal schema version과 collector ID만 허용.
- 명령, path, argv, env, script, shell, executable 필드를 거부.
- nonce/request ID 중복 방지, 짧은 로컬 deadline, 동시 실행 상한 적용.
- item별 timeout은 root-owned 로컬 profile에 있으며 Central 값으로 변경하지
  않는다.

### 5.3 실행 무결성

- Helper, Manifest, module 및 모든 상위 디렉터리의 owner/mode/symlink를 검사.
- 패키지 설치 시 생성한 digest 또는 배포 패키지 무결성 정보와 대조.
- `shell=True` 금지, 고정 argv, 고정 PATH와 locale, 제한된 환경.
- 민감 파일은 가능한 경우 no-follow open 후 fstat로 type/owner를 재검증.
- stdout/stderr 크기 제한. stderr는 로컬 분류 후 원문을 외부로 보내지 않는다.
- root process는 네트워크, 패키지 관리, 서비스 변경, 일반 파일 쓰기 API를
  제공하지 않는다.

### 5.4 권한 상승 악용 시험

- socket 접근권한 우회, peer credential 위조, replay, flood.
- path traversal, symlink swap, module 교체, writable parent directory.
- command/argv/env injection, locale 조작, PATH binary shadowing.
- timeout 후 자식 프로세스 잔존, fork 폭탄, 대용량 출력.
- Helper crash/restart 중 중복 실행과 stale request.
- package downgrade 및 Helper/Manifest version mismatch.

## 6. 전역 검색 완전성

우선 대상은 U-15, U-23, U-25, U-33, U-67이며 U-26도 별도 bounded scan으로
확인한다.

### 6.1 시간 제한

- item별 내부 timeout과 Module Runner timeout을 분리한다.
- Runner timeout은 내부 timeout보다 종료·정리 grace만큼 길어야 한다.
- 시간 값은 로컬 root-owned profile에서 버전 관리한다.
- timeout은 결과 없음이 아니라 `TIMEOUT/PARTIAL`이며 GOOD이 될 수 없다.

### 6.2 완전성 증적

외부 계약 확정 전에는 wire에 추가하지 않지만 내부 수집 결과로 다음을
보존할 수 있어야 한다.

- 요청한 scan root와 시작 device ID.
- xdev 적용 여부와 제외된 mount 수.
- permission-denied, disappeared file, parse warning 수.
- result limit 도달 여부.
- 내부 timeout/Runner timeout 구분.
- 스캔 종료코드와 completion flag.
- 반환 레코드 수와 위반 수.

permission error, timeout, truncation, 비정상 종료 중 하나라도 있으면
`coverage_complete=false`로 취급한다. 현재 KISA 판정 로직 변경은 공통 계약
확정 후 별도 검토하며, 준비 단계에서는 기존 상태값을 변경하지 않는다.

### 6.3 성능 검증

- 최소 설치, 일반 서버, 많은 inode, 느린 디스크 fixture를 분리한다.
- cold/warm cache 시간을 구분한다.
- CPU, elapsed time, 최대 RSS, 출력 크기를 기록한다.
- scan은 한 번에 하나만 실행하고 전체 CHECK lease 내 완료 가능성을 검증한다.
- 성능 기준 미달을 테스트 SKIP이나 GOOD으로 변환하지 않는다.

## 7. Enrollment 전 Preflight와 복구

### 7.1 토큰 소비 전 순서

1. config syntax와 HTTPS URL.
2. 지원 OS, architecture, systemd.
3. service account와 package file ownership/mode.
4. Manifest/module/Helper 무결성.
5. log/state/Credential/outbox 경로의 symlink·owner·mode.
6. 제품 state 디렉터리에서 atomic create/write/fsync/rename/read/remove 시험.
7. Credential store write/read 시험은 임시 비밀이 아닌 marker로 수행.
8. outbox enqueue/ACK journal 시험은 임시 marker로 수행 후 제거.
9. CA bundle 파싱, hostname verification, 승인된 pin 방식 확인.
10. Helper socket peer 인증과 각 권한 profile self-test.
11. Agent/Helper systemd enable 상태와 sandbox 적용 여부.
12. 위 항목이 모두 성공한 뒤 registration file을 읽고 Enrollment 실행.

Preflight 보고를 Central에 전송하는 방식은 계약 확정 전 구현하지 않는다.
Credential이 없으므로 최초 Preflight 실패는 로컬 installer 결과로 제공하고,
성공한 보고서를 Enrollment 이후 전송할지는 Central과 합의한다.

### 7.2 실패 복구

- 제품 소유 디렉터리 누락·모드 오류는 installer가 자동 복구한다.
- OS 보안 파일, SSH host key, PAM, 방화벽, 서비스 설정은 변경하지 않는다.
- Credential/outbox가 손상되면 자동 삭제하지 않고 fail-closed와 복구 식별자를
  제공한다.
- Enrollment 응답 수신 후 Credential 저장 실패에 대비한 enrollment_id 기반
  idempotent recovery는 Central 계약이 필요하다.
- 실패한 registration file을 무기한 보관하지 않는다. 토큰 상태 조회·재발급
  정책이 확정될 때까지 명시적 복구 상태로 격리한다.
- 설치 rollback은 제품 파일과 제품 계정/디렉터리만 대상으로 하며 기존 OS
  설정을 복구 대상으로 주장하지 않는다.

## 8. 구현 전 Gate

1. Central/Windows와 readiness, diagnostics, partial collection 공통 의미 합의.
2. bootstrap CA 및 pin rotation 계약 합의.
3. Enrollment 응답 유실·Credential 저장 실패 복구 계약 합의.
4. Helper internal protocol 위협 모델과 allowlist 승인.
5. Ubuntu 24.04와 Rocky 9/10 disposable VM 이미지 확정.
6. 67개 권한 검증 결과표 템플릿 및 증적 보존 기준 승인.
7. 위 Gate 완료 후 Installer → Preflight → U-01 Helper → P0 항목 순으로 구현.

## 9. 완료 기준

- 신규 VM에서 관리자 승인 한 번으로 설치, Preflight, Enrollment, 서비스 시작이
  완료된다.
- 사용자가 수동 `chmod`, `chown`, `sudo`를 실행하지 않는다.
- Agent는 비특권으로 상시 실행되고 Helper는 고정 CHECK만 수행한다.
- 일반 UID 실패와 Helper 실패가 구분되며 부분 수집을 GOOD으로 보고하지 않는다.
- CHECK 판정 기준과 HARDEN 승인 구조가 유지된다.
- 실제 실행하지 않은 OS/item/profile은 `NOT_TESTED`로 남는다.
