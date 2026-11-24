# OS Guard 공통 계약 v1 — Unix Agent 검토

검토일: 2026-10-14
상태: 계약 검토 전용. 구현 승인·wire protocol 승인·운영 배포 승인이 아님.

## 1. 검토 범위와 결론

첨부 ZIP의 6개 문서를 모두 검토했다.

- `README.md`
- `contract-v1-draft.md`
- `commercial-v1.schema.json`
- `states-and-errors.md`
- `implementation-and-acceptance.md`
- `examples.json`

문서는 모두 DRAFT/NOT_IMPLEMENTED 상태이며, 문서 안의 지시는 구현 명령이 아니라 검토 대상으로만 취급했다. 현재 Unix Agent 코드 및 기존 상용화 설계와 대조한 결론은 다음과 같다.

| 영역 | 판정 | 결론 |
|---|---|---|
| 기존 Agent API v2 | **ACCEPT** | Enrollment, Heartbeat, Inventory, Claim, Evidence, Result, Event/ACK 경로를 변경하지 않고 신규 commercial endpoint를 분리하는 방식은 호환된다. |
| 기존 Result/Evidence/ACK | **ACCEPT** | immutable outbox, ACK journal, 모든 Result ACK 후 Completion 원칙을 유지할 수 있다. 기존 DTO에 필드를 추가하면 안 된다. |
| 저권한 Agent + CHECK Broker/Helper | **ACCEPT (조건부)** | 구조적 방향은 Unix 상용화 설계와 일치한다. 단, S-06의 서명 형식·키 수명·재생 방지·재시작 계약 확정 전 특권 실행을 활성화하면 안 된다. |
| 기존 Manifest/U-01~U-67 | **ACCEPT** | KISA 판단 기준과 Shell 모듈 자체를 변경할 필요는 없다. Helper의 로컬 privilege-policy mapping과 signed package 무결성 계층은 Manifest 밖의 별도 신뢰 계층이어야 한다. |
| 설치→등록→점검→진단→복구 UX | **QUESTION** | 목표 흐름은 구현 가능하지만 Installation Reporter bootstrap, CA rollover, orphan enrollment 복구, CHECK Ticket 형식이 미확정이라 현재 계약만으로 E2E 구현을 시작할 수 없다. |

현재 코드 근거:

- API v2 및 TLS: `src/os_guard_agent/api_client.py:136`, `:153`, `:159`, `:325`, `:383`, `:436`, `:569`, `:636`
- 등록 파일과 토큰 폐기: `src/os_guard_agent/registration.py:30`, `:71`, `:83`; `src/os_guard_agent/__main__.py:58-67`
- credential atomic 저장/rotation: `src/os_guard_agent/token_store.py:31`, `:34`, `:89`, `:131`
- FULL/PARTIAL 및 로컬 Manifest mapping: `src/os_guard_agent/module_runner.py:58-99`; `src/os_guard_agent/manifest.py:52`, `:119`
- 로컬 CHECK 실행: `src/os_guard_agent/module_runner.py:101-151`
- Result/Evidence/Completion outbox: `src/os_guard_agent/agent.py:261-359`; `src/os_guard_agent/outbox.py:57`, `:100`, `:140`, `:245`
- 현재 HARDEN용 Policy/Grant는 CHECK Ticket이 아님: `src/os_guard_agent/grant.py:71-267`, `src/os_guard_agent/policy.py:402-547`; 두 경로 모두 운영 실행을 허용하지 않는다.

## 2. 공동 결정사항 검토

### S-01 — 상태·Readiness·Preflight

**CHANGE_REQUEST**

계약의 4축 상태 분리, `PROBED`와 정적 분석 구분, token 소비 전 GLOBAL gate, `READY/PARTIAL/BLOCKED/UNKNOWN` 분리는 타당하다. 현재 Heartbeat `READY`와 Inventory `SUCCEEDED/FAILED`의 의미를 바꾸지 않고 신규 report로 분리한 것도 호환된다.

충돌/누락:

- Schema는 빈/누락 probe, `required_for_enrollment=false`, 임의 probe 이름으로도 형식 검증을 통과할 수 있다.
- 필수 GLOBAL probe catalog/version과 Central 검증 규칙이 Schema에 binding되지 않았다.
- readiness freshness를 재부팅·서비스 재시작 후 무효화한다고 문서에 쓰였으나 report에는 `boot_id` 또는 `service_instance_id`/Central challenge가 없다.
- Agent 자체가 `enrollment_gate=READY`를 선언할 수 있으므로 Central이 이를 권위값으로 사용하면 안 된다.

권장 수정:

1. `preflight_catalog_id/version`을 report와 installation session에 binding한다.
2. Central은 platform/release별 필수 probe 집합, 중복 금지, 누락 금지, `required_for_enrollment` 값을 서버 정책으로 재계산한다.
3. `boot_instance_id`와 `service_instance_id` 또는 session challenge를 추가해 stale report replay를 차단한다.
4. enrollment gate와 readiness 최종 상태는 Central 파생값으로 정의하고 Agent 값은 observation으로만 저장한다.

보안 위험: 누락 probe나 오래된 PASS를 이용해 credential 저장·CA·Helper 검증 없이 Enrollment/CHECK gate가 열릴 수 있다.

### S-04 — 사용자별 범위·부분 수집

**CHANGE_REQUEST**

HOST/USER/FILESYSTEM/ROLE scope와 item별 coverage를 도입하는 방향은 필요하다. 다만 현재 Unix `Task`는 FULL/PARTIAL과 `item_ids`만 가지며 per-item scope는 없다(`models.py:234-265`). 기존 U-01~U-67 모듈은 Agent 프로세스의 host context에서 실행된다.

충돌/누락:

- Schema가 `kind=USER`인데 `binding_id=null`인 scope를 허용한다.
- `item_ids`와 `item_scopes`의 1:1 관계, 중복·누락·여분 scope가 Schema로 강제되지 않는다.
- `Coverage`의 expected/observed/omitted 산술 관계와 COMPLETE/PARTIAL 의미가 강제되지 않는다.
- NSS 사용자, mount namespace/container, include chain의 안정된 opaque binding 생성 규칙과 개인정보 보존 정책이 없다.
- FULL job에서 USER/HOST가 혼합될 때 현재 Agent는 이를 표현하거나 실행할 수 없다.

권장 수정:

1. USER/FILESYSTEM/ROLE은 `binding_id`를 필수로 하고, HOST는 null만 허용하도록 조건부 Schema를 강화한다.
2. 각 item에 정확히 하나 이상의 승인 scope가 필요한지 item catalog에 선언하고, ticket의 `item_ids`와 `item_scopes`를 Central과 Helper 모두 동일하게 검증한다.
3. coverage invariant를 명시한다: COMPLETE는 expected/observed가 확정되고 omitted=0, PARTIAL은 누락 사유와 집계가 필수, UNKNOWN은 전체 성공으로 사용 금지.
4. Unix v1은 검증된 HOST scope 항목만 ELIGIBLE로 두고 USER/namespace 항목은 collector가 실제 구현될 때까지 UNKNOWN/BLOCKED로 유지한다.

보안 위험: scope 축약이나 누락을 FULL/GOOD으로 오인하거나, 다른 사용자·namespace의 결과를 대상 사용자 결과로 귀속할 수 있다.

### S-05 — Credential 저장 실패·재등록·기존 작업

**QUESTION**

"저장 self-test → Enrollment → durable 저장/reload → Receipt → fresh HB/Inventory/readiness" 순서와 raw secret 비보존, old 결과/증적 불변 원칙은 수용 가능하다. 현재 Unix Agent도 registration token을 CLI에 노출하지 않고 저장 성공 후 registration file을 제거하며, credential과 outbox를 atomic 파일로 관리한다.

결정이 필요한 사항:

- Central의 orphan Agent/credential 조회·폐기 및 active job/미ACK 결과를 보존하는 재등록 gate의 정확한 API와 상태 전이가 없다.
- 새 `agent_id`를 받은 뒤 기존 outbox를 그대로 열 경우 old Agent의 메시지를 새 credential로 전송하지 않도록 저장소 namespace/quarantine 규칙이 필요하다.
- Enrollment 응답 유실과 Central commit 여부 불명확 상태에서 installer가 어떤 API로 상태를 조회하는지 미정이다.
- Unix credential 보호 저장 방식은 아직 0600 파일이며, 플랫폼별 stronger-at-rest 저장 책임이 미확정이다.

권장 결정:

1. `session_id/enrollment_id/server_id` 기반 read-only recovery status API와 권한 있는 orphan revoke API를 정의한다.
2. outbox를 `server_id/agent_id`에 영구 binding하고 identity가 다르면 전송하지 않고 reconciliation 상태로 둔다.
3. Registration secret, installation journal, credential, old outbox의 각 보존/삭제 조건을 상태표로 확정한다.
4. receipt ACK 유실은 동일 byte/id 재전송으로 복구하고 새 Enrollment를 자동 수행하지 않는다.

보안 위험: old 메시지 retag, credential orphan, 반복 Enrollment, 토큰 원문 장기 보관 또는 미ACK 증적 유실.

### S-06 — Signed CHECK Ticket과 특권 실행기

**CHANGE_REQUEST**

Signed CHECK Ticket은 필요하다. peer UID/socket ACL만으로는 침해된 저권한 transport가 root Helper에 허가된 항목을 가장하는 것을 막지 못한다. 다만 현재 `ExecutionTicketClaims`는 claims 의미만 정의하며 signed envelope/JWS, 알고리즘, key rotation이 OPEN이다. 기존 `grant.py`는 HARDEN 승인 증거이고 CHECK Ticket으로 재사용하면 안 된다.

필수 수정/확정:

1. 서명 envelope, canonicalization 또는 JWS profile, 허용 알고리즘(예: Ed25519), `key_id`, key usage=`CHECK_TICKET`, issuer/audience 규칙을 규격화한다.
2. 공개키는 signed package/관리자 승인 bootstrap으로만 설치하고 ticket 안의 key/key path를 금지한다.
3. `item_ids`↔`item_scopes` 완전 일치, OS family, package digest, local privilege policy, service identity, manifest/module/criteria/readiness, job/attempt, timeout profile을 모두 서명·검증한다.
4. ticket은 로컬 allowlist를 넓히지 못하며 `command`, `path`, `argv`, `environment`, `sudo`, interpreter, script body를 포함하거나 유도하면 거부한다.
5. ticket ID replay journal, 동시 소비, crash 상태, 동일 attempt renewal, expired/lease-expired stop, key rotation/revocation의 잔여 실행 창을 결정한다.
6. 운영 credential과 ticket 검증키를 Helper에 제공하지 않는다. Helper는 network와 operating credential을 가지지 않는다.

보안 위험: confused deputy, 원격 privilege/profile injection, ticket replay, 교차 Agent/Job/사용자 실행, 탈취 키의 잔여 사용.

### S-07 — 최초 CA 신뢰·인증서 교체

**CHANGE_REQUEST**

현재 Unix Agent는 registration file의 SHA-256 fingerprint 형식만 검증하고(`registration.py:71-73`), 실제 HTTPS는 OS trust store 기반 `ssl.create_default_context()`의 chain/hostname 검증만 수행한다(`api_client.py:153`). 따라서 문서의 "최초 fingerprint + runtime chain/SAN"은 아직 코드상 연결되지 않았다.

권장 수정:

1. fingerprint가 CA certificate DER인지 leaf/SPKI인지 정확히 정의한다.
2. registration file과 fingerprint를 같은 미신뢰 채널에서 받는 것을 신뢰 bootstrap으로 인정하지 않는다. signed installer/package 또는 관리자 인증 채널에 trust anchor를 포함한다.
3. Unix 전용 bundle과 machine-wide trust store 중 범위를 설치 승인 화면에 명시한다. 기본은 제품 전용 bundle을 권장한다.
4. CA 교체는 old/new overlap, 활성화 시각, rollback/downgrade 차단, 복수 pin, 폐기 후 행동을 정의한다.
5. Installation Reporter가 Enrollment 전에 사용하는 TLS도 동일 bootstrap 규칙에 포함한다.
6. `verify=False`, HTTP fallback, 인증서 오류 자동 무시는 계속 금지한다.

보안 위험: 공격자 제공 CA+지문 동시 신뢰, CA 교체 시 대규모 offline, stale CA downgrade, shared machine trust 오염.

### S-08 — Installation Reporter와 설치 UX

**QUESTION**

Enrollment token을 진단에 사용하지 않고 별도 최소권한 reporter credential을 두는 방향은 적절하다. 그러나 session 생성/secret download DTO, credential 전달 형식, TTL/rate, offline journal 전송 규칙이 OPEN이다.

Central 결정 요청:

1. 사용자가 내부 secret을 복사하지 않아도 installer가 `session_id`와 reporter credential을 받는 인증된 다운로드/launch 방식.
2. credential의 session/server/package digest binding, 1회성 여부, TTL, rate/body limit, revoke 조건.
3. reporter가 허용되는 endpoint와 kind를 고정: installation event와 pre-enrollment preflight만 허용하고 Enrollment/HB/Inventory/Claim/Result/rotate/receipt는 금지.
4. reporter가 보낸 READY/auto-recoverable/approval을 Central이 상태·복구 권위로 사용하지 않는 규칙.
5. offline journal의 파일 권한, maximum size, sequence 충돌, terminal event 역행 금지, uninstall 시 보존 정책.

보안 위험: 두 번째 bootstrap secret의 탈취, 설치 상태 위조, report flood, reporter 권한이 operating credential로 확대되는 confused authentication.

### S-10 — 기존 Result와 신규 진단 계약

**CHANGE_REQUEST**

기존 Result/Evidence 계약과 판정 enum을 유지하고 readiness/diagnostic을 별도 DTO로 분리하는 원칙은 맞다. 그러나 현재 Schema의 report-level diagnostics에는 runtime `job_id`, `attempt_id`, `result_id`, `item_id` 상관관계가 충분하지 않다. 기존 Agent는 ModuleRunner 예외를 `MODULE_EXECUTION_FAILED`로 축약한다(`agent.py:313-339`).

권장 수정:

1. 기존 Result top-level은 그대로 두고, 신규 runtime diagnostic container에 `job_id`, `attempt_id`, `result_id` 또는 `message_id`, `item_id`, `scope`, `coverage`, safe cause를 인증된 binding으로 정의한다.
2. diagnostic은 판정 결과를 덮어쓰지 않으며, 동일 Result의 재시도에서 reason/observed time을 변경하지 않는다.
3. Central은 unknown reason/cause를 안전한 generic UI로 표시하되 PASS/FAIL/NA로 변환하지 않는다.
4. contract 문서의 `UNABLE` 용어와 현재 Unix `GOOD/VULNERABLE/N/A/UNCHECKABLE + review_state` 매핑을 명시한다. 기존 Unix wire enum을 일방적으로 바꾸지 않는다.
5. errno/effective UID/helper status/필요 권한은 allowlist된 최소값만 보내고 raw stderr/path/config/account 정보는 보내지 않는다.

보안 위험: 진단과 결과의 잘못된 연결, UNCHECKABLE을 GOOD로 오인, raw OS 오류의 secret/PII 유출, 동일 result 재전송의 비결정성.

### S-11 — Timeout·재시작·작업 복구

**CHANGE_REQUEST**

현재 Agent는 `server_time + lease_duration_sec`를 monotonic deadline으로 사용하고, outbox/ACK journal은 영구 보존한다. 하지만 ModuleRunner timeout은 항목당 고정 15초이고(`module_runner.py:101-140`), crash 중 Helper 실행과 ticket 소비 상태, timeout profile, child process 제한은 아직 없다.

권장 수정:

1. `timeout_profile_version`을 Central job snapshot, signed ticket, local policy에 동일하게 binding하되 Central 값이 로컬 상한을 늘리지 못하게 한다.
2. source를 COLLECTOR/HELPER/TRANSPORT/LEASE로 분리하고 wall clock은 표시용, 실행 중단은 서버 시간 증거로 계산한 monotonic deadline을 사용한다.
3. item 실행 journal 상태를 `AUTHORIZED → STARTED → RESULT_DURABLE → ACKED`로 정의하고, crash 시 STARTED ticket을 재사용하지 않는다. 결과가 durable이면 동일 bytes/id만 재전송한다.
4. lease/ticket 만료 시 새 collector 시작 금지, 실행 중 child/process group 종료와 bounded cleanup 규칙을 정한다.
5. 전역 검색은 항목별 budget, maximum entries/bytes, partial coverage, stop reason을 남기고 partial을 전체 성공으로 변환하지 않는다.
6. 재부팅 후 Central `completed_item_ids`와 로컬 ACK journal을 대조하되 다른 attempt의 outbox를 삭제/retag하지 않는다.

보안 위험: 무제한 privileged scan, lease 만료 후 실행, crash 후 중복 실행, timeout 원인 오분류, partial 결과의 전체 PASS 오인.

## 3. Schema상 허용되어도 실제로 거부해야 하는 요청

`commercial-v1.schema.json`은 shape 검증 수단이지 authorization/semantic validation이 아니다. 다음은 JSON Schema를 통과할 수 있더라도 endpoint 또는 Agent에서 거부해야 한다.

1. **endpoint-kind 혼용**: combined `oneOf`에 포함됐다는 이유로 Reporter가 EnrollmentReceipt/Readiness/Ticket/Lifecycle/ACK를 보내는 요청.
2. **principal binding 불일치**: Bearer/reporter session의 server/agent/session/enrollment/credential와 body ID 불일치.
3. **pre-enrollment 권한 확대**: reporter credential로 Enrollment, HB, Inventory, Claim, Result, credential rotate/revoke를 호출하는 요청.
4. **서버 전용 DTO 업로드**: `ReportAck`, `LifecycleView`, `ExecutionTicketClaims`를 Agent 관측처럼 제출하는 요청.
5. **gate 우회**: 빈 probes, 필수 probe 누락, `required_for_enrollment=false` 변경, static/owner-declared UNKNOWN을 PASS로 취급한 READY.
6. **stale observation**: old boot/service identity/policy/release/manifest/scope의 report 또는 동일 ID의 다른 bytes. 동일 ID·동일 bytes 재전송만 duplicate로 ACK하며 freshness를 갱신하지 않는다.
7. **scope 오류**: USER/FILESYSTEM/ROLE의 null·미등록 binding, cross-server/user scope, item과 무관한 scope, item_ids와 item_scopes 중복·누락·여분.
8. **coverage 불변식 위반**: COMPLETE인데 omitted>0/unknown count, observed>expected, PARTIAL인데 누락 원인 없음, UNKNOWN을 FULL eligibility로 사용.
9. **ticket semantic 오류**: 서명 부재/미허용 alg/key usage, unknown/revoked key, issuer/audience 불일치, expired/not-yet-valid, lease보다 긴 TTL, replay, wrong agent/job/attempt/release/readiness/scope/item.
10. **원격 실행 주입**: command, shell, script, script_body, executable, path, argv, interpreter, environment, sudo/profile 또는 유사 실행 지시 필드. unknown field 거부와 별도로 중첩 객체도 검사한다.
11. **platform 혼용**: Unix Agent에 W-code, Windows Agent에 U-code, release platform/OS/architecture와 ticket·manifest 불일치.
12. **미승인 release**: digest 형식만 맞고 Central approved package registry/local signed artifact와 일치하지 않는 package.
13. **진단 권위 위조**: client가 `auto_recoverable`, `approval_required`, `requested_state`, remediation 또는 privilege profile로 Central action을 지시하는 요청.
14. **민감정보/원문**: token, credential, private key, password/hash, raw shadow/PAM/SSH/SNMP 설정, raw stdout/stderr/exception, 개인 사용자명·경로가 diagnostics/evidence에 포함된 요청.
15. **구문 모호성/자원 고갈**: duplicate JSON keys, NaN/Infinity, 잘못된 UTC offset/date-time, 과도한 nesting/string/array/report 크기, duplicate IDs, sequence rollback.
16. **불변 결과 위반**: 같은 message/result/report ID로 payload/hash/observed time/판정을 바꾼 재전송, ACK 전 outbox payload 변경.

Schema 개선 권고:

- route별 root schema를 분리하고 combined schema를 endpoint validator로 사용하지 않는다.
- JSON Schema 2020-12 format assertion을 실제 validator에서 활성화한다.
- 의미 불변식은 Central/Agent/Helper에서 이중 검증하고 negative examples와 인수 테스트에 포함한다.
- `unevaluatedProperties=false` 지원 여부를 실제 validator 버전으로 확인한다.

## 4. 사용자 경험 실현 가능성

목표 UX는 다음 전제가 해결되면 가능하다.

| 사용자 단계 | 가능 여부 | 전제/현재 gap |
|---|---|---|
| Central에서 설치파일 다운로드 | 조건부 가능 | signed release metadata, platform/arch/support gate, reporter/session bootstrap 확정 필요 |
| 최초 관리자 권한 1회 승인 | 조건부 가능 | package signature와 CA fingerprint를 신뢰 경로에서 보여주고 service UID, 디렉터리, systemd, Helper/socket/local policy를 installer가 원자적으로 배치해야 함 |
| 서비스·권한·CA·Manifest 자동 구성 | 조건부 가능 | Unix file ownership/mode/link/SELinux/AppArmor 검증, 전용 CA bundle, root Helper allowlist와 rollback 규격 필요 |
| 자동 등록·연결 | 가능 | token 전 Preflight, durable credential receipt, reporter recovery API가 필요. 사용자의 token/chmod/chown 조작은 없어야 함 |
| Central CHECK 실행 | 조건부 가능 | fresh readiness + signed ticket + local policy 교집합인 항목만 허용. U-01~U-67 로컬 스크립트는 그대로 재사용 가능 |
| 오류 원인 확인·안전 복구 | 조건부 가능 | S-10 runtime diagnostic correlation, product-owned path repair allowlist, S-05 orphan recovery, S-11 journal 확정 필요 |

자동 복구는 product-owned directory/unit/config에 한정한다. `/etc/shadow`, PAM/SSH/firewall, 계정·ACL, machine-wide CA, KISA 대상 설정은 CHECK 과정에서 고치지 않으며 HARDEN 승인과도 분리한다.

## 5. Unix 구현 영향

계약 합의 후 수정/추가가 예상되는 Unix 영역이다. 이번 검토에서는 변경하지 않았다.

| 영역 | 예상 코드 위치 | 변경 성격 |
|---|---|---|
| Preflight/readiness 모델·전송 | `models.py`, `api_client.py`, 신규 preflight/readiness 모듈 | 신규 독립 DTO/endpoint; 기존 HB/Inventory 불변 |
| Installer/reporter | 신규 installer/systemd/preflight/reporter 구성 | 관리자 1회 승인, 실제 service UID self-test, token 전 gate |
| Credential/reenroll | `registration.py`, `token_store.py`, `outbox.py`, `agent.py` | Receipt, identity-bound outbox, recovery/reconciliation |
| CA bootstrap | `registration.py`, `api_client.py`, installer | fingerprint 실제 검증, 제품 전용 trust bundle, rollover |
| CHECK Broker/Helper | 신규 broker/helper/local privilege policy | network secret 없는 root Helper, authenticated IPC, signed ticket, replay journal |
| Scope/coverage | `models.py`, `module_runner.py`, 신규 collector metadata | item별 scope와 truthful partial coverage; Shell 판정 기준 불변 |
| 진단 | `agent.py`, `module_runner.py`, 신규 diagnostic mapper | safe typed cause와 runtime job/result correlation |
| timeout/recovery | `module_runner.py`, `agent.py`, outbox/실행 journal | local cap, monotonic deadline, child kill, crash recovery |

Manifest는 현재의 item→local module allowlist 역할을 유지한다. 실행 권한 profile, ticket key, CA, service identity는 Manifest에 임의로 섞지 않는다.

## 6. Central에 요청할 수정·결정사항

우선순위 순서:

1. **S-06** signed CHECK Ticket의 완전한 wire/signature/key/replay/renewal 규격과 negative examples.
2. **S-07** CA bootstrap 신뢰 출처, pin 종류, 전용 bundle 범위, rollover/rollback 규격.
3. **S-01** 필수 GLOBAL probe catalog/version과 boot/service/challenge freshness binding.
4. **S-08** installation session/reporter credential의 생성·안전 전달·TTL·endpoint allowlist·offline journal 규격.
5. **S-04** USER/FILESYSTEM/ROLE binding 필수 조건, item-scope 대응, coverage 산술 불변식과 privacy/retention.
6. **S-05** enrollment ambiguity 조회, orphan revoke, active job/old outbox reconciliation API와 상태 전이.
7. **S-10** 기존 Result를 변경하지 않는 runtime diagnostic correlation DTO 및 Unix 상태 매핑.
8. **S-11** timeout profile/local cap, lease-ticket 관계, Helper crash/reboot journal과 partial completion 규칙.
9. route별 인증 principal과 허용 DTO kind를 OpenAPI/Schema로 분리하고 위 semantic reject 목록을 인수 기준에 포함.

## 7. 최종 판정 요약

| 결정 | 판정 |
|---|---|
| S-01 | **CHANGE_REQUEST** — catalog/version 및 freshness binding 필요 |
| S-04 | **CHANGE_REQUEST** — non-HOST binding과 item-scope/coverage 불변식 필요 |
| S-05 | **QUESTION** — orphan recovery와 old outbox/job reconciliation API 결정 필요 |
| S-06 | **CHANGE_REQUEST** — signed envelope/key/replay/restart 규격이 없어 특권 CHECK 활성화 불가 |
| S-07 | **CHANGE_REQUEST** — fingerprint 실검증과 bootstrap/rotation 규격 필요 |
| S-08 | **QUESTION** — reporter secret 전달·권한·TTL·offline journal 미확정 |
| S-10 | **CHANGE_REQUEST** — runtime diagnostic과 Result/Job 상관관계 및 Unix 상태 매핑 필요 |
| S-11 | **CHANGE_REQUEST** — timeout profile, monotonic stop, ticket/execution journal 및 reboot 복구 규격 필요 |

기존 API v2와 Result/Evidence/ACK를 유지하는 방향, 로컬 Manifest 기반 U-code 선택, 원격 command 금지, 저권한 transport와 제한된 Helper 분리는 수용 가능하다. 위 CHANGE_REQUEST와 QUESTION이 합의되기 전에는 특권 CHECK Helper, 신규 commercial claim, 자동 복구를 상용 활성화하지 않는 것이 안전하다.
