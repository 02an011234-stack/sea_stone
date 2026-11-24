# HARDEN policy fixture contract

Status: test-only. These fields are not an operating policy API and do not
authorize host mutation. The Agent policy verifier does not support these
U-codes, `operational_use_allowed` remains false, and the CHECK-only Manifest
and Module Runner remain unchanged.

The new HARDEN scripts fail closed outside an isolated `OS_GUARD_TEST_ROOT`.
`OS_GUARD_TEST_POLICY_FIXTURE=true` identifies a test fixture only. It must
never be accepted as a substitute for a signed policy and one-time Grant.

## Shared requirements

- Explicit PREVIEW fingerprint and `OS_GUARD_HARDEN_APPROVED=true` for EXECUTE.
- Existing CHECK must be actionable. PENDING and UNCHECKABLE are never upgraded
  by fixture policy. Consequently U-36 remains blocked while its runtime CHECK
  reports active r-services as PENDING.
- Configuration files must be regular, readable, unambiguous local files.
- Any service reload or stop must be represented by an explicit fixture field.
- Production use additionally requires signed policy schemas, trusted external
  evidence, Grant consumption, and Agent execution integration.

## Item fields

| Item | Test-only fields | Required future operating evidence |
| --- | --- | --- |
| U-06 | approved local su group, local-files identity provenance, verified membership, alternative-admin and console-recovery evidence | signed local group scope, NSS provenance, current member impact, verified administration and recovery paths |
| U-36 | approved unit list, stop approval, management-path verification, dependency verification | signed list of unnecessary r-services, validated management path, live dependency evidence |
| U-46 | approved MTA=`sendmail`, restrictqrun approval, reload approval | supported Sendmail version/config source, service-account impact analysis, approved reload window |
| U-48 | approved MTA=`sendmail`, EXPN/VRFY restriction approval, reload approval | supported Sendmail version/config source, syntax/application validation, approved reload window |
| U-52 | approved Telnet units, disable/stop approval, alternative-management verification | externally verified SSH/console access, session-impact check, explicit Telnet retirement approval |
| U-53 | approved daemon=`vsftpd`, approved non-product banner, reload approval | institution-approved banner, supported vsftpd configuration source/version, approved reload window |
| U-11 | approved local KISA account list, restricted shell, local-source/session/dependency verification | signed account scope, NSS provenance, live session and service dependency evidence |
| U-35 | approved service=`vsftpd`, anonymous-disable approval, business-impact verification, reload approval | signed sharing exception policy, supported configuration source, active dependency and reload window evidence |
| U-57 | approved daemon=`vsftpd`, blocked account=`root`, static PAM ftpusers mechanism and login-impact verification | signed restricted-account policy, effective PAM/daemon configuration evidence |
| U-62 | approved single-line banner, target=`/etc/issue.net`, system-only scope, institutional approval evidence | signed institution banner and approved per-service target set |
| U-27 | approved trust-file paths, r-command trust remediation approval, local passwd provenance and relationship-impact verification | signed bounded file scope, local identity provenance, approved retirement of exact plus-wildcard trust records |
| U-38 | approved legacy echo/discard/daytime/chargen units, stop approval, dependency evidence | signed unit scope and proof that DNS/NTP/SNMP or other infrastructure services are excluded and unaffected |
| U-39 | approved NFS server units, empty-export/client/dependency evidence, stop approval | signed NFS retirement decision, live export/client/mount/dependency evidence and recovery plan |
| U-41 | approved autofs units, cleared mounts, dependency evidence, stop approval | signed automount retirement decision, live map/mount/NFS/SMB dependency evidence and recovery plan |
| U-58 | approved SNMP units, retirement approval, monitoring-impact and replacement-monitoring evidence | signed monitoring retirement policy, live collector dependency evidence and approved monitoring replacement |
| U-54 | approved plaintext FTP units, retirement and stop approval, secure-transfer replacement, client migration and session-clearance evidence | signed FTP retirement scope, active-session inventory, verified SFTP/FTPS replacement and recovery procedure |
| U-56 | approved daemon=`proftpd`, one bounded management network, static configuration source, client-impact evidence, reload approval | signed FTP client network policy, effective daemon configuration and approved reload window |
| U-61 | one bounded management network, static direct-community configuration, monitoring-connectivity evidence, reload approval | verified `SNMP_ACCESS_CONTROL` policy, protected community credential, live collector connectivity and approved reload window |

U-65 is intentionally not included. Its current runtime CHECK cannot establish
`source_approval_verified=true`, so a configuration-only fixture HARDEN cannot
meet the mandatory post-change `GOOD` recheck without bypassing CHECK semantics.

No raw token, password, credential, private key, or signed document is accepted
through these fixture fields or included in HARDEN JSON output.
