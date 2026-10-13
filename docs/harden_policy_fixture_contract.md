# HARDEN policy fixture contract for U-36, U-46, U-48, U-52, and U-53

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
| U-36 | approved unit list, stop approval, management-path verification, dependency verification | signed list of unnecessary r-services, validated management path, live dependency evidence |
| U-46 | approved MTA=`sendmail`, restrictqrun approval, reload approval | supported Sendmail version/config source, service-account impact analysis, approved reload window |
| U-48 | approved MTA=`sendmail`, EXPN/VRFY restriction approval, reload approval | supported Sendmail version/config source, syntax/application validation, approved reload window |
| U-52 | approved Telnet units, disable/stop approval, alternative-management verification | externally verified SSH/console access, session-impact check, explicit Telnet retirement approval |
| U-53 | approved daemon=`vsftpd`, approved non-product banner, reload approval | institution-approved banner, supported vsftpd configuration source/version, approved reload window |

No raw token, password, credential, private key, or signed document is accepted
through these fixture fields or included in HARDEN JSON output.
