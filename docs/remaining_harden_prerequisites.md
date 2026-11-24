# Remaining Unix HARDEN prerequisites
Status: analysis and test-fixture contract only. Nothing in this document
enables HARDEN. The Manifest remains CHECK-only and validated policy evidence
continues to report `operational_use_allowed=false`.

## U-01 isolated CHECK support

`U-01.sh` now resolves configuration files below `OS_GUARD_TEST_ROOT` only
when that variable is present. In that mode `sshd -T` receives the isolated
`sshd_config` through `-f`; Include and Match discovery use the same root.
Evidence continues to contain product paths such as `/etc/ssh/sshd_config`,
not host-side temporary paths.

The production Module Runner constructs a new environment containing only
PATH, locale, distro, version, and module version. It never forwards
`OS_GUARD_TEST_ROOT`, so a Central job or inherited Agent environment cannot
activate the fixture path. This support is sufficient for CHECK regression,
but not for U-01 HARDEN: an approved alternative administrator path, console
recovery evidence, effective syntax verification, reload orchestration, and
session-safe rollback remain absent.

## U-02 isolated CHECK support

`U-02.sh` resolves login.defs, pwquality, pwhistory, and PAM files below the
same test-only root while keeping standard product paths in JSON evidence.
Fixtures exercise the existing complete-policy decision, weak values, invalid
values, and PAM include review without changing the decision thresholds.

This does not make U-02 HARDEN safe. Rocky authselect ownership and generated
profiles are not represented by the current CHECK result, and authentication
configuration requires a multi-file transaction plus an OS-native validation
step. Direct edits to authselect-managed outputs remain prohibited.

### Distribution authentication sources

On Rocky 9/10, authselect commonly owns the effective `system-auth` and
`password-auth` outputs. The selected profile is recorded under
`/etc/authselect`, while profile templates may come from vendor or custom
authselect directories. Editing only `/etc/pam.d/system-auth` can be overwritten
by a later authselect operation and cannot be considered a durable remediation.
The current CHECK reads the effective system-auth stack but does not establish
which authselect profile/template generated it or validate password-auth as an
equivalent effective path. U-02 HARDEN therefore needs profile provenance,
custom-profile ownership, generation validation, and rollback of both source
and generated state.

On Ubuntu 22/24, `common-password` is the effective stack inspected by the
current CHECK. pam-auth-update and package profiles can generate or update the
common-* files, so a direct edit is safe only after proving that the file is an
approved static source. The current include/substack detection correctly moves
ambiguous stacks to PENDING, but it does not authenticate a user or prove that
every PAM consumer selects the same stack.

Static CHECK can verify module presence, control flags, argument values, and
relative ordering. It cannot prove successful interactive authentication,
application-specific PAM service selection, or authselect/pam-auth-update
regeneration behavior. Those require isolated OS-native integration tests and
must not be simulated as CHECK GOOD.

## U-36 KISA and CHECK scope

The 2026 KISA U-36 page describes r-command examples as rsh/remsh, rlogin,
rexec, and rsync. Therefore the mere presence of rsync in the current CHECK is
not unsupported by the guide. The action procedure, however, focuses on
shell/login/exec services and ports 514/513/512. The project still needs an
explicit interpretation for standalone rsync daemon units before treating
`rsync.service` or `rsyncd.service` exactly like rlogin/rsh/rexec.

Current runtime CHECK marks every detected active service as unresolved and
therefore PENDING. Its fixture can express approved/unapproved counts, but no
signed operating-policy projection supplies those counts in production. The
existing U-36 HARDEN wrapper correctly stops at `CHECK_STATE_NOT_ACTIONABLE`.
It must remain a safety wrapper and must not be counted as A/B completion.

Required decision:

1. Confirm whether standalone rsync daemon activation is in the actionable
   U-36 service scope or belongs to a separate service-policy review.
2. Define signed per-unit necessity decisions, management-path proof, active
   dependency evidence, and a recovery plan.
3. Bind those decisions to the exact unit-state fingerprint used by PREVIEW.

Recommended initial automatic-action allowlist, subject to Central policy
approval, is limited to `rsh`, `rlogin`, and `rexec` systemd service/socket
units plus their exact inetd/xinetd activation records. `rsync.service` and
`rsyncd.service` should remain review-only until a signed retirement decision,
active client/job inventory, backup or cluster dependency evidence, and exact
enablement-state recovery have been verified. The existing wrapper remains
fail-closed and is not changed by this recommendation.

## U-65 verified NTP policy evidence

The policy verifier already validates an `NTP_TIME_SYNCHRONIZATION` envelope
scoped only to U-65. A successful `PolicyEvidenceValidationResult` contains
the verified envelope and its `approved_time_sources`; it is protected by
trusted time, revocation, persistent version state, Agent/Server scope,
Manifest, and module-version checks.

There is no approved channel from that Python result to a CHECK subprocess.
The Module Runner intentionally passes a fixed environment, and U-65 only
observes an aggregate source count. Passing `approved=1` through an environment
variable would discard policy identity, version, hash, expiry, and the actual
source comparison and is forbidden.

Before integration, define a locally generated read-only decision projection
containing at least:

- policy id, version, hash, type, issuer, expiry, Server and Agent ids;
- item id U-65, Manifest id, and module version;
- canonical approved-source digest and observed-source digest;
- exact source-set comparison result and observation time;
- trusted-time and revocation-state versions.

The projection must be created only from a valid in-memory policy result,
stored in an Agent-owned non-symlink path, bound to one CHECK attempt, and
removed after use. The module input mechanism and Evidence schema require a
Central/Agent contract decision. Until then U-65 stays PENDING when approval
cannot be proved and HARDEN remains deferred.

### Projection trust contract

An unsigned JSON projection is not a trust artifact. Ownership and mode bits
only protect against other local UIDs; they do not protect the projection from
a compromised Agent process running as the same UID. The preferred contract is
to deliver the original signed policy envelope together with an attempt-bound
observation document to a local comparison component that reuses the existing
PolicyVerifier. A comparison result is valid only while all of these bindings
match:

- server id, agent id, job id, attempt id, item id, and policy type;
- policy id, version, SHA-256 hash, signing key id, and expiry;
- manifest id, module version, OS identity, and trusted-time sequence;
- revocation-list id/version and policy-store anti-downgrade state;
- canonical observed-settings digest and collection completion state.

The local transport should be an inherited read-only descriptor or sealed
memory object created specifically for the CHECK child. A reusable path or an
environment-supplied approval boolean is not acceptable. If a file fallback is
ever approved, it additionally needs atomic no-follow creation, private parent
directory ownership, file identity verification before and after reading,
single-attempt naming, expiry, and deletion. These controls still do not create
independent trust against same-UID compromise.

No Agent signing key currently exists for locally signing observations, and
the bearer operating credential must not be repurposed as a signing key. An
independently privileged CHECK broker could reverify the original Central
signature and bind observations, but that requires the future signed CHECK
ticket and IPC authentication contract. Consequently this repository does not
yet create or consume Projection files in the operating CHECK path.

## U-66 verified logging policy evidence

`SYSTEM_LOGGING` is scoped only to U-66 and validates retention days, whether
remote forwarding is required, and collector references. As with U-65, no
approved projection reaches the Shell CHECK.

The current policy schema is also insufficient to prove the existing CHECK's
effective configuration. It does not define required facility/severity rules,
local storage expectations, how collector references resolve to configured
destinations, transport requirements, or journald/rsyslog precedence. A
boolean `policy_verified` cannot safely represent these comparisons.

U-66 integration therefore requires both:

1. a versioned logging-policy schema for required rules, retention/storage,
   forwarding transport, and trusted collector reference resolution; and
2. the same attempt-bound local projection mechanism, with separate logging
   fields and comparison digests rather than reuse of the NTP decision.

Missing, expired, revoked, mismatched, or unresolvable policy evidence must
leave U-66 PENDING or in its existing fail-closed state. No logging HARDEN is
safe before this contract exists.

The SYSTEM_LOGGING schema must be extended without implicit defaults to cover:

- required facility/severity selectors and mandatory local destinations;
- retention scope, storage backend, rotation ownership, and retention unit;
- whether remote forwarding is required, optional, or prohibited;
- resolved collector identities/endpoints, transport, and TLS requirements;
- journald persistence/forwarding expectations and rsyslog precedence;
- acceptable include sources and treatment of dynamic/generated config.

Collector references alone cannot be compared with a redacted aggregate CHECK
result. Reference resolution must happen inside the trusted policy comparison
component, and transport secrets must never enter CHECK Evidence.

## Non-goals

- No policy boolean is accepted from an environment variable.
- Fixture inputs are not operating policy and never authorize host mutation.
- No Grant is consumed and no HARDEN execution path is connected.
- No SSH, PAM, NTP, logging, service, account, or firewall setting is changed.
