# OS Guard Unix Agent E2E lab package

This archive is a development artifact for an isolated Ubuntu or Rocky test
VM. It is not an operating HARDEN release.

## Safety state

- The installed Manifest authorizes `CHECK` only.
- The Agent advertises and claims `CHECK` only.
- `HARDEN`, `RECHECK`, and `ROLLBACK` task claims are rejected.
- Signed Policy and Grant verification is read-only; every result keeps
  `operational_use_allowed=false`.
- Files under `modules/unix/harden/` are fixture-validated development sources.
  Their presence does not authorize execution on a host.
- No registration token, operating credential, private key, or CA private
  material is included.

## Supported installation target

- Ubuntu 22.04 and 24.04
- Rocky Linux 9 and 10
- systemd
- Python 3.9 or newer
- offline wheels for `cryptography>=41` and all transitive dependencies

The installer creates an isolated Agent virtual environment and installs only
from a trusted offline wheelhouse. It never changes packages in the system
Python environment and it does not download dependencies. Python 3.9/3.10
also requires a `tomli` wheel. A production package still requires a signed
wheel baseline and package-signing policy.

## Installation

For a Central-generated server-specific bundle, the protected registration,
CA certificate, and compatible offline wheelhouse use the paths documented in
`docs/unix_server_bundle_contract.md`. Installation then requires no arguments:

```sh
sudo ./install.sh
```

For development or recovery, explicit paths remain supported. Do not put a
real operating credential inside this archive.

```sh
chmod 0600 /protected/path/registration.json
sudo ./install.sh \
  --wheelhouse /protected/path/wheelhouse \
  --ca-certificate /protected/path/os-guard-ca.crt \
  --registration-file /protected/path/registration.json
```

The wheelhouse must contain Linux wheels compatible with the target OS and
architecture. For Ubuntu 22.04 with Python 3.10 this normally includes
`cryptography`, `cffi`, `pycparser`, and `tomli`. Installation fails before
systemd activation if pip cannot resolve the complete offline dependency set
or the installed cryptography version is below 41.0.0.

Example shape with non-functional values:

```json
{
  "schema_version": "2.0",
  "family": "UNIX",
  "enrollment_id": "enrollment-example",
  "token": "example-one-time-value",
  "expires_at": "2099-01-01T00:00:00Z",
  "server_id": "server-example",
  "central_server_url": "https://central.example/agent-api/v2",
  "ca_sha256_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "enrollment_header": "X-Enrollment-Token"
}
```

The TLS client always validates the certificate chain and hostname. The
server-specific Installer verifies the packaged CA certificate fingerprint
over DER bytes, validates CA policy, and configures that CA for TLS chain and
hostname verification before Enrollment. An unauthenticated network CA
download is never trusted automatically.

## Implemented Central CHECK flow

`Enrollment -> Heartbeat -> Inventory -> Claim CHECK -> local Manifest ->
local U-xx.sh -> Evidence -> Result ACK -> COMPLETED event ACK`

FULL and PARTIAL CHECK are supported. Evidence, Result, and Event requests are
stored in the durable Outbox until their ACK is journaled. Pending transfers
are retried after a process restart. A reassigned attempt discards only unsent
entries belonging to the stale attempt.

## Blocked flow

`HARDEN -> RECHECK -> ROLLBACK` is intentionally blocked in the operating
Agent. Existing Central endpoints accept CHECK transport, but the repository
has no agreed task/lease/result contract that safely authorizes host mutation,
lease renewal during mutation, RECHECK causality, or ROLLBACK authority.

Before enabling it, Central and Agent must agree on:

1. signed Policy, trusted-time, revocation, and one-time Grant delivery;
2. PREVIEW and state-fingerprint binding;
3. atomic Grant consumption immediately before mutation;
4. 120-second lease renewal and fail-closed behavior;
5. HARDEN/RECHECK/ROLLBACK Result and Event schemas;
6. crash recovery states that never replay a mutation automatically;
7. backup identity, ownership, expiry, and rollback authorization.

## VM verification boundary

Run installation and CHECK tests first. Take a VM snapshot before any future
HARDEN experiment. Do not enable HARDEN merely because fixture source is
present. High-risk SSH, PAM, firewall, authentication, NFS, and network-service
changes require item-specific approval and recovery validation.

Verify the archive checksum before extraction:

```sh
sha256sum -c os-guard-unix-agent-e2e-lab-v0.1.0-dev.tar.gz.sha256
tar -tzf os-guard-unix-agent-e2e-lab-v0.1.0-dev.tar.gz
```
