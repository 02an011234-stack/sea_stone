# OS Guard Unix local installation foundation

Status: local installation and protected registration-file Enrollment. Central
installation Reporter, signed package verification, CA bootstrap, and the
privileged CHECK Helper are not enabled by this implementation.

## Local install

From an extracted, trusted release directory, the administrator runs one
command:

```sh
sudo ./install.sh install
```

The installer validates the supported distribution and systemd, verifies that
the release tree has no symbolic links, creates the non-login `osguard`
identity, installs root-owned code and CHECK modules, prepares product-owned
state/log paths, installs the hardened systemd unit, and runs local Preflight.

The service is enabled immediately. It is started only when a protected,
reloadable operating credential already exists. On a first installation the
result therefore reports `enrollment_required=true`; automatic delivery of the
Central registration can be performed in the same administrator operation:

```sh
sudo ./install.sh --registration-file /protected/path/registration.json
```

The currently implemented registration schema is:

```json
{
  "schema_version": "2.0",
  "family": "UNIX",
  "enrollment_id": "enrollment-example",
  "token": "example-one-time-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "server_id": "server-example",
  "central_server_url": "https://central.example/agent-api/v2",
  "ca_sha256_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "enrollment_header": "X-Enrollment-Token"
}
```

The file must be a regular, non-symlink file no larger than 64 KiB, owned by
root or the sudo-invoking user, with no group/other access. Values above are
illustrative and are not valid credentials.

The installer validates the registration document before changing product
files, configures a fresh Agent configuration with its HTTPS Central URL, and
stages a mode-0600 copy for the `osguard` identity. It invokes the existing
Enrollment CLI through `runuser`; the Enrollment Token is never placed in an
argument. The service starts only after the resulting operating credential is
atomically stored and reloaded. On success the original registration file is
unlinked. On authentication, network, response-loss, or credential-storage
failure it is retained for explicit recovery and is not retried automatically.

The installer input must be owned by root or the invoking sudo user and must
not grant group/other permissions. Direct Enrollment must still be launched as
the `osguard` identity with an `osguard`-owned mode-0600 file. The credential
directory remains `osguard:osguard` mode 0700 and the credential file is
written atomically with mode 0600. Existing credentials are validated and
preserved; supplying a registration file does not overwrite or consume them.

The installed Agent runs from `/opt/os-guard-agent/.venv`. Installation is
network-free: the virtual environment uses approved host Python packages and a
fixed `.pth` entry for the root-owned Agent source. Production packaging still
needs a signed package dependency baseline or wheelhouse for fully isolated
third-party dependencies; the installer never downloads packages from an
external index.

The HTTP client uses the system CA trust store, requires certificate chain and
hostname verification, and has no `verify=false` path. The registration
`ca_sha256_fingerprint` is validated syntactically but is not used for CA
bootstrap or pinning because Central has not yet defined whether it identifies
the issuing CA or leaf certificate, nor its rotation contract.

### Payload scope limitation

The current development installer copies the complete `modules/` tree. This
means fixture-only HARDEN shell files are present in the root-owned payload even
though the installed Manifest remains CHECK-only, Agent HARDEN dispatch is
disabled, and `operational_use_allowed=false`. Presence in the payload is not
an authorization to execute those files. Before a production package is
approved, release packaging must either exclude inactive HARDEN files or bind
their inclusion to signed package integrity and the approved Policy/Grant
execution boundary. This has not yet been validated on an Ubuntu or Rocky VM.

## Local diagnostics

```sh
sudo ./install.sh preflight
sudo ./install.sh preflight --network
```

The first form performs local validation without contacting Central. The
second also performs a verified TLS hostname/CA handshake. Neither form reads
an Enrollment Token or emits a Central READY state.

When invoked through the root installer, Preflight is delegated with
`runuser` to the `osguard` identity. Its durable-storage probe performs atomic
writes in the state, Outbox/ACK, and log paths, so a successful root-only probe
cannot be mistaken for service-account readiness. A missing credential is
reported as the intentional enrollment-wait condition; an unreadable or
invalid credential is a failure.

## Reinstall and removal

Running `sudo ./install.sh install` again replaces product code through a
same-filesystem staging directory while preserving configuration, Credential,
Outbox, and ACK state.

The previous payload remains available until the `osguard`-context post-install
Preflight succeeds. A failure restores that payload, and a later installer run
first recovers an interrupted payload transaction. Configuration, Credential,
Outbox, and ACK data are outside the payload transaction and are never removed
by a normal reinstall.

```sh
sudo ./install.sh uninstall
sudo ./install.sh uninstall --purge-state
```

The default removal preserves configuration and state for recovery. The
explicit purge option removes only OS Guard product paths. Neither operation
changes SSH keys, PAM, firewall, `/etc/shadow`, or other host security policy.

## Service boundary

`os-guard-agent.service` runs as `osguard` with no capabilities and a read-only
system view except for its state and log directories. The privileged CHECK
Helper is not installed. If an unapproved Helper binary is present, Preflight
fails closed.
