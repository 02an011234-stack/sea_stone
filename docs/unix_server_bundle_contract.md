# Unix server-specific installation bundle

This contract defines the files Central must add to the generic Unix Agent
release before offering a server-specific download. The bundle is installed
locally; it is not a remote installation protocol.

## Required layout

```text
os-guard-unix-agent-e2e-lab-v0.1.0-dev/
├── install.sh
├── registration/
│   └── registration.json          mode 0600
├── trust/
│   └── os-guard-ca.crt            mode 0644
├── wheelhouse/
│   ├── cryptography-*.whl         target-compatible Linux wheel
│   ├── cffi-*.whl
│   ├── pycparser-*.whl
│   └── tomli-*.whl                required for Python 3.9/3.10
└── ... generic Agent payload
```

The registration JSON retains the agreed nine-field schema. Its
`ca_sha256_fingerprint` is the lowercase SHA-256 digest of the DER bytes of
the single PEM certificate in `trust/os-guard-ca.crt`.

The archive must be server-specific, access-controlled, short-lived, and
must never contain an operating credential or CA private key. Central must
preserve registration mode 0600 in the archive. The archive itself still
contains the one-time token after successful installation; operators must
delete the archive and any copies according to the enrollment retention
policy.

## One-step installation

```sh
sudo ./install.sh
```

The Installer recognizes only the exact paths above. Explicit
`--registration-file`, `--wheelhouse`, and `--ca-certificate` arguments remain
available for development and recovery.

The Installer validates the protected registration file, verifies the CA
fingerprint over DER bytes, creates an isolated virtual environment, installs
dependencies with `pip --no-index --only-binary=:all:`, validates that the
certificate is a current CA, installs the public CA into the Agent-specific
configuration, performs TLS chain and hostname verification, and only then
sends the enrollment token.

## CA delivery boundary

The Agent does not automatically trust a CA downloaded over an otherwise
untrusted connection. `GET /downloads/os-guard-ca.crt` may be used only when
the HTTPS connection is already authenticated by an existing trust anchor.
For first installation, Central must include the fingerprint-matched CA in
the authenticated server-specific package.

## Central packaging responsibilities

- select wheels matching Ubuntu/Rocky, CPU architecture, Python ABI, and glibc;
- generate a fresh, unexpired, one-time registration JSON for one server;
- include no credential, private key, log, Outbox, or result data;
- sign or otherwise authenticate the complete download artifact;
- set registration mode 0600 and publish the artifact checksum;
- reject token reuse and keep enrollment idempotency semantics server-side.

The generic development archive does not contain a registration file, CA, or
wheel files and therefore is not final proof of Central one-step E2E success.
