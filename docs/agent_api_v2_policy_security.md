# Agent API v2 policy-security read contract

Status: proposed Agent/server contract. The current repository implements only
the Agent-side HTTPS client and local verification pipeline. No central-server
handler exists yet.

Base URL: `/agent-api/v2`

All requests use `Authorization: Bearer <operating token>`, `Accept:
application/json`, and `Cache-Control: no-store`. TLS certificate and hostname
verification are mandatory. Responses contain the signed envelope itself, not
an unsigned wrapper, and are limited to 1 MiB.

| Evidence | Method and path |
| --- | --- |
| Authenticated time | `GET /policy-security/time-evidence` |
| Current policy/key revocations | `GET /policy-security/revocations/current` |
| Operating policy | `GET /policy-security/policies/{policy_id}/versions/{policy_version}` |
| One-time execution Grant | `GET /policy-security/grants/{grant_id}` |

Expected status handling:

- `200 application/json`: signed evidence envelope.
- `204`, `404`, `410`: required evidence unavailable; validation fails closed.
- `401`, `403`: operating authentication rejected.
- `409`: requested evidence conflicts with current server state.
- `429`, `5xx`: temporary server failure; no immediate execution is allowed.
- Any other status, media type, empty body, or oversized body is rejected.

Agent validation order:

1. Verify and persist fresh signed time evidence.
2. Verify and persist the current signed revocation document using trusted time.
3. Verify policy signature, scope, lifetime, current revocation, and persistent
   anti-downgrade state.
4. Optionally pre-validate a job-bound Grant against the newly verified policy.

Grant retrieval is read-only staging. It does not consume the Grant and cannot
authorize HARDEN. A future execution path must repeat all current-state checks
and atomically consume the Grant immediately before host mutation.

The API does not accept commands, scripts, module paths, public keys, or trust
store paths. Keys remain locally provisioned. Raw signed documents, tokens, and
policy values must not be logged.
