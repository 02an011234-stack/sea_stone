from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from os_guard_agent.models import Action, OsInfo
from os_guard_agent.policy import (
    InMemoryPolicyVersionStore,
    PolicyValidationCode,
    PolicyValidationContext,
    PolicyVerifier,
    TrustedPolicyKeyStore,
    canonicalize_json,
)
from os_guard_agent.trusted_time import TrustedTime, TrustedTimeCode, TrustedTimeError


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


class PolicyVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.key_id = "policy-key-2026-a"
        self.key_store = TrustedPolicyKeyStore(
            {self.key_id: self.private_key.public_key()},
            {self.key_id: frozenset({"central-policy-service"})},
        )
        self.context = PolicyValidationContext(
            server_id="server-1",
            agent_id="agent-1",
            os_info=OsInfo(
                distro="ubuntu",
                version="Ubuntu 22.04",
                version_id="22.04",
                kernel="6.8.0",
                hostname="host-1",
                architecture="x86_64",
                supported=True,
            ),
            manifest_id="manifest-unix-67-v1",
            module_version="unix-2026.1",
            allowed_u_codes=frozenset({"U-61", "U-62", "U-64", "U-65", "U-66"}),
            allowed_actions=frozenset({Action.HARDEN}),
            clock_trusted=True,
        )

    def payload(
        self,
        *,
        policy_type: str = "SNMP_ACCESS_CONTROL",
        policy_id: str = "policy-1",
        policy_version: int = 1,
        u_code: str = "U-61",
        values: dict | None = None,
    ) -> dict:
        if values is None:
            values = {"approved_management_networks": ["10.20.0.0/16"]}
        return {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_type": policy_type,
            "issuer_id": "central-policy-service",
            "approved_by": "security-admin-1",
            "approved_at": "2026-01-14T08:00:00Z",
            "issued_at": "2026-01-14T09:00:00Z",
            "valid_from": "2026-01-15T00:00:00Z",
            "expires_at": "2026-02-15T00:00:00Z",
            "target": {
                "server_id": "server-1",
                "agent_ids": ["agent-1"],
                "supported_os": {"rocky": ["9", "10"], "ubuntu": ["22", "24"]},
                "u_codes": [u_code],
                "actions": ["HARDEN"],
                "manifest_ids": ["manifest-unix-67-v1"],
                "module_versions": ["unix-2026.1"],
            },
            "values": values,
        }

    def signed_document(
        self,
        payload: dict | None = None,
        *,
        key_id: str | None = None,
        private_key: Ed25519PrivateKey | None = None,
        algorithm: str = "Ed25519",
        schema_version: str = "1.0",
    ) -> bytes:
        payload = copy.deepcopy(payload or self.payload())
        key_id = key_id or self.key_id
        private_key = private_key or self.private_key
        payload_hash = hashlib.sha256(canonicalize_json(payload)).hexdigest()
        signed_fields = {
            "policy_schema_version": schema_version,
            "signature_algorithm": algorithm,
            "signing_key_id": key_id,
            "payload_sha256": payload_hash,
            "payload": payload,
        }
        envelope = {
            **signed_fields,
            "signature": base64.b64encode(
                private_key.sign(canonicalize_json(signed_fields))
            ).decode("ascii"),
        }
        return json.dumps(envelope, ensure_ascii=False).encode("utf-8")

    def verifier(self, **kwargs) -> PolicyVerifier:
        return PolicyVerifier(
            self.key_store,
            kwargs.pop("version_store", InMemoryPolicyVersionStore()),
            clock=lambda: NOW,
            revocation_state_current=kwargs.pop("revocation_state_current", True),
            **kwargs,
        )

    def assert_code(self, document: bytes, code: PolicyValidationCode, **kwargs) -> None:
        result = self.verifier(**kwargs).validate(document, self.context)
        self.assertFalse(result.valid)
        self.assertEqual(result.code, code)
        self.assertFalse(result.operational_use_allowed)

    def test_valid_signature_hash_scope_and_timestamps(self) -> None:
        result = self.verifier().validate(self.signed_document(), self.context)
        self.assertTrue(result.valid)
        self.assertEqual(result.code, PolicyValidationCode.VALID)
        self.assertEqual(result.policy.payload.policy_id, "policy-1")
        self.assertEqual(result.policy.payload.target.actions, (Action.HARDEN,))
        self.assertRegex(result.policy_hash, r"^[0-9a-f]{64}$")
        self.assertFalse(result.operational_use_allowed)
        self.assertIn("HARDEN execution authorization is not implemented", result.operational_limitations)

    def test_canonical_json_is_order_independent_and_unicode_preserving(self) -> None:
        first = {"é": "값", "a": 2, "z": [True, None]}
        second = {"z": [True, None], "a": 2, "é": "값"}
        expected = '{"a":2,"z":[true,null],"é":"값"}'.encode("utf-8")
        self.assertEqual(canonicalize_json(first), expected)
        self.assertEqual(canonicalize_json(first), canonicalize_json(second))

    def test_canonical_json_rejects_float_and_unsafe_integer(self) -> None:
        with self.assertRaises(ValueError):
            canonicalize_json({"value": 1.5})
        with self.assertRaises(ValueError):
            canonicalize_json({"value": 9_007_199_254_740_992})

    def test_duplicate_json_key_is_rejected(self) -> None:
        document = b'{"policy_schema_version":"1.0","policy_schema_version":"1.0"}'
        self.assert_code(document, PolicyValidationCode.DUPLICATE_JSON_KEY)

    def test_malformed_json_is_rejected(self) -> None:
        self.assert_code(b"{", PolicyValidationCode.MALFORMED_JSON)

    def test_unknown_envelope_field_is_rejected(self) -> None:
        envelope = json.loads(self.signed_document())
        envelope["public_key"] = "must-not-be-trusted"
        self.assert_code(
            json.dumps(envelope).encode(), PolicyValidationCode.INVALID_ENVELOPE
        )

    def test_unsupported_schema_is_rejected(self) -> None:
        self.assert_code(
            self.signed_document(schema_version="2.0"),
            PolicyValidationCode.UNSUPPORTED_SCHEMA_VERSION,
        )

    def test_unsupported_algorithm_is_rejected(self) -> None:
        self.assert_code(
            self.signed_document(algorithm="RSA-PSS"),
            PolicyValidationCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
        )

    def test_untrusted_key_is_rejected_even_with_valid_signature(self) -> None:
        foreign_key = Ed25519PrivateKey.generate()
        self.assert_code(
            self.signed_document(key_id="foreign-key", private_key=foreign_key),
            PolicyValidationCode.UNTRUSTED_SIGNING_KEY,
        )

    def test_revoked_key_is_rejected(self) -> None:
        self.assert_code(
            self.signed_document(),
            PolicyValidationCode.SIGNING_KEY_REVOKED,
            revoked_key_ids=frozenset({self.key_id}),
        )

    def test_payload_hash_mismatch_is_rejected(self) -> None:
        envelope = json.loads(self.signed_document())
        envelope["payload"]["policy_id"] = "changed-policy"
        self.assert_code(
            json.dumps(envelope).encode(), PolicyValidationCode.HASH_MISMATCH
        )

    def test_header_tampering_invalidates_signature(self) -> None:
        envelope = json.loads(self.signed_document())
        envelope["signing_key_id"] = "another-local-key"
        another_key = Ed25519PrivateKey.generate()
        verifier = PolicyVerifier(
            TrustedPolicyKeyStore(
                {
                    self.key_id: self.private_key.public_key(),
                    "another-local-key": another_key.public_key(),
                },
                {
                    self.key_id: frozenset({"central-policy-service"}),
                    "another-local-key": frozenset({"central-policy-service"}),
                },
            ),
            InMemoryPolicyVersionStore(),
            clock=lambda: NOW,
            revocation_state_current=True,
        )
        result = verifier.validate(json.dumps(envelope).encode(), self.context)
        self.assertEqual(result.code, PolicyValidationCode.INVALID_SIGNATURE)

    def test_invalid_base64_signature_is_rejected(self) -> None:
        envelope = json.loads(self.signed_document())
        envelope["signature"] = "not base64!"
        self.assert_code(
            json.dumps(envelope).encode(), PolicyValidationCode.INVALID_SIGNATURE
        )

    def test_unknown_policy_type_is_rejected(self) -> None:
        payload = self.payload(policy_type="ARBITRARY_COMMAND")
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.UNSUPPORTED_POLICY_TYPE
        )

    def test_signing_key_must_be_bound_to_payload_issuer(self) -> None:
        payload = self.payload()
        payload["issuer_id"] = "different-policy-service"
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.ISSUER_MISMATCH
        )

    def test_policy_type_must_match_u_code(self) -> None:
        payload = self.payload(u_code="U-62")
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.U_CODE_SCOPE_INVALID
        )

    def test_snmp_policy_values_are_typed(self) -> None:
        payload = self.payload(values={"approved_management_networks": ["10.0.0.7/24"]})
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.INVALID_POLICY_VALUES
        )

    def test_login_banner_policy_values_are_typed(self) -> None:
        payload = self.payload(
            policy_type="LOGIN_WARNING_MESSAGE",
            u_code="U-62",
            values={"approved_banner_text": "Authorized use only"},
        )
        self.assertTrue(self.verifier().validate(self.signed_document(payload), self.context).valid)

    def test_patch_policy_values_are_typed(self) -> None:
        payload = self.payload(
            policy_type="SECURITY_PATCH_MANAGEMENT",
            u_code="U-64",
            values={
                "change_window_start": "2026-01-20T01:00:00Z",
                "change_window_end": "2026-01-20T03:00:00Z",
                "reboot_approved": False,
                "service_impact_approved": True,
            },
        )
        self.assertTrue(self.verifier().validate(self.signed_document(payload), self.context).valid)

    def test_ntp_policy_values_are_typed(self) -> None:
        payload = self.payload(
            policy_type="NTP_TIME_SYNCHRONIZATION",
            u_code="U-65",
            values={"approved_time_sources": ["time.example.org", "192.0.2.10"]},
        )
        self.assertTrue(self.verifier().validate(self.signed_document(payload), self.context).valid)

    def test_logging_policy_values_are_typed(self) -> None:
        payload = self.payload(
            policy_type="SYSTEM_LOGGING",
            u_code="U-66",
            values={
                "retention_days": 365,
                "remote_forwarding_required": True,
                "collector_refs": ["collector-primary"],
            },
        )
        self.assertTrue(self.verifier().validate(self.signed_document(payload), self.context).valid)

    def test_untrusted_clock_is_rejected(self) -> None:
        context = copy.copy(self.context)
        object.__setattr__(context, "clock_trusted", False)
        result = self.verifier().validate(self.signed_document(), context)
        self.assertEqual(result.code, PolicyValidationCode.UNTRUSTED_CLOCK)

    def test_not_yet_valid_policy_is_rejected(self) -> None:
        payload = self.payload()
        payload["valid_from"] = "2026-01-16T00:00:00Z"
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.POLICY_NOT_YET_VALID
        )

    def test_expired_policy_is_rejected(self) -> None:
        payload = self.payload()
        payload["expires_at"] = "2026-01-15T12:00:00Z"
        self.assert_code(self.signed_document(payload), PolicyValidationCode.POLICY_EXPIRED)

    def test_server_scope_mismatch_is_rejected(self) -> None:
        payload = self.payload()
        payload["target"]["server_id"] = "server-2"
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.SERVER_SCOPE_MISMATCH
        )

    def test_agent_scope_mismatch_is_rejected(self) -> None:
        payload = self.payload()
        payload["target"]["agent_ids"] = ["agent-2"]
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.AGENT_SCOPE_MISMATCH
        )

    def test_os_scope_mismatch_is_rejected(self) -> None:
        payload = self.payload()
        payload["target"]["supported_os"] = {"rocky": ["9"]}
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.OS_SCOPE_MISMATCH
        )

    def test_unsupported_local_os_state_is_rejected(self) -> None:
        context = copy.copy(self.context)
        object.__setattr__(
            context,
            "os_info",
            OsInfo(
                distro="ubuntu",
                version="Ubuntu 22.04",
                version_id="22.04",
                kernel="test-kernel",
                hostname="test-host",
                architecture="x86_64",
                supported=False,
                unsupported_reason="test",
            ),
        )
        result = self.verifier().validate(self.signed_document(), context)
        self.assertEqual(result.code, PolicyValidationCode.OS_SCOPE_MISMATCH)

    def test_all_four_supported_os_scopes_are_accepted(self) -> None:
        for distro, version_id in (
            ("rocky", "9.5"),
            ("rocky", "10.0"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        ):
            with self.subTest(distro=distro, version_id=version_id):
                context = copy.copy(self.context)
                object.__setattr__(
                    context,
                    "os_info",
                    OsInfo(
                        distro=distro,
                        version=version_id,
                        version_id=version_id,
                        kernel="test-kernel",
                        hostname="test-host",
                        architecture="x86_64",
                        supported=True,
                    ),
                )
                result = self.verifier().validate(self.signed_document(), context)
                self.assertTrue(result.valid)

    def test_local_u_code_allowlist_is_enforced(self) -> None:
        context = copy.copy(self.context)
        object.__setattr__(context, "allowed_u_codes", frozenset({"U-62"}))
        result = self.verifier().validate(self.signed_document(), context)
        self.assertEqual(result.code, PolicyValidationCode.U_CODE_SCOPE_INVALID)

    def test_local_action_allowlist_is_enforced(self) -> None:
        context = copy.copy(self.context)
        object.__setattr__(context, "allowed_actions", frozenset({Action.CHECK}))
        result = self.verifier().validate(self.signed_document(), context)
        self.assertEqual(result.code, PolicyValidationCode.ACTION_SCOPE_INVALID)

    def test_manifest_scope_mismatch_is_rejected(self) -> None:
        payload = self.payload()
        payload["target"]["manifest_ids"] = ["another-manifest"]
        self.assert_code(
            self.signed_document(payload), PolicyValidationCode.MANIFEST_SCOPE_MISMATCH
        )

    def test_module_version_scope_mismatch_is_rejected(self) -> None:
        payload = self.payload()
        payload["target"]["module_versions"] = ["unix-2027.1"]
        self.assert_code(
            self.signed_document(payload),
            PolicyValidationCode.MODULE_VERSION_SCOPE_MISMATCH,
        )

    def test_revoked_policy_id_is_rejected(self) -> None:
        self.assert_code(
            self.signed_document(),
            PolicyValidationCode.POLICY_REVOKED,
            revoked_policy_ids=frozenset({"policy-1"}),
        )

    def test_version_store_blocks_duplicate_downgrade_and_hash_conflict(self) -> None:
        store = InMemoryPolicyVersionStore()
        verifier = self.verifier(version_store=store)
        version_two = self.signed_document(self.payload(policy_version=2))
        self.assertTrue(verifier.validate(version_two, self.context).valid)
        self.assertEqual(
            verifier.validate(version_two, self.context).code,
            PolicyValidationCode.POLICY_DUPLICATE,
        )
        downgrade = self.signed_document(self.payload(policy_version=1))
        self.assertEqual(
            verifier.validate(downgrade, self.context).code,
            PolicyValidationCode.POLICY_DOWNGRADE,
        )
        conflict_payload = self.payload(policy_version=2)
        conflict_payload["approved_by"] = "security-admin-2"
        self.assertEqual(
            verifier.validate(self.signed_document(conflict_payload), self.context).code,
            PolicyValidationCode.POLICY_VERSION_CONFLICT,
        )

    def test_local_pem_trust_store_loads_ed25519_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            pem = self.private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            (directory / f"{self.key_id}.pem").write_bytes(pem)
            verifier = PolicyVerifier(
                TrustedPolicyKeyStore.from_directory(
                    directory,
                    {self.key_id: frozenset({"central-policy-service"})},
                ),
                InMemoryPolicyVersionStore(),
                clock=lambda: NOW,
                revocation_state_current=True,
            )
            self.assertTrue(verifier.validate(self.signed_document(), self.context).valid)

    def test_policy_document_key_or_path_is_never_accepted(self) -> None:
        envelope = json.loads(self.signed_document())
        envelope["signing_key_path"] = "../../untrusted.pem"
        self.assert_code(
            json.dumps(envelope).encode(), PolicyValidationCode.INVALID_ENVELOPE
        )

    def test_ephemeral_version_or_stale_revocation_blocks_operational_use(self) -> None:
        result = self.verifier(revocation_state_current=False).validate(
            self.signed_document(), self.context
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.operational_use_allowed)
        self.assertIn("persistent anti-rollback state is not configured", result.operational_limitations)
        self.assertIn(
            "policy and signing-key revocation state is not current",
            result.operational_limitations,
        )

    def test_authenticated_time_provider_replaces_boolean_clock_assertion(self) -> None:
        class Provider:
            def current_time(self):
                return TrustedTime(
                    value=NOW,
                    evidence_id="time-1",
                    source_id="signed-server-time",
                    authenticated=True,
                    uncertainty_seconds=1,
                    evidence_expires_at=datetime(2026, 1, 16, tzinfo=timezone.utc),
                )

        context = replace(self.context, clock_trusted=False)
        result = self.verifier(trusted_time_provider=Provider()).validate(
            self.signed_document(), context
        )
        self.assertTrue(result.valid)

    def test_unavailable_authenticated_time_rejects_policy(self) -> None:
        class Provider:
            def current_time(self):
                raise TrustedTimeError(
                    TrustedTimeCode.TIME_STATE_UNAVAILABLE,
                    "test time unavailable",
                )

        result = self.verifier(trusted_time_provider=Provider()).validate(
            self.signed_document(), self.context
        )
        self.assertEqual(result.code, PolicyValidationCode.UNTRUSTED_CLOCK)


if __name__ == "__main__":
    unittest.main()
