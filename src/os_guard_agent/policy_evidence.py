"""Read-only retrieval and local verification of signed policy security evidence.

The service performs HTTPS GETs and updates only local security metadata stores.
It never invokes a Unix module, enables HARDEN, or consumes an execution Grant.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace
from enum import Enum

from .api_client import ApiClient, PolicyEvidenceApiError
from .grant import GrantValidationContext, GrantValidationResult, SignedExecutionGrantVerifier
from .models import OperatingCredential
from .policy import PolicyValidationContext, PolicyValidationResult, PolicyVerifier
from .policy_revocation import SignedRevocationVerifier
from .trusted_time import SignedTimeEvidenceVerifier

LOGGER = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class PolicyEvidenceCode(str, Enum):
    VALID = "VALID"
    FETCH_FAILED = "FETCH_FAILED"
    TIME_EVIDENCE_REJECTED = "TIME_EVIDENCE_REJECTED"
    REVOCATION_REJECTED = "REVOCATION_REJECTED"
    POLICY_REJECTED = "POLICY_REJECTED"
    GRANT_REJECTED = "GRANT_REJECTED"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"


@dataclass(frozen=True)
class PolicyEvidenceRequest:
    policy_id: str
    policy_version: int
    grant_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not _IDENTIFIER.fullmatch(
            self.policy_id
        ):
            raise ValueError("policy_id is invalid")
        if (
            not isinstance(self.policy_version, int)
            or isinstance(self.policy_version, bool)
            or self.policy_version < 1
        ):
            raise ValueError("policy_version must be a positive integer")
        if self.grant_id is not None and (
            not isinstance(self.grant_id, str)
            or not _IDENTIFIER.fullmatch(self.grant_id)
        ):
            raise ValueError("grant_id is invalid")


@dataclass(frozen=True)
class PolicyEvidenceValidationResult:
    valid: bool
    code: PolicyEvidenceCode
    message: str
    policy_result: PolicyValidationResult | None = None
    grant_result: GrantValidationResult | None = None
    operational_use_allowed: bool = False


class PolicyEvidenceReceiver:
    """Fetch and verify evidence in dependency order without operational use."""

    def __init__(
        self,
        api_client: ApiClient,
        time_verifier: SignedTimeEvidenceVerifier,
        revocation_verifier: SignedRevocationVerifier,
        policy_verifier: PolicyVerifier,
        grant_verifier: SignedExecutionGrantVerifier,
    ) -> None:
        self._api_client = api_client
        self._time_verifier = time_verifier
        self._revocation_verifier = revocation_verifier
        self._policy_verifier = policy_verifier
        self._grant_verifier = grant_verifier

    def receive_and_validate(
        self,
        credential: OperatingCredential,
        request: PolicyEvidenceRequest,
        policy_context: PolicyValidationContext,
        grant_context: GrantValidationContext | None = None,
    ) -> PolicyEvidenceValidationResult:
        if (
            credential.server_id != policy_context.server_id
            or credential.agent_id != policy_context.agent_id
        ):
            return self._failure(
                PolicyEvidenceCode.CONTEXT_MISMATCH,
                "credential and policy validation scope differ",
            )
        if (request.grant_id is None) != (grant_context is None):
            return self._failure(
                PolicyEvidenceCode.CONTEXT_MISMATCH,
                "Grant request and validation context must be supplied together",
            )
        if grant_context is not None and (
            grant_context.grant_id != request.grant_id
            or grant_context.server_id != credential.server_id
            or grant_context.agent_id != credential.agent_id
        ):
            return self._failure(
                PolicyEvidenceCode.CONTEXT_MISMATCH,
                "Grant retrieval scope differs from the authenticated Agent",
            )

        try:
            time_document = self._api_client.fetch_trusted_time_evidence(credential)
            time_result = self._time_verifier.validate_and_record(
                time_document,
                server_id=credential.server_id,
                agent_id=credential.agent_id,
            )
            if not time_result.valid:
                return self._failure(
                    PolicyEvidenceCode.TIME_EVIDENCE_REJECTED,
                    f"trusted time evidence was rejected ({time_result.code.value})",
                )

            revocation_document = self._api_client.fetch_policy_revocation(credential)
            revocation_result = self._revocation_verifier.validate_and_record(
                revocation_document,
                server_id=credential.server_id,
                clock_trusted=False,
                accept_duplicate=True,
            )
            if not revocation_result.valid:
                return self._failure(
                    PolicyEvidenceCode.REVOCATION_REJECTED,
                    f"policy revocation evidence was rejected ({revocation_result.code.value})",
                )

            policy_document = self._api_client.fetch_operating_policy(
                credential,
                request.policy_id,
                request.policy_version,
            )
            policy_result = self._policy_verifier.validate(
                policy_document,
                policy_context,
                accept_duplicate=True,
                expected_policy_id=request.policy_id,
                expected_policy_version=request.policy_version,
            )
            if not policy_result.valid or policy_result.policy is None:
                return self._failure(
                    PolicyEvidenceCode.POLICY_REJECTED,
                    f"operating policy was rejected ({policy_result.code.value})",
                )
            grant_result: GrantValidationResult | None = None
            if request.grant_id is not None and grant_context is not None:
                grant_document = self._api_client.fetch_execution_grant(
                    credential,
                    request.grant_id,
                )
                grant_result = self._grant_verifier.validate(
                    grant_document,
                    replace(grant_context, policy_result=policy_result),
                )
                if not grant_result.valid:
                    return self._failure(
                        PolicyEvidenceCode.GRANT_REJECTED,
                        f"execution Grant was rejected ({grant_result.code.value})",
                        policy_result=policy_result,
                        grant_result=grant_result,
                    )
        except PolicyEvidenceApiError:
            return self._failure(
                PolicyEvidenceCode.FETCH_FAILED,
                "required policy security evidence could not be retrieved",
            )

        LOGGER.info(
            "Policy evidence validated for read-only staging "
            "(policy_id=%s, version=%s, grant_present=%s)",
            request.policy_id,
            request.policy_version,
            request.grant_id is not None,
        )
        return PolicyEvidenceValidationResult(
            valid=True,
            code=PolicyEvidenceCode.VALID,
            message="policy evidence is valid for staging only",
            policy_result=policy_result,
            grant_result=grant_result,
            operational_use_allowed=False,
        )

    @staticmethod
    def _failure(
        code: PolicyEvidenceCode,
        message: str,
        *,
        policy_result: PolicyValidationResult | None = None,
        grant_result: GrantValidationResult | None = None,
    ) -> PolicyEvidenceValidationResult:
        LOGGER.warning("Policy evidence staging rejected (reason=%s)", code.value)
        return PolicyEvidenceValidationResult(
            False,
            code,
            message,
            policy_result,
            grant_result,
            False,
        )
