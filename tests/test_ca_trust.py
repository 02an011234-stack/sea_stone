from __future__ import annotations

import hashlib
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from os_guard_agent.agent import Agent
from os_guard_agent.ca_policy import CaPolicyError, validate_ca_certificate_policy
from os_guard_agent.ca_trust import (
    CaTrustError,
    create_verified_ssl_context,
    verify_ca_fingerprint,
)
from os_guard_agent.config import AgentConfig


def write_certificate(path: Path, *, is_ca: bool = True) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OS Guard Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(Encoding.PEM))
    return hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()


def test_ca_der_fingerprint_and_tls_context(tmp_path):
    certificate_path = tmp_path / "os-guard-ca.crt"
    fingerprint = write_certificate(certificate_path)

    assert verify_ca_fingerprint(certificate_path, fingerprint) == fingerprint
    validate_ca_certificate_policy(certificate_path, fingerprint)
    context = create_verified_ssl_context(certificate_path)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_agent_api_client_uses_configured_ca(tmp_path):
    certificate_path = tmp_path / "os-guard-ca.crt"
    write_certificate(certificate_path)
    config = AgentConfig(
        central_server_url="https://central.example.test/agent-api/v2",
        agent_id=None,
        log_path=tmp_path / "agent.log",
        ca_cert_path=certificate_path,
    )

    client = Agent(config)._api_client()
    assert client.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert client.ssl_context.check_hostname is True


def test_ca_fingerprint_mismatch_is_rejected(tmp_path):
    certificate_path = tmp_path / "os-guard-ca.crt"
    write_certificate(certificate_path)

    with pytest.raises(CaTrustError, match="does not match"):
        verify_ca_fingerprint(certificate_path, "0" * 64)


def test_non_ca_certificate_is_rejected(tmp_path):
    certificate_path = tmp_path / "leaf.crt"
    fingerprint = write_certificate(certificate_path, is_ca=False)

    with pytest.raises(CaPolicyError, match="not authorized as a CA"):
        validate_ca_certificate_policy(certificate_path, fingerprint)


def test_ca_symlink_is_rejected(tmp_path):
    certificate_path = tmp_path / "os-guard-ca.crt"
    write_certificate(certificate_path)
    link = tmp_path / "linked-ca.crt"
    try:
        link.symlink_to(certificate_path)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(CaTrustError, match="symbolic links"):
        verify_ca_fingerprint(link, "0" * 64)
