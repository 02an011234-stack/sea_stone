"""Cryptographic policy checks for a pinned OS Guard CA certificate."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


class CaPolicyError(RuntimeError):
    """Raised when a certificate is not suitable as an Agent trust anchor."""


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def validate_ca_certificate_policy(path: Path, expected_sha256: str) -> None:
    """Require a current CA certificate with the expected DER fingerprint."""

    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except (OSError, ValueError, x509.ExtensionNotFound):
        raise CaPolicyError("CA certificate policy validation failed") from None
    if not basic_constraints.ca:
        raise CaPolicyError("certificate is not authorized as a CA")
    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.key_cert_sign:
        raise CaPolicyError("CA certificate cannot sign certificates")

    now = datetime.now(timezone.utc)
    not_before = (
        certificate.not_valid_before_utc
        if hasattr(certificate, "not_valid_before_utc")
        else _utc(certificate.not_valid_before)
    )
    not_after = (
        certificate.not_valid_after_utc
        if hasattr(certificate, "not_valid_after_utc")
        else _utc(certificate.not_valid_after)
    )
    if now < not_before or now > not_after:
        raise CaPolicyError("CA certificate is outside its validity period")
    actual_fingerprint = hashlib.sha256(
        certificate.public_bytes(Encoding.DER)
    ).hexdigest()
    if actual_fingerprint != expected_sha256.lower():
        raise CaPolicyError("CA certificate fingerprint mismatch")
