"""CA certificate validation shared by installation and Agent TLS clients."""

from __future__ import annotations

import hashlib
import ssl
import stat
from pathlib import Path


MAX_CA_CERTIFICATE_BYTES = 1024 * 1024


class CaTrustError(RuntimeError):
    """Raised when a product CA file cannot be trusted safely."""


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise CaTrustError("CA certificate path must not contain symbolic links")


def certificate_der(path: Path) -> bytes:
    """Return DER bytes for exactly one safely opened PEM certificate."""

    try:
        _reject_symlink_components(path)
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise CaTrustError("CA certificate is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_CA_CERTIFICATE_BYTES:
            raise CaTrustError("CA certificate size is invalid")
        pem = path.read_text(encoding="ascii")
    except CaTrustError:
        raise
    except (OSError, UnicodeError):
        raise CaTrustError("CA certificate cannot be read") from None

    if pem.count("-----BEGIN CERTIFICATE-----") != 1 or pem.count(
        "-----END CERTIFICATE-----"
    ) != 1:
        raise CaTrustError("CA bundle must contain exactly one PEM certificate")
    try:
        return ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        raise CaTrustError("CA certificate PEM is invalid") from None


def verify_ca_fingerprint(path: Path, expected_sha256: str) -> str:
    """Verify the Registration fingerprint over certificate DER bytes."""

    normalized = expected_sha256.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise CaTrustError("expected CA fingerprint is invalid")
    actual = hashlib.sha256(certificate_der(path)).hexdigest()
    if actual != normalized:
        raise CaTrustError("CA certificate fingerprint does not match registration")
    return actual


def create_verified_ssl_context(ca_cert_path: Path | None) -> ssl.SSLContext:
    """Create a hostname-verifying context with optional product CA trust."""

    try:
        context = (
            ssl.create_default_context(cafile=str(ca_cert_path))
            if ca_cert_path is not None
            else ssl.create_default_context()
        )
    except (OSError, ssl.SSLError):
        raise CaTrustError("verified TLS context could not be created") from None
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise CaTrustError("TLS certificate and hostname verification are required")
    return context
