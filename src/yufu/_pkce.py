"""RFC 7636 Proof Key for Code Exchange helpers."""

from __future__ import annotations

import base64
import hashlib
import secrets
import string

VERIFIER_LENGTH = 32
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def new_verifier() -> str:
    """Return a cryptographically random RFC 7636 code verifier."""

    return _b64url(secrets.token_bytes(VERIFIER_LENGTH))


def challenge(verifier: str) -> str:
    """Return the S256 challenge for a verifier."""

    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def validate_verifier(verifier: str) -> None:
    """Validate RFC 7636 syntax and length bounds.

    Raises:
        ValueError: when the verifier is not 43-128 unreserved characters.
    """

    if not 43 <= len(verifier) <= 128:
        raise ValueError("yufu: PKCE verifier must be between 43 and 128 characters")
    if any(character not in _UNRESERVED for character in verifier):
        raise ValueError("yufu: PKCE verifier contains an invalid character")
