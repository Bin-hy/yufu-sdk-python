"""The small RS256/JWKS subset used by the Runtime SDK.

This module is private. Callers receive typed claims from :mod:`yufu` and never
need to handle raw JOSE objects.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import MAX_TOKEN_SIZE

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class JoseError(Exception):
    """A malformed or unverifiable JOSE object."""


class UnsupportedAlgorithmError(JoseError):
    """The token uses an algorithm other than RS256."""


class KeyNotFoundError(JoseError):
    """The JWKS has no key for the token's ``kid``."""


def _reject_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant {value}")


def b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise JoseError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise JoseError("invalid base64url value") from exc


@dataclass(frozen=True, slots=True)
class JwtHeader:
    alg: str
    kid: str
    typ: str


@dataclass(slots=True)
class ParsedJwt:
    header: JwtHeader
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes

    def verify(self, key: rsa.RSAPublicKey) -> None:
        if key.key_size < 2048:
            raise JoseError("RSA key is smaller than 2048 bits")
        try:
            key.verify(self.signature, self.signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise JoseError("invalid signature") from exc


def parse_jwt(token: str) -> ParsedJwt:
    """Split and decode a compact JWS without verifying it."""

    if not token or len(token) > MAX_TOKEN_SIZE:
        raise JoseError("invalid token")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("invalid token")

    try:
        header_data = json.loads(b64url_decode(parts[0]), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise JoseError("invalid token header") from exc
    if not isinstance(header_data, dict):
        raise JoseError("invalid token header")
    alg = header_data.get("alg")
    kid = header_data.get("kid")
    typ = header_data.get("typ", "")
    if not isinstance(alg, str) or not isinstance(kid, str) or not isinstance(typ, str):
        raise JoseError("invalid token header")
    if alg != "RS256":
        raise UnsupportedAlgorithmError("unsupported algorithm")
    if not kid:
        raise JoseError("token header is missing kid")

    try:
        claims_data = json.loads(b64url_decode(parts[1]), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise JoseError("invalid token claims") from exc
    if not isinstance(claims_data, dict):
        raise JoseError("invalid token claims")

    signature = b64url_decode(parts[2])
    if not signature:
        raise JoseError("invalid token signature")
    return ParsedJwt(
        header=JwtHeader(alg=alg, kid=kid, typ=typ),
        claims=claims_data,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=signature,
    )


def _jwk_public_key(jwk: Mapping[str, Any]) -> rsa.RSAPublicKey:
    n_bytes = b64url_decode(_required_string(jwk, "n"))
    e_bytes = b64url_decode(_required_string(jwk, "e"))
    if not n_bytes:
        raise JoseError("invalid JWK modulus")
    if not e_bytes:
        raise JoseError("invalid JWK exponent")
    modulus = int.from_bytes(n_bytes, "big")
    exponent = int.from_bytes(e_bytes, "big")
    if exponent < 3 or exponent > (1 << 63) - 1:
        raise JoseError("invalid JWK exponent")
    if modulus.bit_length() < 2048:
        raise JoseError("RSA key is smaller than 2048 bits")
    try:
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except ValueError as exc:
        raise JoseError("invalid RSA public key") from exc


def _required_string(data: Mapping[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise JoseError(f"JWK is missing {name}")
    return value


def parse_jwks(data: bytes | str | Mapping[str, Any]) -> dict[str, rsa.RSAPublicKey]:
    """Parse and validate an RSA JWKS document."""

    if isinstance(data, Mapping):
        document: Any = data
    else:
        try:
            document = json.loads(data, parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError) as exc:
            raise JoseError("invalid JWKS") from exc
    if not isinstance(document, dict):
        raise JoseError("invalid JWKS")
    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        raise JoseError("empty JWKS")

    result: dict[str, rsa.RSAPublicKey] = {}
    for item in keys:
        if not isinstance(item, dict):
            continue
        if item.get("kty") != "RSA":
            continue
        if item.get("use", "") not in {"", "sig"}:
            continue
        if item.get("alg", "") not in {"", "RS256"}:
            continue
        kid = item.get("kid")
        if not isinstance(kid, str) or not kid:
            raise JoseError("JWK is missing kid")
        result[kid] = _jwk_public_key(item)
    if not result:
        raise JoseError("JWKS has no usable RS256 signing key")
    return result


def string_claim(claims: Mapping[str, Any], name: str) -> str | None:
    value = claims.get(name)
    return value if isinstance(value, str) else None


def number_claim(claims: Mapping[str, Any], name: str) -> int | None:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def bool_claim(claims: Mapping[str, Any], name: str) -> bool | None:
    value = claims.get(name)
    return value if isinstance(value, bool) else None


def audience_claim(claims: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the ``aud`` claim as a tuple.

    Both the string and array forms allowed by RFC 7519 are accepted.
    """

    value = claims.get("aud")
    if isinstance(value, str):
        if not value:
            raise JoseError("empty aud")
        return (value,)
    if isinstance(value, list):
        if not value or any(not isinstance(item, str) or not item for item in value):
            raise JoseError("invalid aud")
        return tuple(value)
    raise JoseError("missing aud" if value is None else "invalid aud")


def string_tuple_claim(claims: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = claims.get(name)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))
