"""Small signing and mock-transport helpers for unit tests."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64url(modulus),
        "e": b64url(exponent),
    }


def jwks(*keys: tuple[str, rsa.RSAPrivateKey]) -> dict[str, Any]:
    return {"keys": [public_jwk(private_key, kid) for kid, private_key in keys]}


def sign(
    private_key: rsa.RSAPrivateKey,
    claims: dict[str, Any],
    *,
    kid: str = "key-1",
    typ: str = "at+jwt",
    alg: str = "RS256",
) -> str:
    header = {"alg": alg, "kid": kid, "typ": typ}
    header_b64 = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    claims_b64 = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{claims_b64}.{b64url(signature)}"


def discovery(issuer: str, **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oidc/authorize",
        "token_endpoint": f"{issuer}/oidc/token",
        "userinfo_endpoint": f"{issuer}/oidc/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "revocation_endpoint": f"{issuer}/oidc/revoke",
        "introspection_endpoint": f"{issuer}/oidc/introspect",
        "end_session_endpoint": f"{issuer}/oidc/end-session",
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
    }
    document.update(overrides)
    return document
