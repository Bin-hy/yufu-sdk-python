from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from yufu._jose import (
    JoseError,
    UnsupportedAlgorithmError,
    audience_claim,
    number_claim,
    parse_jwks,
    parse_jwt,
)

from .helpers import b64url, jwks, make_key, public_jwk, sign


def test_parse_and_verify_token() -> None:
    key = make_key()
    token = sign(
        key,
        {"iss": "https://id.example.com", "sub": "42", "exp": 1793491500},
    )
    parsed = parse_jwt(token)
    assert parsed.header.alg == "RS256"
    assert parsed.header.kid == "key-1"
    assert parsed.header.typ == "at+jwt"
    assert parsed.claims["sub"] == "42"
    parsed.verify(key.public_key())


def test_parse_rejects_unsupported_algorithm() -> None:
    key = make_key()
    token = sign(key, {"sub": "42"}, alg="RS512")
    with pytest.raises(UnsupportedAlgorithmError):
        parse_jwt(token)


def test_parse_rejects_missing_kid() -> None:
    key = make_key()
    token = sign(key, {"sub": "42"}, kid="")
    with pytest.raises(JoseError):
        parse_jwt(token)


def test_parse_rejects_malformed_and_oversized_tokens() -> None:
    with pytest.raises(JoseError):
        parse_jwt("not-a-token")
    with pytest.raises(JoseError):
        parse_jwt("a" * (16 * 1024 + 1))


def test_verify_rejects_wrong_key() -> None:
    key = make_key()
    other = make_key()
    parsed = parse_jwt(sign(key, {"sub": "42"}))
    with pytest.raises(JoseError):
        parsed.verify(other.public_key())


def test_parse_jwks_round_trip() -> None:
    key = make_key()
    keys = parse_jwks(jwks(("key-1", key)))
    assert set(keys) == {"key-1"}
    assert keys["key-1"].key_size == 2048


def test_parse_jwks_skips_non_rsa_and_non_sig_keys() -> None:
    key = make_key()
    document = jwks(("key-1", key))
    document["keys"].insert(0, {"kty": "EC", "kid": "ec"})
    document["keys"].insert(0, {**public_jwk(key, "enc"), "use": "enc"})
    keys = parse_jwks(document)
    assert set(keys) == {"key-1"}


def test_parse_jwks_rejects_empty_and_missing_kid() -> None:
    with pytest.raises(JoseError):
        parse_jwks({"keys": []})
    key = make_key()
    document = jwks(("key-1", key))
    document["keys"][0].pop("kid")
    with pytest.raises(JoseError):
        parse_jwks(document)


def test_parse_jwks_rejects_small_modulus() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(JoseError):
        parse_jwks(jwks(("key-1", small)))


def test_parse_jwks_rejects_invalid_exponent() -> None:
    key = make_key()
    document = jwks(("key-1", key))
    document["keys"][0]["e"] = b64url(b"\x01")
    with pytest.raises(JoseError):
        parse_jwks(document)


def test_audience_claim_accepts_string_and_array() -> None:
    assert audience_claim({"aud": "urn:app:test"}) == ("urn:app:test",)
    assert audience_claim({"aud": ["a", "b"]}) == ("a", "b")
    with pytest.raises(JoseError):
        audience_claim({})
    with pytest.raises(JoseError):
        audience_claim({"aud": []})
    with pytest.raises(JoseError):
        audience_claim({"aud": ["a", 1]})


def test_number_claim_rejects_booleans_and_floats() -> None:
    assert number_claim({"exp": 1}, "exp") == 1
    assert number_claim({"exp": True}, "exp") is None
    assert number_claim({"exp": 1.0}, "exp") is None


def test_parse_jwt_rejects_non_object_claims() -> None:
    header = b64url(json.dumps({"alg": "RS256", "kid": "key-1"}).encode())
    claims = b64url(json.dumps([1, 2, 3]).encode())
    signature = b64url(b"signature")
    with pytest.raises(JoseError):
        parse_jwt(f"{header}.{claims}.{signature}")
