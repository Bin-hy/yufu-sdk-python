from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from yufu import Config, Discovery, YufuError
from yufu._core import (
    access_claims_from,
    build_authorize_url,
    check_typ,
    id_claims_from,
    introspection_from,
    logout_claims_from,
    token_error,
    token_set_from_response,
    userinfo_from,
    validate_endpoint,
    verify_parsed_jwt,
)
from yufu._jose import JoseError, UnsupportedAlgorithmError, parse_jwt

from .helpers import make_key, sign

ISSUER = "https://id.example.com"
CLOCK = 1793491200


def config() -> Config:
    return Config(
        issuer=ISSUER,
        client_id="web",
        client_secret="secret",
        redirect_uri="https://app.example/callback",
        now=lambda: datetime.fromtimestamp(CLOCK, timezone.utc),
    )


def discovery() -> Discovery:
    return Discovery(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/oidc/authorize",
        token_endpoint=f"{ISSUER}/oidc/token",
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",
    )


def claims(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "42",
        "aud": "urn:app:test",
        "iat": CLOCK,
        "exp": CLOCK + 300,
    }
    value.update(overrides)
    return value


def test_build_authorize_url_extra_values_and_reserved() -> None:
    authorization = build_authorize_url(
        config(),
        discovery(),
        state="state-1",
        nonce="nonce-1",
        extra={"prompt": "login", "ui_locales": ["en", "zh"]},
    )
    assert "prompt=login" in authorization.url
    assert "ui_locales=en" in authorization.url
    assert "ui_locales=zh" in authorization.url
    with pytest.raises(ValueError):
        build_authorize_url(config(), discovery(), extra={"state": "x"})
    with pytest.raises(TypeError):
        build_authorize_url(config(), discovery(), scopes="openid")


def test_authorization_request_repr_hides_code_verifier() -> None:
    authorization = build_authorize_url(config(), discovery())
    assert authorization.code_verifier not in repr(authorization)


def test_validate_endpoint() -> None:
    validate_endpoint("token_endpoint", "https://id.example.com/token")
    with pytest.raises(YufuError):
        validate_endpoint("token_endpoint", "/token")


def test_token_set_from_response_validation() -> None:
    tokens = token_set_from_response(
        config(),
        {
            "access_token": "a",
            "id_token": "i",
            "refresh_token": "r",
            "token_type": "bearer",
            "expires_in": 300,
            "scope": "openid",
        },
    )
    assert tokens.token_type == "bearer"
    assert tokens.expires_at is not None
    with pytest.raises(YufuError):
        token_set_from_response(config(), {})
    with pytest.raises(YufuError):
        token_set_from_response(config(), {"access_token": "a", "expires_in": "300"})
    with pytest.raises(YufuError):
        token_set_from_response(config(), {"access_token": "a", "id_token": 1})


def test_access_claims_are_typed() -> None:
    value = access_claims_from(
        claims(
            jti="jti-1",
            scope="openid profile",
            token_use="user_session",
            application="urn:app:test",
            session_id="session-1",
            client_id="web",
            roles=["admin", 1],
            permissions=["read"],
            nbf=CLOCK,
        )
    )
    assert value.audience == "urn:app:test"
    assert value.roles == ("admin",)
    assert value.permissions == ("read",)
    assert value.not_before is not None
    with pytest.raises(YufuError):
        access_claims_from({"aud": "urn:app:test", "exp": CLOCK})
    with pytest.raises(YufuError):
        access_claims_from({"sub": "42", "exp": CLOCK})
    with pytest.raises(YufuError):
        access_claims_from({"sub": "42", "aud": "urn:app:test"})


def test_id_claims_are_typed() -> None:
    value = id_claims_from(
        claims(
            aud="web",
            nonce="nonce-1",
            sid="sid-1",
            name="Alice",
            preferred_username="alice",
            email="alice@example.com",
            email_verified=True,
            auth_time=CLOCK,
            at_hash="hash",
        )
    )
    assert value.email_verified is True
    assert value.auth_time is not None
    assert value.at_hash == "hash"


def test_logout_claims_validation() -> None:
    base = {
        "iss": ISSUER,
        "aud": "web",
        "iat": CLOCK,
        "exp": CLOCK + 120,
        "jti": "jti-1",
        "sid": "sid-1",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    value = logout_claims_from(config(), base)
    assert value.jti == "jti-1"
    assert value.sid == "sid-1"

    with pytest.raises(YufuError):
        logout_claims_from(config(), {**base, "nonce": "n"})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {key: value for key, value in base.items() if key != "jti"})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {key: value for key, value in base.items() if key != "iat"})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {key: value for key, value in base.items() if key != "exp"})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {**base, "exp": CLOCK + 121})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {**base, "sid": "", "sub": ""})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {key: value for key, value in base.items() if key != "events"})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {**base, "events": {}})
    with pytest.raises(YufuError):
        logout_claims_from(config(), {**base, "events": {"other": {}}})
    with pytest.raises(YufuError):
        logout_claims_from(
            config(),
            {
                **base,
                "events": {"http://schemas.openid.net/event/backchannel-logout": {"x": 1}},
            },
        )


def test_introspection_and_userinfo_parsing() -> None:
    introspection = introspection_from(
        {
            "active": True,
            "aud": ["urn:app:test"],
            "exp": CLOCK + 300,
            "scope": "openid",
            "sub": "42",
        }
    )
    assert introspection.active
    assert introspection.audience == "urn:app:test"
    assert introspection.expires_at is not None
    assert not introspection_from({"active": False}).active

    info = userinfo_from({"sub": "42", "preferred_username": "alice"})
    assert info.subject == "42"
    with pytest.raises(YufuError):
        userinfo_from({})


def test_token_error_maps_unsupported_algorithm() -> None:
    error = token_error(UnsupportedAlgorithmError("unsupported algorithm"))
    assert error.code == "unsupported_algorithm"
    assert token_error(JoseError("bad")).code == "invalid_token"


def test_verify_parsed_jwt_time_and_claim_checks() -> None:
    key = make_key()
    keys = {"key-1": key.public_key()}
    cfg = config()

    def verify(value: dict[str, Any], typ: str = "at+jwt") -> None:
        parsed = parse_jwt(sign(key, value, typ=typ))
        verify_parsed_jwt(
            cfg,
            parsed,
            keys,
            expected_typ=("at+jwt",),
            audience="urn:app:test",
        )

    verify(claims())
    with pytest.raises(YufuError) as exc_info:
        verify(claims(exp=CLOCK - 61))
    assert exc_info.value.reason == "expired"
    with pytest.raises(YufuError) as exc_info:
        verify(claims(nbf=CLOCK + 61))
    assert exc_info.value.reason == "not_yet_valid"
    with pytest.raises(YufuError) as exc_info:
        verify(claims(iat=CLOCK + 61))
    assert exc_info.value.reason == "issued_in_future"
    with pytest.raises(YufuError) as exc_info:
        verify(claims(iss="https://other.example"))
    assert exc_info.value.reason == "issuer_mismatch"
    with pytest.raises(YufuError) as exc_info:
        verify(claims(aud="urn:other"))
    assert exc_info.value.reason == "audience_mismatch"
    with pytest.raises(YufuError) as exc_info:
        verify({name: value for name, value in claims().items() if name != "exp"})
    assert exc_info.value.reason == "missing_exp"


def test_check_typ() -> None:
    key = make_key()
    parsed = parse_jwt(sign(key, claims(), typ="JWT"))
    check_typ(parsed, ("JWT", ""))
    with pytest.raises(YufuError) as exc_info:
        check_typ(parsed, ("at+jwt",))
    assert exc_info.value.reason == "typ_mismatch"
