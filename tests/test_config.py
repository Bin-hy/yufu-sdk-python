from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from yufu import Config, TokenAuthMethod, TokenSet
from yufu.config import normalize_issuer


def test_normalize_issuer_strips_trailing_slash() -> None:
    assert normalize_issuer("https://id.example.com/") == "https://id.example.com"
    assert normalize_issuer(" https://id.example.com/tenant/ ") == ("https://id.example.com/tenant")


@pytest.mark.parametrize(
    "issuer",
    [
        "",
        "id.example.com",
        "ftp://id.example.com",
        "https://id.example.com?x=1",
        "https://id.example.com#x",
    ],
)
def test_normalize_issuer_rejects_invalid_values(issuer: str) -> None:
    with pytest.raises(ValueError):
        normalize_issuer(issuer)


def test_config_defaults() -> None:
    config = Config(issuer="https://id.example.com", client_id="web")
    assert config.scopes == ("openid",)
    assert config.auth_method is TokenAuthMethod.NONE
    assert config.timeout == 10.0
    assert config.leeway == 60.0


def test_config_repr_redacts_client_secret() -> None:
    config = Config(
        issuer="https://id.example.com",
        client_id="web",
        client_secret="super-secret",
    )
    rendered = repr(config)
    assert "super-secret" not in rendered
    assert "***" in rendered


def test_config_infers_client_secret_post() -> None:
    config = Config(
        issuer="https://id.example.com",
        client_id="web",
        client_secret="secret",
    )
    assert config.auth_method is TokenAuthMethod.CLIENT_SECRET_POST


def test_config_accepts_basic_auth() -> None:
    config = Config(
        issuer="https://id.example.com",
        client_id="web",
        client_secret="secret",
        token_auth_method="client_secret_basic",
    )
    assert config.auth_method is TokenAuthMethod.CLIENT_SECRET_BASIC


def test_config_empty_auth_method_uses_default() -> None:
    config = Config(
        issuer="https://id.example.com",
        client_id="web",
        client_secret="secret",
        token_auth_method="",
    )
    assert config.auth_method is TokenAuthMethod.CLIENT_SECRET_POST


def test_config_rejects_missing_secret_for_confidential_client() -> None:
    with pytest.raises(ValueError):
        Config(
            issuer="https://id.example.com",
            client_id="web",
            token_auth_method=TokenAuthMethod.CLIENT_SECRET_POST,
        )


def test_config_rejects_secret_for_public_client() -> None:
    with pytest.raises(ValueError):
        Config(
            issuer="https://id.example.com",
            client_id="web",
            client_secret="secret",
            token_auth_method=TokenAuthMethod.NONE,
        )


def test_config_rejects_unknown_auth_method() -> None:
    with pytest.raises(ValueError):
        Config(
            issuer="https://id.example.com",
            client_id="web",
            client_secret="secret",
            token_auth_method="private_key_jwt",
        )


def test_config_rejects_negative_leeway() -> None:
    with pytest.raises(ValueError):
        Config(issuer="https://id.example.com", client_id="web", leeway=-1)


def test_config_rejects_string_scopes() -> None:
    with pytest.raises(ValueError):
        Config(issuer="https://id.example.com", client_id="web", scopes="openid profile")


def test_config_rejects_empty_scope() -> None:
    with pytest.raises(ValueError):
        Config(issuer="https://id.example.com", client_id="web", scopes=["openid", ""])


def test_config_defaults_zero_ttls() -> None:
    config = Config(
        issuer="https://id.example.com",
        client_id="web",
        discovery_ttl=0,
        jwks_ttl=0,
    )
    assert config.discovery_ttl == 300.0
    assert config.jwks_ttl == 300.0


def test_token_set_expiry() -> None:
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    tokens = TokenSet(
        access_token="token",
        expires_at=now + timedelta(seconds=300),
    )
    assert not tokens.is_expired(now=now)
    assert tokens.is_expired(now=now + timedelta(seconds=301))
    assert not TokenSet(access_token="token").is_expired(now=now)


def test_token_set_repr_hides_tokens() -> None:
    tokens = TokenSet(
        access_token="access-secret",
        id_token="id-secret",
        refresh_token="refresh-secret",
    )
    rendered = repr(tokens)
    assert "access-secret" not in rendered
    assert "id-secret" not in rendered
    assert "refresh-secret" not in rendered
