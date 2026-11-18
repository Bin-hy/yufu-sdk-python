"""Typed protocol models returned by the Runtime SDK."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import epoch
from .errors import YufuError


def _string(data: Mapping[str, Any], name: str, default: str = "") -> str:
    value = data.get(name, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise YufuError(code="invalid_response", description=f"{name} must be a string")
    return value


def _boolean(data: Mapping[str, Any], name: str, default: bool = False) -> bool:
    value = data.get(name, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise YufuError(code="invalid_response", description=f"{name} must be a boolean")
    return value


def _string_list(data: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = data.get(name)
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise YufuError(code="invalid_response", description=f"{name} must be an array of strings")
    return tuple(value)


@dataclass(slots=True)
class Discovery:
    """The subset of OpenID Provider metadata the Runtime SDK uses."""

    issuer: str
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    revocation_endpoint: str = ""
    introspection_endpoint: str = ""
    end_session_endpoint: str = ""
    response_types_supported: tuple[str, ...] = ()
    response_modes_supported: tuple[str, ...] = ()
    subject_types_supported: tuple[str, ...] = ()
    id_token_signing_alg_values_supported: tuple[str, ...] = ()
    grant_types_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()
    introspection_endpoint_auth_methods_supported: tuple[str, ...] = ()
    revocation_endpoint_auth_methods_supported: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    claims_supported: tuple[str, ...] = ()
    code_challenge_methods_supported: tuple[str, ...] = ()
    backchannel_logout_supported: bool = False
    backchannel_logout_session_supported: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Discovery:
        return cls(
            issuer=_string(data, "issuer"),
            authorization_endpoint=_string(data, "authorization_endpoint"),
            token_endpoint=_string(data, "token_endpoint"),
            userinfo_endpoint=_string(data, "userinfo_endpoint"),
            jwks_uri=_string(data, "jwks_uri"),
            revocation_endpoint=_string(data, "revocation_endpoint"),
            introspection_endpoint=_string(data, "introspection_endpoint"),
            end_session_endpoint=_string(data, "end_session_endpoint"),
            response_types_supported=_string_list(data, "response_types_supported"),
            response_modes_supported=_string_list(data, "response_modes_supported"),
            subject_types_supported=_string_list(data, "subject_types_supported"),
            id_token_signing_alg_values_supported=_string_list(
                data, "id_token_signing_alg_values_supported"
            ),
            grant_types_supported=_string_list(data, "grant_types_supported"),
            token_endpoint_auth_methods_supported=_string_list(
                data, "token_endpoint_auth_methods_supported"
            ),
            introspection_endpoint_auth_methods_supported=_string_list(
                data, "introspection_endpoint_auth_methods_supported"
            ),
            revocation_endpoint_auth_methods_supported=_string_list(
                data, "revocation_endpoint_auth_methods_supported"
            ),
            scopes_supported=_string_list(data, "scopes_supported"),
            claims_supported=_string_list(data, "claims_supported"),
            code_challenge_methods_supported=_string_list(data, "code_challenge_methods_supported"),
            backchannel_logout_supported=_boolean(data, "backchannel_logout_supported"),
            backchannel_logout_session_supported=_boolean(
                data, "backchannel_logout_session_supported"
            ),
            raw=dict(data),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """The result of building an authorization URL.

    Keep ``state``, ``nonce`` and ``code_verifier`` in the user's session until
    the callback is processed.
    """

    url: str
    state: str
    nonce: str
    code_verifier: str = field(repr=False)
    code_challenge: str
    redirect_uri: str


@dataclass(slots=True)
class TokenSet:
    """The result of a code exchange or refresh."""

    access_token: str = field(repr=False)
    id_token: str = field(default="", repr=False)
    refresh_token: str = field(default="", repr=False)
    token_type: str = "Bearer"
    expires_in: int = 0
    scope: str = ""
    expires_at: datetime | None = None

    def is_expired(self, leeway: float = 0.0, *, now: datetime | None = None) -> bool:
        """Return ``True`` when the access token is expired."""

        if self.expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        return epoch(current) > epoch(self.expires_at) + leeway


@dataclass(slots=True)
class AccessTokenClaims:
    """Validated access-token claims exposed to resource servers."""

    issuer: str
    subject: str
    audience: str
    audiences: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime | None = None
    not_before: datetime | None = None
    jti: str = ""
    scope: str = ""
    token_use: str = ""
    application: str = ""
    session_id: str = ""
    client_id: str = ""
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IDTokenClaims:
    """Validated OpenID Connect ID Token claims."""

    issuer: str
    subject: str
    audience: str
    audiences: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime | None = None
    nonce: str = ""
    auth_time: datetime | None = None
    sid: str = ""
    name: str = ""
    preferred_username: str = ""
    email: str = ""
    email_verified: bool | None = None
    at_hash: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LogoutTokenClaims:
    """A validated OIDC back-channel logout token."""

    issuer: str
    audience: str
    subject: str
    sid: str
    jti: str
    issued_at: datetime
    expires_at: datetime
    events: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Introspection:
    """An RFC 7662 introspection response."""

    active: bool
    scope: str = ""
    client_id: str = ""
    username: str = ""
    token_type: str = ""
    expires_at: datetime | None = None
    subject: str = ""
    sid: str = ""
    audience: str = ""
    issuer: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class UserInfo:
    """The profile returned by the UserInfo endpoint."""

    subject: str
    preferred_username: str = ""
    name: str = ""
    nickname: str = ""
    email: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
