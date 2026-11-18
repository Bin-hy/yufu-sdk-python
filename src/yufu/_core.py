"""Protocol logic shared by the synchronous and asynchronous clients."""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from ._jose import (
    JoseError,
    KeyNotFoundError,
    ParsedJwt,
    UnsupportedAlgorithmError,
    audience_claim,
    bool_claim,
    number_claim,
    string_claim,
    string_tuple_claim,
)
from ._pkce import challenge as pkce_challenge
from ._pkce import new_verifier
from .config import Config, epoch
from .errors import YufuError
from .models import (
    AccessTokenClaims,
    AuthorizationRequest,
    Discovery,
    IDTokenClaims,
    Introspection,
    LogoutTokenClaims,
    TokenSet,
    UserInfo,
)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
RESERVED_AUTHORIZE_PARAMS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "scope",
        "state",
        "nonce",
    }
)


def random_url_token(size: int = 32) -> str:
    import base64

    return base64.urlsafe_b64encode(secrets.token_bytes(size)).rstrip(b"=").decode("ascii")


def validate_endpoint(name: str, value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise YufuError(
            code="invalid_discovery",
            description=f"{name} is not an absolute http(s) URL",
        )


def build_authorize_url(
    config: Config,
    discovery: Discovery,
    *,
    state: str = "",
    nonce: str = "",
    scopes: Sequence[str] | None = None,
    redirect_uri: str = "",
    extra: Mapping[str, str | Sequence[str]] | None = None,
) -> AuthorizationRequest:
    redirect = redirect_uri or config.redirect_uri
    if not redirect:
        raise ValueError("yufu: redirect_uri is required for authorization")

    if isinstance(scopes, str):
        raise TypeError("yufu: scopes must be a sequence of strings, not a string")
    selected_scopes = tuple(scopes) if scopes else tuple(config.scopes)
    if "openid" not in selected_scopes:
        raise ValueError("yufu: scopes must include openid")

    state = state or random_url_token()
    nonce = nonce or random_url_token()
    verifier = new_verifier()
    code_challenge = pkce_challenge(verifier)

    values: list[tuple[str, str]] = []
    for key, value in (extra or {}).items():
        if key in RESERVED_AUTHORIZE_PARAMS:
            raise ValueError(f"yufu: authorization parameter {key!r} is reserved")
        if isinstance(value, str):
            values.append((key, value))
        else:
            for item in value:
                if not isinstance(item, str):
                    raise TypeError(f"yufu: authorization parameter {key!r} must be a string")
                values.append((key, item))
    values.extend(
        [
            ("client_id", config.client_id),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", " ".join(selected_scopes)),
            ("state", state),
            ("nonce", nonce),
        ]
    )

    endpoint = urlsplit(discovery.authorization_endpoint)
    if endpoint.scheme not in {"http", "https"} or not endpoint.netloc:
        raise YufuError(
            code="invalid_discovery",
            description="authorization_endpoint is invalid",
        )
    url = urlunsplit(
        (
            endpoint.scheme,
            endpoint.netloc,
            endpoint.path,
            urlencode(values, doseq=True),
            endpoint.fragment,
        )
    )
    return AuthorizationRequest(
        url=url,
        state=state,
        nonce=nonce,
        code_verifier=verifier,
        code_challenge=code_challenge,
        redirect_uri=redirect,
    )


def token_set_from_response(config: Config, response: Mapping[str, Any]) -> TokenSet:
    access_token = response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise YufuError(
            code="invalid_response",
            description="token response is missing access_token",
        )

    token_type = response.get("token_type")
    if token_type is None or token_type == "":
        token_type = "Bearer"
    if not isinstance(token_type, str) or token_type.casefold() != "bearer":
        raise YufuError(
            code="invalid_response",
            description=f"unsupported token_type {token_type!r}",
        )

    expires_in = response.get("expires_in", 0)
    if expires_in is None:
        expires_in = 0
    if isinstance(expires_in, bool) or not isinstance(expires_in, int):
        raise YufuError(
            code="invalid_response",
            description="token response expires_in must be an integer",
        )

    def optional_string(name: str) -> str:
        value = response.get(name, "")
        if value is None:
            return ""
        if not isinstance(value, str):
            raise YufuError(
                code="invalid_response",
                description=f"token response {name} must be a string",
            )
        return value

    expires_at = config.now() + timedelta(seconds=expires_in) if expires_in > 0 else None
    return TokenSet(
        access_token=access_token,
        id_token=optional_string("id_token"),
        refresh_token=optional_string("refresh_token"),
        token_type=token_type,
        expires_in=expires_in,
        scope=optional_string("scope"),
        expires_at=expires_at,
    )


def _datetime(value: int | None) -> datetime | None:
    return datetime.fromtimestamp(value, timezone.utc) if value is not None else None


def _required_subject(raw: Mapping[str, Any], kind: str) -> str:
    subject = string_claim(raw, "sub")
    if not subject:
        raise YufuError(
            code="invalid_token",
            reason="missing_sub",
            description=f"{kind} is missing sub",
        )
    return subject


def _required_expiry(raw: Mapping[str, Any], kind: str) -> datetime:
    expires_at = number_claim(raw, "exp")
    if expires_at is None:
        raise YufuError(
            code="invalid_token",
            reason="missing_exp",
            description=f"{kind} is missing exp",
        )
    return datetime.fromtimestamp(expires_at, timezone.utc)


def _audiences(raw: Mapping[str, Any]) -> tuple[str, ...]:
    try:
        return audience_claim(raw)
    except JoseError as exc:
        raise YufuError(
            code="invalid_token",
            reason="audience_mismatch",
            description=str(exc),
            cause=exc,
        ) from exc


def access_claims_from(raw: Mapping[str, Any]) -> AccessTokenClaims:
    subject = _required_subject(raw, "access token")
    audiences = _audiences(raw)
    expires_at = _required_expiry(raw, "access token")
    return AccessTokenClaims(
        issuer=string_claim(raw, "iss") or "",
        subject=subject,
        audience=audiences[0],
        audiences=audiences,
        expires_at=expires_at,
        issued_at=_datetime(number_claim(raw, "iat")),
        not_before=_datetime(number_claim(raw, "nbf")),
        jti=string_claim(raw, "jti") or "",
        scope=string_claim(raw, "scope") or "",
        token_use=string_claim(raw, "token_use") or "",
        application=string_claim(raw, "application") or "",
        session_id=string_claim(raw, "session_id") or "",
        client_id=string_claim(raw, "client_id") or "",
        roles=string_tuple_claim(raw, "roles"),
        permissions=string_tuple_claim(raw, "permissions"),
        raw=dict(raw),
    )


def id_claims_from(raw: Mapping[str, Any]) -> IDTokenClaims:
    subject = _required_subject(raw, "ID token")
    audiences = _audiences(raw)
    expires_at = _required_expiry(raw, "ID token")
    return IDTokenClaims(
        issuer=string_claim(raw, "iss") or "",
        subject=subject,
        audience=audiences[0],
        audiences=audiences,
        expires_at=expires_at,
        issued_at=_datetime(number_claim(raw, "iat")),
        nonce=string_claim(raw, "nonce") or "",
        auth_time=_datetime(number_claim(raw, "auth_time")),
        sid=string_claim(raw, "sid") or "",
        name=string_claim(raw, "name") or "",
        preferred_username=string_claim(raw, "preferred_username") or "",
        email=string_claim(raw, "email") or "",
        email_verified=bool_claim(raw, "email_verified"),
        at_hash=string_claim(raw, "at_hash") or "",
        raw=dict(raw),
    )


def logout_claims_from(config: Config, raw: Mapping[str, Any]) -> LogoutTokenClaims:
    if "nonce" in raw:
        raise YufuError(
            code="invalid_token",
            reason="nonce_present",
            description="logout token must not contain nonce",
        )
    jti = string_claim(raw, "jti")
    if not jti:
        raise YufuError(
            code="invalid_token",
            reason="missing_jti",
            description="logout token is missing jti",
        )
    issued_at = number_claim(raw, "iat")
    if issued_at is None:
        raise YufuError(
            code="invalid_token",
            reason="missing_iat",
            description="logout token is missing iat",
        )
    expires_at = number_claim(raw, "exp")
    if expires_at is None:
        raise YufuError(
            code="invalid_token",
            reason="missing_exp",
            description="logout token is missing exp",
        )
    if expires_at <= issued_at or expires_at - issued_at > 120:
        raise YufuError(
            code="invalid_token",
            reason="lifetime_too_long",
            description="logout token lifetime must be at most 120 seconds",
        )
    subject = string_claim(raw, "sub") or ""
    sid = string_claim(raw, "sid") or ""
    if not subject and not sid:
        raise YufuError(
            code="invalid_token",
            reason="missing_subject",
            description="logout token requires sub or sid",
        )
    events_value = raw.get("events")
    if not isinstance(events_value, dict):
        raise YufuError(
            code="invalid_token",
            reason="missing_events",
            description="logout token is missing events",
        )
    if len(events_value) != 1:
        raise YufuError(
            code="invalid_token",
            reason="invalid_events",
            description="logout token must contain exactly one event",
        )
    event = events_value.get(BACKCHANNEL_LOGOUT_EVENT)
    if not isinstance(event, dict) or event:
        raise YufuError(
            code="invalid_token",
            reason="invalid_events",
            description="back-channel logout event must be an empty object",
        )
    audiences = _audiences(raw)
    return LogoutTokenClaims(
        issuer=config.issuer,
        audience=audiences[0],
        subject=subject,
        sid=sid,
        jti=jti,
        issued_at=datetime.fromtimestamp(issued_at, timezone.utc),
        expires_at=datetime.fromtimestamp(expires_at, timezone.utc),
        events=dict(events_value),
        raw=dict(raw),
    )


def introspection_from(raw: Mapping[str, Any]) -> Introspection:
    audience = ""
    aud_value = raw.get("aud")
    if isinstance(aud_value, str):
        audience = aud_value
    elif isinstance(aud_value, list) and aud_value and isinstance(aud_value[0], str):
        audience = aud_value[0]
    return Introspection(
        active=bool_claim(raw, "active") is True,
        scope=string_claim(raw, "scope") or "",
        client_id=string_claim(raw, "client_id") or "",
        username=string_claim(raw, "username") or "",
        token_type=string_claim(raw, "token_type") or "",
        expires_at=_datetime(number_claim(raw, "exp")),
        subject=string_claim(raw, "sub") or "",
        sid=string_claim(raw, "sid") or "",
        audience=audience,
        issuer=string_claim(raw, "iss") or "",
        raw=dict(raw),
    )


def userinfo_from(raw: Mapping[str, Any]) -> UserInfo:
    subject = string_claim(raw, "sub")
    if not subject:
        raise YufuError(code="invalid_response", description="userinfo is missing sub")
    return UserInfo(
        subject=subject,
        preferred_username=string_claim(raw, "preferred_username") or "",
        name=string_claim(raw, "name") or "",
        nickname=string_claim(raw, "nickname") or "",
        email=string_claim(raw, "email") or "",
        raw=dict(raw),
    )


def token_error(exc: JoseError) -> YufuError:
    if isinstance(exc, UnsupportedAlgorithmError):
        return YufuError(
            code="unsupported_algorithm",
            reason="unsupported_algorithm",
            description=str(exc),
            cause=exc,
        )
    return YufuError(
        code="invalid_token",
        reason="malformed_token",
        description=str(exc),
        cause=exc,
    )


def check_typ(parsed: ParsedJwt, expected_typ: Sequence[str]) -> None:
    expected = {value.casefold() for value in expected_typ}
    if parsed.header.typ.casefold() not in expected:
        raise YufuError(
            code="invalid_token",
            reason="typ_mismatch",
            description=f"unexpected token typ {parsed.header.typ!r}",
        )


def verify_parsed_jwt(
    config: Config,
    parsed: ParsedJwt,
    keys: Mapping[str, Any],
    *,
    expected_typ: Sequence[str],
    audience: str,
) -> None:
    check_typ(parsed, expected_typ)

    key = keys.get(parsed.header.kid)
    if key is None:
        raise YufuError(
            code="invalid_token",
            reason="unknown_kid",
            description=f"JWKS has no key for kid {parsed.header.kid!r}",
            cause=KeyNotFoundError("key not found"),
        )
    try:
        parsed.verify(key)
    except JoseError as exc:
        raise YufuError(
            code="invalid_token",
            reason="bad_signature",
            description="signature verification failed",
            cause=exc,
        ) from exc

    issuer = string_claim(parsed.claims, "iss")
    if issuer != config.issuer:
        raise YufuError(
            code="invalid_token",
            reason="issuer_mismatch",
            description="issuer does not match",
        )

    audiences = _audiences(parsed.claims)
    if audience not in audiences:
        raise YufuError(
            code="invalid_token",
            reason="audience_mismatch",
            description="audience does not match",
        )

    expires_at = number_claim(parsed.claims, "exp")
    if expires_at is None:
        raise YufuError(
            code="invalid_token",
            reason="missing_exp",
            description="token is missing exp",
        )
    now = epoch(config.now())
    if now > expires_at + config.leeway:
        raise YufuError(
            code="invalid_token",
            reason="expired",
            description="token is expired",
        )
    not_before = number_claim(parsed.claims, "nbf")
    if not_before is not None and now + config.leeway < not_before:
        raise YufuError(
            code="invalid_token",
            reason="not_yet_valid",
            description="token is not valid yet",
        )
    issued_at = number_claim(parsed.claims, "iat")
    if issued_at is not None and issued_at > now + config.leeway:
        raise YufuError(
            code="invalid_token",
            reason="issued_in_future",
            description="token was issued in the future",
        )
