"""Synchronous yufu Runtime SDK client."""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa

from ._core import (
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
from ._http import decode_json_object, new_http_error, read_limited
from ._jose import JoseError, KeyNotFoundError, ParsedJwt, parse_jwks, parse_jwt, string_claim
from ._pkce import validate_verifier
from .config import Config, TokenAuthMethod, TokenTypeHint, epoch
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


@dataclass(frozen=True, slots=True)
class _RequestAuth:
    method: TokenAuthMethod
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(slots=True)
class _RefreshCall:
    event: threading.Event = field(default_factory=threading.Event)
    tokens: TokenSet | None = None
    error: BaseException | None = None


def _hint_value(hint: TokenTypeHint | str | None) -> str:
    if hint is None:
        return ""
    return hint.value if isinstance(hint, TokenTypeHint) else hint


class Client:
    """A concurrency-safe Runtime SDK client.

    The client is a thin HTTP/OIDC consumer. It does not depend on yufu server
    internals and can be used against any deployment that publishes the same
    discovery document and token profile. One instance may be shared between
    threads; discovery, JWKS and refresh caches are synchronized.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        http_client: httpx.Client | None = None,
        **config_kwargs: Any,
    ) -> None:
        if config is not None and config_kwargs:
            raise TypeError("pass either config or keyword arguments, not both")
        self._config = config if config is not None else Config(**config_kwargs)
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(
            timeout=self._config.timeout,
            follow_redirects=False,
        )

        self._discovery_lock = threading.Lock()
        self._discovery: Discovery | None = None
        self._discovery_expires = 0.0

        self._jwks_lock = threading.Lock()
        self._jwks: dict[str, rsa.RSAPublicKey] | None = None
        self._jwks_expires = 0.0

        self._refresh_lock = threading.Lock()
        self._refreshes: dict[str, _RefreshCall] = {}

    @property
    def config(self) -> Config:
        return self._config

    def close(self) -> None:
        """Release idle HTTP connections owned by the SDK."""

        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _auth(self) -> _RequestAuth:
        return _RequestAuth(
            method=self._config.auth_method,
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
        )

    @staticmethod
    def _apply_auth(form: list[tuple[str, str]], auth: _RequestAuth) -> httpx.BasicAuth | None:
        if auth.method is TokenAuthMethod.CLIENT_SECRET_POST:
            form.extend(
                [
                    ("client_id", auth.client_id),
                    ("client_secret", auth.client_secret),
                ]
            )
        elif auth.method is TokenAuthMethod.NONE:
            form.append(("client_id", auth.client_id))
        else:
            return httpx.BasicAuth(auth.client_id, auth.client_secret)
        return None

    def _do(
        self,
        method: str,
        url: str,
        *,
        data: list[tuple[str, str]] | None = None,
        headers: Mapping[str, str] | None = None,
        auth: httpx.Auth | None = None,
        timeout: float | None = None,
        parse_json: bool = True,
    ) -> dict[str, Any] | None:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": self._config.user_agent,
        }
        if headers:
            request_headers.update(headers)
        kwargs: dict[str, Any] = {"headers": request_headers}
        if data is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            kwargs["content"] = urlencode(data, doseq=True).encode("utf-8")
        if auth is not None:
            kwargs["auth"] = auth
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            response = self._http.request(method, url, **kwargs)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise YufuError(code="network_error", cause=exc) from exc
        try:
            body = read_limited(response)
        except YufuError:
            raise
        except httpx.HTTPError as exc:
            raise YufuError(
                code="network_error",
                status_code=response.status_code,
                cause=exc,
            ) from exc
        if not 200 <= response.status_code < 300:
            raise new_http_error(response, body)
        if not parse_json:
            return None
        return decode_json_object(body, status_code=response.status_code)

    def discover(self, *, timeout: float | None = None) -> Discovery:
        """Fetch and cache the issuer's OpenID Provider metadata."""

        with self._discovery_lock:
            now = epoch(self._config.now())
            if self._discovery is not None and now < self._discovery_expires:
                return self._discovery
            payload = self._do(
                "GET",
                f"{self._config.issuer}/.well-known/openid-configuration",
                timeout=timeout,
            )
            assert payload is not None
            discovery = Discovery.from_dict(payload)
            if discovery.issuer != self._config.issuer:
                raise YufuError(
                    code="invalid_discovery",
                    description=(
                        f"issuer mismatch: got {discovery.issuer!r} want {self._config.issuer!r}"
                    ),
                )
            validate_endpoint("authorization_endpoint", discovery.authorization_endpoint)
            validate_endpoint("token_endpoint", discovery.token_endpoint)
            validate_endpoint("jwks_uri", discovery.jwks_uri)
            self._discovery = discovery
            self._discovery_expires = epoch(self._config.now()) + self._config.discovery_ttl
            return discovery

    def authorize_url(
        self,
        *,
        state: str = "",
        nonce: str = "",
        scopes: Sequence[str] | None = None,
        redirect_uri: str = "",
        extra: Mapping[str, str | Sequence[str]] | None = None,
        timeout: float | None = None,
    ) -> AuthorizationRequest:
        """Build an authorization URL with generated state, nonce and PKCE."""

        discovery = self.discover(timeout=timeout)
        return build_authorize_url(
            self._config,
            discovery,
            state=state,
            nonce=nonce,
            scopes=scopes,
            redirect_uri=redirect_uri,
            extra=extra,
        )

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        *,
        redirect_uri: str = "",
        timeout: float | None = None,
    ) -> TokenSet:
        """Redeem an authorization code with PKCE."""

        if not code.strip():
            raise ValueError("yufu: code is required")
        validate_verifier(code_verifier)
        redirect = redirect_uri or self._config.redirect_uri
        if not redirect:
            raise ValueError("yufu: redirect_uri is required for code exchange")
        discovery = self.discover(timeout=timeout)
        form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", code_verifier),
            ("redirect_uri", redirect),
        ]
        auth = self._auth()
        basic = self._apply_auth(form, auth)
        payload = self._do(
            "POST",
            discovery.token_endpoint,
            data=form,
            auth=basic,
            timeout=timeout,
        )
        assert payload is not None
        return token_set_from_response(self._config, payload)

    def refresh(self, refresh_token: str, *, timeout: float | None = None) -> TokenSet:
        """Redeem a refresh token.

        Concurrent calls with the same refresh token are coalesced into one
        server request.
        """

        if not refresh_token.strip():
            raise ValueError("yufu: refresh token is required")
        with self._refresh_lock:
            call = self._refreshes.get(refresh_token)
            if call is None:
                call = _RefreshCall()
                self._refreshes[refresh_token] = call
                owner = True
            else:
                owner = False
        if not owner:
            if not call.event.wait(timeout):
                raise YufuError(
                    code="timeout",
                    description="refresh wait timed out",
                    cause=TimeoutError("refresh wait timed out"),
                )
            if call.error is not None:
                raise call.error
            assert call.tokens is not None
            return call.tokens
        try:
            tokens = self._refresh(refresh_token, timeout=timeout)
        except BaseException as exc:
            call.error = exc
            raise
        else:
            call.tokens = tokens
            return tokens
        finally:
            call.event.set()
            with self._refresh_lock:
                self._refreshes.pop(refresh_token, None)

    def _refresh(self, refresh_token: str, *, timeout: float | None) -> TokenSet:
        discovery = self.discover(timeout=timeout)
        form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ]
        auth = self._auth()
        basic = self._apply_auth(form, auth)
        payload = self._do(
            "POST",
            discovery.token_endpoint,
            data=form,
            auth=basic,
            timeout=timeout,
        )
        assert payload is not None
        tokens = token_set_from_response(self._config, payload)
        if not tokens.refresh_token:
            tokens.refresh_token = refresh_token
        return tokens

    def introspect(
        self,
        token: str,
        hint: TokenTypeHint | str | None = None,
        *,
        timeout: float | None = None,
    ) -> Introspection:
        """Call the introspection endpoint with this client's credentials."""

        if not token.strip():
            raise ValueError("yufu: token is required")
        discovery = self.discover(timeout=timeout)
        if not discovery.introspection_endpoint:
            raise YufuError(
                code="unsupported",
                description="issuer does not publish introspection_endpoint",
            )
        form = [("token", token)]
        hint_value = _hint_value(hint)
        if hint_value:
            form.append(("token_type_hint", hint_value))
        auth = self._auth()
        basic = self._apply_auth(form, auth)
        payload = self._do(
            "POST",
            discovery.introspection_endpoint,
            data=form,
            auth=basic,
            timeout=timeout,
        )
        assert payload is not None
        return introspection_from(payload)

    def revoke(
        self,
        token: str,
        hint: TokenTypeHint | str | None = None,
        *,
        timeout: float | None = None,
    ) -> None:
        """Revoke an access or refresh token. Revocation is idempotent."""

        if not token.strip():
            raise ValueError("yufu: token is required")
        discovery = self.discover(timeout=timeout)
        if not discovery.revocation_endpoint:
            raise YufuError(
                code="unsupported",
                description="issuer does not publish revocation_endpoint",
            )
        form = [("token", token)]
        hint_value = _hint_value(hint)
        if hint_value:
            form.append(("token_type_hint", hint_value))
        auth = self._auth()
        basic = self._apply_auth(form, auth)
        self._do(
            "POST",
            discovery.revocation_endpoint,
            data=form,
            auth=basic,
            timeout=timeout,
            parse_json=False,
        )

    def end_session_url(
        self,
        post_logout_redirect_uri: str,
        *,
        id_token_hint: str = "",
        state: str = "",
        timeout: float | None = None,
    ) -> str:
        """Build the browser redirect for RP-initiated logout."""

        if not post_logout_redirect_uri:
            raise ValueError("yufu: post_logout_redirect_uri is required")
        discovery = self.discover(timeout=timeout)
        if not discovery.end_session_endpoint:
            raise YufuError(
                code="unsupported",
                description="issuer does not publish end_session_endpoint",
            )
        values = [
            ("client_id", self._config.client_id),
            ("post_logout_redirect_uri", post_logout_redirect_uri),
        ]
        if id_token_hint:
            values.append(("id_token_hint", id_token_hint))
        if state:
            values.append(("state", state))
        endpoint = urlsplit(discovery.end_session_endpoint)
        if endpoint.scheme not in {"http", "https"} or not endpoint.netloc:
            raise YufuError(
                code="invalid_discovery",
                description="end_session_endpoint is invalid",
            )
        return urlunsplit(
            (
                endpoint.scheme,
                endpoint.netloc,
                endpoint.path,
                urlencode(values, doseq=True),
                endpoint.fragment,
            )
        )

    def userinfo(self, access_token: str, *, timeout: float | None = None) -> UserInfo:
        """Fetch the profile for an access token."""

        if not access_token.strip():
            raise ValueError("yufu: access token is required")
        discovery = self.discover(timeout=timeout)
        if not discovery.userinfo_endpoint:
            raise YufuError(
                code="unsupported",
                description="issuer does not publish userinfo_endpoint",
            )
        payload = self._do(
            "GET",
            discovery.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=timeout,
        )
        assert payload is not None
        return userinfo_from(payload)

    def verify_access_token(
        self,
        token: str,
        audience: str,
        *,
        timeout: float | None = None,
    ) -> AccessTokenClaims:
        """Verify an ``at+jwt`` access token for a resource server.

        ``audience`` is the application access audience, not the OIDC client id.
        """

        if not audience.strip():
            raise ValueError("yufu: audience is required")
        parsed = self._parse(token)
        check_typ(parsed, ("at+jwt",))
        keys = self._keys_for(parsed.header.kid, timeout=timeout)
        verify_parsed_jwt(
            self._config,
            parsed,
            keys,
            expected_typ=("at+jwt",),
            audience=audience,
        )
        return access_claims_from(parsed.claims)

    def verify_id_token(
        self,
        token: str,
        nonce: str = "",
        *,
        timeout: float | None = None,
    ) -> IDTokenClaims:
        """Verify an ID Token for ``client_id``."""

        parsed = self._parse(token)
        check_typ(parsed, ("JWT", ""))
        keys = self._keys_for(parsed.header.kid, timeout=timeout)
        verify_parsed_jwt(
            self._config,
            parsed,
            keys,
            expected_typ=("JWT", ""),
            audience=self._config.client_id,
        )
        if nonce:
            actual = string_claim(parsed.claims, "nonce")
            if actual != nonce:
                raise YufuError(
                    code="invalid_token",
                    reason="nonce_mismatch",
                    description="ID token nonce does not match",
                )
        return id_claims_from(parsed.claims)

    def verify_logout_token(
        self,
        token: str,
        *,
        timeout: float | None = None,
    ) -> LogoutTokenClaims:
        """Verify an OIDC back-channel logout token for ``client_id``."""

        parsed = self._parse(token)
        check_typ(parsed, ("logout+jwt",))
        keys = self._keys_for(parsed.header.kid, timeout=timeout)
        verify_parsed_jwt(
            self._config,
            parsed,
            keys,
            expected_typ=("logout+jwt",),
            audience=self._config.client_id,
        )
        return logout_claims_from(self._config, parsed.claims)

    @staticmethod
    def _parse(token: str) -> ParsedJwt:
        try:
            return parse_jwt(token)
        except JoseError as exc:
            raise token_error(exc) from exc

    def _keys_for(
        self,
        kid: str,
        *,
        timeout: float | None = None,
    ) -> dict[str, rsa.RSAPublicKey]:
        with self._jwks_lock:
            now = epoch(self._config.now())
            if self._jwks is not None and now < self._jwks_expires and kid in self._jwks:
                return self._jwks
            keys = self._fetch_jwks(timeout=timeout)
            self._jwks = keys
            self._jwks_expires = epoch(self._config.now()) + self._config.jwks_ttl
            if kid not in keys:
                raise YufuError(
                    code="invalid_token",
                    reason="unknown_kid",
                    description=f"JWKS has no key for kid {kid!r}",
                    cause=KeyNotFoundError("key not found"),
                )
            return keys

    def _fetch_jwks(self, *, timeout: float | None) -> dict[str, rsa.RSAPublicKey]:
        discovery = self.discover(timeout=timeout)
        payload = self._do("GET", discovery.jwks_uri, timeout=timeout)
        assert payload is not None
        try:
            return parse_jwks(payload)
        except JoseError as exc:
            raise YufuError(
                code="invalid_jwks",
                description=str(exc),
                cause=exc,
            ) from exc
