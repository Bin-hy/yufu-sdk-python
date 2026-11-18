"""Client configuration and shared limits."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

from ._version import __version__

DEFAULT_DISCOVERY_TTL: float = 300.0
DEFAULT_JWKS_TTL: float = 300.0
DEFAULT_LEEWAY: float = 60.0
DEFAULT_TIMEOUT: float = 10.0
MAX_RESPONSE_SIZE: int = 1 << 20
MAX_TOKEN_SIZE: int = 16 * 1024


class TokenAuthMethod(str, Enum):
    """Client authentication method used at the token, introspection and
    revocation endpoints."""

    CLIENT_SECRET_POST = "client_secret_post"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    NONE = "none"


class TokenTypeHint(str, Enum):
    """Optional RFC 7662 / RFC 7009 token type hint."""

    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def epoch(value: datetime) -> float:
    """Convert a datetime to a POSIX timestamp, treating naive values as UTC."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def normalize_issuer(raw: str) -> str:
    """Validate and normalize an issuer URL.

    The issuer must be an absolute http(s) URL without a query or fragment.
    A trailing slash is removed so comparisons against discovery metadata are
    exact.
    """

    value = raw.strip()
    if not value:
        raise ValueError("yufu: issuer is required")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("yufu: issuer must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise ValueError("yufu: issuer must not contain a query or fragment")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


@dataclass(slots=True)
class Config:
    """Configuration for a Runtime SDK client.

    ``issuer`` and ``client_id`` are required. ``client_secret`` is optional for
    public clients. ``redirect_uri`` is required only for :meth:`authorize_url`
    and :meth:`exchange_code`.
    """

    issuer: str
    client_id: str
    client_secret: str = ""
    redirect_uri: str = ""
    scopes: Sequence[str] = field(default_factory=lambda: ("openid",))

    # Defaults to client_secret_post when client_secret is set, otherwise none.
    token_auth_method: TokenAuthMethod | str | None = None

    # HTTP and cache tuning.
    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = f"yufu-python-sdk/{__version__}"
    discovery_ttl: float = DEFAULT_DISCOVERY_TTL
    jwks_ttl: float = DEFAULT_JWKS_TTL

    # Applied to exp, nbf and iat validation.
    leeway: float = DEFAULT_LEEWAY

    # Injectable for deterministic tests.
    now: Callable[[], datetime] = utcnow

    def __post_init__(self) -> None:
        self.issuer = normalize_issuer(self.issuer)
        self.client_id = self.client_id.strip()
        if not self.client_id:
            raise ValueError("yufu: client_id is required")

        if isinstance(self.scopes, str):
            raise ValueError("yufu: scopes must be a sequence of strings, not a string")
        scopes = tuple(self.scopes)
        if any(not isinstance(scope, str) or not scope for scope in scopes):
            raise ValueError("yufu: scopes must be non-empty strings")
        self.scopes = scopes or ("openid",)

        method = self.token_auth_method
        if method is None or method == "":
            method = (
                TokenAuthMethod.CLIENT_SECRET_POST if self.client_secret else TokenAuthMethod.NONE
            )
        elif isinstance(method, str):
            try:
                method = TokenAuthMethod(method)
            except ValueError as exc:
                raise ValueError(f"yufu: unsupported token_auth_method {method!r}") from exc
        self.token_auth_method = method

        if method in {TokenAuthMethod.CLIENT_SECRET_POST, TokenAuthMethod.CLIENT_SECRET_BASIC}:
            if not self.client_secret:
                raise ValueError(f"yufu: client_secret is required for {method.value}")
        elif self.client_secret:
            raise ValueError("yufu: client_secret must be empty for TokenAuthMethod.NONE")

        if self.timeout <= 0:
            raise ValueError("yufu: timeout must be positive")
        if self.discovery_ttl <= 0:
            self.discovery_ttl = DEFAULT_DISCOVERY_TTL
        if self.jwks_ttl <= 0:
            self.jwks_ttl = DEFAULT_JWKS_TTL
        if self.leeway < 0:
            raise ValueError("yufu: leeway must not be negative")
        if not self.user_agent:
            self.user_agent = f"yufu-python-sdk/{__version__}"
        if not callable(self.now):
            raise ValueError("yufu: now must be callable")

    @property
    def auth_method(self) -> TokenAuthMethod:
        """The validated token authentication method."""

        method = self.token_auth_method
        assert isinstance(method, TokenAuthMethod)
        return method

    def __repr__(self) -> str:
        secret = "***" if self.client_secret else ""
        method = self.token_auth_method
        method_value = method.value if isinstance(method, TokenAuthMethod) else method
        return (
            f"Config(issuer={self.issuer!r}, client_id={self.client_id!r}, "
            f"client_secret={secret!r}, redirect_uri={self.redirect_uri!r}, "
            f"scopes={self.scopes!r}, token_auth_method={method_value!r}, "
            f"timeout={self.timeout!r}, discovery_ttl={self.discovery_ttl!r}, "
            f"jwks_ttl={self.jwks_ttl!r}, leeway={self.leeway!r})"
        )
