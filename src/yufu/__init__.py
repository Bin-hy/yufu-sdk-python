"""yufu Runtime SDK for Python.

The SDK is a thin HTTP/OIDC client for applications that integrate with a yufu
deployment. It covers discovery, Authorization Code + PKCE, token refresh,
UserInfo, JWKS verification, introspection, revocation and back-channel logout.
"""

from __future__ import annotations

from ._version import __version__
from .async_client import AsyncClient
from .client import Client
from .config import (
    DEFAULT_DISCOVERY_TTL,
    DEFAULT_JWKS_TTL,
    DEFAULT_LEEWAY,
    DEFAULT_TIMEOUT,
    Config,
    TokenAuthMethod,
    TokenTypeHint,
)
from .errors import Error, YufuError, is_error_code
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

__all__ = [
    "DEFAULT_DISCOVERY_TTL",
    "DEFAULT_JWKS_TTL",
    "DEFAULT_LEEWAY",
    "DEFAULT_TIMEOUT",
    "AccessTokenClaims",
    "AsyncClient",
    "AuthorizationRequest",
    "Client",
    "Config",
    "Discovery",
    "Error",
    "IDTokenClaims",
    "Introspection",
    "LogoutTokenClaims",
    "TokenAuthMethod",
    "TokenSet",
    "TokenTypeHint",
    "UserInfo",
    "YufuError",
    "__version__",
    "is_error_code",
]
