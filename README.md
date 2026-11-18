# yufu Runtime SDK for Python

`yufu-sdk` is the Python Runtime SDK for [yufu](https://github.com/Bin-hy/yufu).
It is a thin HTTP/OIDC client for applications that integrate with a yufu
deployment. The SDK is versioned independently of the yufu server.

The Go reference implementation is
[`Bin-hy/yufu-sdk-go`](https://github.com/Bin-hy/yufu-sdk-go). Both SDKs consume
the same language-neutral contract fixtures and expose the same protocol
behavior. Both are Apache-2.0.

## Scope

Included:

- Discovery with issuer validation and caching
- Authorization Code + PKCE (S256), state and nonce generation
- Code exchange and refresh-token rotation with single-flight refresh
- UserInfo
- JWKS caching and RS256 verification
- Access-token verification (`typ=at+jwt`, `iss`, `aud`, `exp`, `nbf`)
- ID Token verification (`iss`, `aud`, `nonce`, `exp`)
- Introspection and revocation
- RP-initiated logout URL
- Back-channel logout token verification
- Typed OAuth/HTTP errors with `request_id` and `Retry-After`
- Synchronous and asyncio clients

Not included:

- M2M / `client_credentials`
- Permission synchronization, `/enforce`, legacy RBAC
- Management/console APIs (browser Cookie + CSRF)

## Install

```bash
pip install yufu-sdk
```

Requires Python 3.10 or later. The package is typed (`py.typed`) and has two
runtime dependencies: `httpx` and `cryptography`.

## Quickstart

```python
import os

from yufu import Client

client = Client(
    issuer="https://id.example.com",
    client_id="web",
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    redirect_uri="https://app.example.com/callback",
    scopes=["openid", "profile", "email"],
)

auth = client.authorize_url()
# Store auth.state, auth.nonce and auth.code_verifier in the user's session,
# then redirect the browser to auth.url.

tokens = client.exchange_code(code, auth.code_verifier, redirect_uri=auth.redirect_uri)
id_claims = client.verify_id_token(tokens.id_token, nonce=auth.nonce)
access_claims = client.verify_access_token(
    tokens.access_token,
    audience="urn:app:production",
)
profile = client.userinfo(tokens.access_token)
```

The access-token audience is the application's registered access audience, not
the OIDC client id. A resource server must pass the expected audience to
`verify_access_token`.

Use the client as a context manager to release its HTTP connections:

```python
with Client(issuer=..., client_id=...) as client:
    ...
```

## Async

```python
import os

from yufu import AsyncClient

async with AsyncClient(
    issuer="https://id.example.com",
    client_id="web",
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    redirect_uri="https://app.example.com/callback",
) as client:
    auth = await client.authorize_url()
    tokens = await client.exchange_code(code, auth.code_verifier, redirect_uri=auth.redirect_uri)
    claims = await client.verify_access_token(
        tokens.access_token,
        audience="urn:app:production",
    )
```

An `AsyncClient` is bound to the event loop that first uses it. Do not share one
instance across loops.

## API surface

`Client` and `AsyncClient` expose the same methods; async methods are awaited.

| Method | Description |
|---|---|
| `discover()` | Fetch and cache OpenID Provider metadata. |
| `authorize_url(...)` | Build an authorization URL with state, nonce and PKCE. |
| `exchange_code(code, verifier, redirect_uri=...)` | Redeem an authorization code. |
| `refresh(refresh_token)` | Redeem a refresh token with single-flight coalescing. |
| `userinfo(access_token)` | Fetch the UserInfo profile. |
| `verify_access_token(token, audience)` | Verify an `at+jwt` access token. |
| `verify_id_token(token, nonce=...)` | Verify an OIDC ID Token. |
| `verify_logout_token(token)` | Verify a back-channel logout token. |
| `introspect(token, hint=...)` | Call the RFC 7662 introspection endpoint. |
| `revoke(token, hint=...)` | Call the RFC 7009 revocation endpoint. |
| `end_session_url(...)` | Build the RP-initiated logout redirect. |
| `close()` / `aclose()` | Release HTTP connections owned by the SDK. |

## Resource server

```python
from yufu import Client, YufuError

reader = Client(
    issuer="https://id.example.com",
    client_id=os.environ["READER_CLIENT_ID"],
    client_secret=os.environ["READER_CLIENT_SECRET"],
)

try:
    claims = reader.verify_access_token(bearer_token, audience="urn:app:production")
except YufuError as exc:
    raise PermissionError(exc.code) from exc

introspection = reader.introspect(bearer_token, hint="access_token")
if not introspection.active or introspection.subject != claims.subject:
    raise PermissionError("token is not active or subject changed")
```

The SDK verifies the JWT locally. The introspection call is an additional
online check; the application decides its freshness policy. See the
[enterprise OIDC guide](https://github.com/Bin-hy/yufu/blob/main/docs/integration/enterprise-oidc.md)
for the 2-second/5-second guidance used by the reference examples.

## Back-channel logout

```python
from yufu import YufuError

try:
    claims = client.verify_logout_token(logout_token)
except YufuError as exc:
    raise PermissionError(exc.code) from exc

# Delete local sessions by claims.sid and claims.subject.
# Persist claims.jti to make delivery idempotent.
```

`verify_logout_token` enforces `typ=logout+jwt`, `aud=client_id`, the
back-channel logout event, `jti`, `sid` or `sub`, no `nonce`, and a lifetime of
at most 120 seconds.

## Configuration

`Client(...)` and `AsyncClient(...)` accept the same keyword arguments as
`yufu.Config`:

| Option | Default | Description |
|---|---|---|
| `issuer` | required | Absolute http(s) issuer URL without query or fragment. |
| `client_id` | required | OIDC client id. |
| `client_secret` | `""` | Optional for public clients. |
| `redirect_uri` | `""` | Required for `authorize_url` and `exchange_code`. |
| `scopes` | `("openid",)` | Scopes used by `authorize_url`. |
| `token_auth_method` | inferred | `client_secret_post`, `client_secret_basic` or `none`. |
| `timeout` | `10.0` | Default HTTP timeout in seconds. |
| `user_agent` | `yufu-python-sdk/<version>` | HTTP `User-Agent`. |
| `discovery_ttl` | `300.0` | Discovery cache TTL in seconds. |
| `jwks_ttl` | `300.0` | JWKS cache TTL in seconds. |
| `leeway` | `60.0` | Clock skew allowance for `exp`, `nbf` and `iat`. |
| `now` | `datetime.now(timezone.utc)` | Injectable clock for deterministic tests. |

Set `leeway=0` to disable clock-skew tolerance.

You can also pass a `Config` instance:

```python
from yufu import Client, Config

config = Config(issuer="https://id.example.com", client_id="web")
client = Client(config)
```

To inject an HTTP client (for proxies, custom transports or tests), pass
`http_client=` to `Client` or `AsyncClient`. The SDK will not close a client it
does not own.

## Errors

All protocol, HTTP and validation failures raise `yufu.YufuError`:

```python
from yufu import YufuError, is_error_code

try:
    client.exchange_code(code, verifier)
except YufuError as exc:
    print(exc.code, exc.status_code, exc.request_id, exc.retry_after)
    if is_error_code(exc, "invalid_grant"):
        ...
```

`YufuError.reason` is a language-neutral token-rejection category used by the
shared contract fixtures, for example `expired`, `bad_signature`, `unknown_kid`,
`typ_mismatch`, `issuer_mismatch`, `audience_mismatch`, `missing_events`,
`nonce_present` or `lifetime_too_long`.

Programmer errors (missing required arguments, invalid PKCE verifier, invalid
configuration) raise `ValueError` or `TypeError`.

## Security defaults

- RS256 only; RSA keys smaller than 2048 bits are rejected.
- `kid` is required and JWKS is refreshed when an unknown `kid` appears.
- Access tokens must have `typ=at+jwt`; ID tokens must have `typ=JWT` or no
  `typ`; logout tokens must have `typ=logout+jwt`.
- `iss` must match the configured issuer exactly.
- Access-token `aud` is mandatory and must match the caller's expected
  audience.
- `exp`, `nbf` and `iat` are validated with a 60-second default leeway.
- HTTP responses are limited to 1 MiB; tokens are limited to 16 KiB.
- Discovery and JWKS caches default to 5 minutes.
- Redirects are not followed, so client credentials are not forwarded to a
  different origin.

## Contract tests

The SDK is tested against the language-neutral corpus in
[`sdk/contract-fixtures`](https://github.com/Bin-hy/yufu/tree/main/sdk/contract-fixtures).
The tests start a loopback issuer on `http://127.0.0.1:18765` and replay the
same discovery, JWKS, PKCE, token, introspection, revocation and logout vectors
as the Go SDK.

Set `YUFU_CONTRACT_FIXTURES` to the fixture directory, or keep the yufu server
repository next to this one:

```bash
export YUFU_CONTRACT_FIXTURES=/path/to/yufu/sdk/contract-fixtures
pytest
```

If the corpus is not available, contract tests are skipped and the unit tests
still run. Do not run contract tests for multiple languages in parallel on the
same host; they share port 18765.

## Development

```bash
uv venv --python 3.12
uv pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy
pytest
```

## Release

The package is published to PyPI as `yufu-sdk` using Trusted Publishing. See
[`docs/release.md`](https://github.com/Bin-hy/yufu-sdk-python/blob/main/docs/release.md)
for the one-time PyPI setup and the tag workflow.

## License

Apache-2.0. See
[LICENSE](https://github.com/Bin-hy/yufu-sdk-python/blob/main/LICENSE).
