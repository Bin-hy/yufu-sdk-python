# Python SDK design and implementation plan

This document records how the Python Runtime SDK maps the Go reference
implementation and the shared contract fixtures. It is the implementation plan
that was used for the `0.1.x` line.

## Goals

- Match the Go SDK's protocol behavior without sharing server code.
- Consume the language-neutral corpus in `yufu/sdk/contract-fixtures`.
- Provide a typed, Pythonic sync client and an asyncio client.
- Ship a package that is ready for PyPI Trusted Publishing.

## Non-goals

- M2M / `client_credentials`.
- Permission synchronization, `/enforce` or legacy RBAC.
- Management/console APIs.
- Generating the client from OpenAPI.

## Module map

| Go SDK | Python module | Responsibility |
|---|---|---|
| `client.go` | `config.py`, `client.py`, `async_client.py` | Config validation, HTTP transport, caches, public facade |
| `discovery.go` | `_core.py`, `models.py` | Discovery parsing, issuer validation, cache |
| `authorize.go` | `_core.py`, `_pkce.py` | Authorization URL, state/nonce, PKCE S256 |
| `token.go` | `_core.py`, `client.py`, `async_client.py` | Code exchange, refresh, single-flight coalescing |
| `verify.go` | `_core.py`, `_jose.py` | JWT/JWKS verification and token profiles |
| `claims.go` | `models.py`, `_core.py` | Typed access/ID/logout claims |
| `introspect.go` | `_core.py`, `client.py` | RFC 7662 introspection |
| `revoke.go` | `client.py` | RFC 7009 revocation |
| `logout.go` | `client.py` | RP-initiated logout URL |
| `userinfo.go` | `_core.py`, `client.py` | UserInfo profile |
| `errors.go` | `errors.py`, `_http.py` | Typed errors, `request_id`, `Retry-After` |
| `internal/pkce` | `_pkce.py` | RFC 7636 helpers |
| `internal/jose` | `_jose.py` | RS256/JWKS subset |

The private modules are intentionally not part of the public API. Callers use
`yufu.Client` / `yufu.AsyncClient` and the typed models exported from `yufu`.

## Public API

| Go | Python |
|---|---|
| `yufu.New(yufu.Config{...})` | `yufu.Client(issuer=..., client_id=..., ...)` |
| `client.AuthorizeURL(opts)` | `client.authorize_url(...)` |
| `client.ExchangeCode(ctx, code, verifier)` | `client.exchange_code(code, verifier, redirect_uri=...)` |
| `client.Refresh(ctx, token)` | `client.refresh(token)` |
| `client.VerifyAccessToken(ctx, token, aud)` | `client.verify_access_token(token, aud)` |
| `client.VerifyIDToken(ctx, token, nonce)` | `client.verify_id_token(token, nonce=...)` |
| `client.VerifyLogoutToken(ctx, token)` | `client.verify_logout_token(token)` |
| `client.UserInfo(ctx, token)` | `client.userinfo(token)` |
| `client.Introspect(ctx, token, hint)` | `client.introspect(token, hint=...)` |
| `client.Revoke(ctx, token, hint)` | `client.revoke(token, hint=...)` |
| `client.EndSessionURL(ctx, opts)` | `client.end_session_url(...)` |
| `client.Discover(ctx)` | `client.discover()` |
| `client.Close()` | `client.close()` / `await client.aclose()` |

Async methods use the same names with `await`. The async client is bound to the
event loop that first uses it.

## Error and rejection mapping

`YufuError` carries the OAuth/HTTP `code`, `status_code`, `request_id`,
`retry_after` and optional `cause`. Token-validation failures also carry a
language-neutral `reason` used by the shared fixtures:

| Fixture reason | Python `reason` |
|---|---|
| `expired` | `expired` |
| `bad_signature` | `bad_signature` |
| `unknown_kid` | `unknown_kid` |
| `typ_mismatch` | `typ_mismatch` |
| `issuer_mismatch` | `issuer_mismatch` |
| `audience_mismatch` | `audience_mismatch` |
| `missing_events` | `missing_events` |
| `nonce_present` | `nonce_present` |
| `lifetime_too_long` | `lifetime_too_long` |

The fixture corpus does not constrain error text; the Python tests assert the
`reason` category, not the message.

## Contract fixture consumption

`tests/conftest.py` loads `manifest.json`, validates every referenced file, and
starts a `ThreadingHTTPServer` on the fixture issuer
(`http://127.0.0.1:18765`). The server implements the ordered `endpoints.json`
rules (`form_equals`, `form_present`, `headers_match`) and serves the static
discovery/JWKS/token/response files. Tests use the fixture clock
(`manifest.clock`) through `Config.now`, so static JWTs validate deterministically.

The fixture root is resolved from `YUFU_CONTRACT_FIXTURES`, then a local
`tests/contract-fixtures` snapshot, then the sibling `cobot-for` / `yufu`
checkouts. If none is present, contract tests skip and unit tests still run.

## Testing plan

| Layer | Coverage |
|---|---|
| Unit | PKCE vectors, config validation, error formatting, `Retry-After`, JOSE/JWKS parsing, claim helpers |
| Client | Single-flight refresh (sync/async), JWKS rotation, error mapping, response-size limit, auth methods, missing endpoints |
| Contract | Discovery/JWKS, authorization-code flow, refresh, endpoint errors, positive/negative token vectors (sync and async) |

## Packaging and release

- Build backend: Hatchling; version read from `src/yufu/_version.py`.
- Distribution name: `yufu-sdk`; import name: `yufu`.
- Runtime dependencies: `httpx` and `cryptography`.
- Typed package: `py.typed` is included in the wheel.
- CI: Python 3.10-3.13, Ruff, mypy, pytest, plus a build/twine job.
- Publish: tag `v*` triggers the Trusted Publishing workflow; see
  [`release.md`](release.md).

## Implementation status

- [x] Config validation, issuer normalization and injectable clock
- [x] Discovery and JWKS caches with issuer/kid refresh
- [x] Authorization Code + PKCE, state/nonce generation
- [x] Code exchange and single-flight refresh (sync/async)
- [x] UserInfo, introspection, revocation, end-session URL
- [x] Access/ID/logout token verification and typed claims
- [x] Typed errors with `request_id`, `Retry-After` and rejection reasons
- [x] Contract fixture server and sync/async contract tests
- [x] PyPI-ready packaging, CI and Trusted Publishing workflow

## Future work

- Optional retry helper with jitter for `temporary` errors.
- Optional HTTP/2 or custom transport examples.
- Java SDK, following the same fixture corpus.
