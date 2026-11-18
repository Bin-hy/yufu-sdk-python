from __future__ import annotations

import asyncio
import base64
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from yufu import AsyncClient, Client, TokenAuthMethod, YufuError

from .helpers import discovery, jwks, make_key, sign

ISSUER = "http://issuer.test"
CLOCK = 1793491200


def now() -> datetime:
    return datetime.fromtimestamp(CLOCK, timezone.utc)


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


def make_client(handler: Any, **config: Any) -> Client:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return Client(
        issuer=ISSUER,
        client_id="web",
        client_secret="secret",
        now=now,
        http_client=http,
        **config,
    )


def test_single_flight_refresh() -> None:
    key = make_key()
    count = 0
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        with lock:
            count += 1
        time.sleep(0.1)
        return httpx.Response(
            200,
            json={
                "access_token": sign(key, claims()),
                "refresh_token": "refresh-2",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )

    client = make_client(handler)
    try:
        barrier = threading.Barrier(5)

        def worker() -> Any:
            barrier.wait()
            return client.refresh("refresh-1")

        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: worker(), range(5)))
    finally:
        client.close()
    assert count == 1
    assert {result.refresh_token for result in results} == {"refresh-2"}


def test_single_flight_propagates_error() -> None:
    count = 0
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        with lock:
            count += 1
        time.sleep(0.05)
        return httpx.Response(400, json={"error": "invalid_grant"})

    client = make_client(handler)
    try:
        barrier = threading.Barrier(5)

        def worker() -> Any:
            barrier.wait()
            return client.refresh("refresh-1")

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(worker) for _ in range(5)]
            errors = [future.exception() for future in futures]
    finally:
        client.close()
    assert count == 1
    assert all(isinstance(error, YufuError) for error in errors)
    assert {error.code for error in errors if isinstance(error, YufuError)} == {"invalid_grant"}


async def test_async_single_flight_refresh() -> None:
    key = make_key()
    count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        count += 1
        await asyncio.sleep(0.1)
        return httpx.Response(
            200,
            json={
                "access_token": sign(key, claims()),
                "refresh_token": "refresh-2",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            now=now,
            http_client=http,
        ) as client,
    ):
        results = await asyncio.gather(*(client.refresh("refresh-1") for _ in range(5)))
    assert count == 1
    assert {result.refresh_token for result in results} == {"refresh-2"}


async def test_async_single_flight_propagates_error() -> None:
    count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        count += 1
        await asyncio.sleep(0.05)
        return httpx.Response(400, json={"error": "invalid_grant"})

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            now=now,
            http_client=http,
        ) as client,
    ):
        results = await asyncio.gather(
            *(client.refresh("refresh-1") for _ in range(5)),
            return_exceptions=True,
        )
    assert count == 1
    errors = [result for result in results if isinstance(result, YufuError)]
    assert len(errors) == len(results)
    assert {error.code for error in errors} == {"invalid_grant"}


def test_jwks_rotation_refetches_on_unknown_kid() -> None:
    first = make_key()
    second = make_key()
    current: dict[str, Any] = {"kid": "key-1", "key": first}
    jwks_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwks_count
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        jwks_count += 1
        return httpx.Response(200, json=jwks((current["kid"], current["key"])))

    client = make_client(handler)
    try:
        first_token = sign(first, claims(), kid="key-1")
        assert client.verify_access_token(first_token, "urn:app:test").subject == "42"
        current.update(kid="key-2", key=second)
        second_token = sign(second, claims(), kid="key-2")
        assert client.verify_access_token(second_token, "urn:app:test").subject == "42"
    finally:
        client.close()
    assert jwks_count == 2


def test_error_mapping_includes_request_id_and_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "7", "x-request-id": "hdr-1"},
            json={
                "error": "slow_down",
                "error_description": "too fast",
                "request_id": "body-1",
            },
        )

    client = make_client(handler)
    try:
        with pytest.raises(YufuError) as exc_info:
            client.discover()
    finally:
        client.close()
    error = exc_info.value
    assert error.code == "slow_down"
    assert error.status_code == 429
    assert error.description == "too fast"
    assert error.request_id == "body-1"
    assert error.retry_after == 7.0
    assert error.temporary


async def test_async_error_mapping() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "temporarily_unavailable"})

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            now=now,
            http_client=http,
        ) as client,
    ):
        with pytest.raises(YufuError) as exc_info:
            await client.discover()
    assert exc_info.value.code == "temporarily_unavailable"
    assert exc_info.value.temporary


def test_response_size_limit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * ((1 << 20) + 1))

    client = make_client(handler)
    try:
        with pytest.raises(YufuError) as exc_info:
            client.discover()
    finally:
        client.close()
    assert exc_info.value.code == "network_error"
    assert "exceeds" in exc_info.value.description


def test_authorize_url_rejects_reserved_extra() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery(ISSUER))

    client = make_client(handler, redirect_uri="https://app.example/callback")
    try:
        with pytest.raises(ValueError):
            client.authorize_url(extra={"client_id": "other"})
        with pytest.raises(ValueError):
            client.authorize_url(scopes=["profile"])
        authorization = client.authorize_url()
    finally:
        client.close()
    query = parse_qs(urlsplit(authorization.url).query)
    assert query["client_id"] == ["web"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid"]
    assert len(authorization.state) == 43
    assert len(authorization.nonce) == 43
    assert len(authorization.code_verifier) == 43


def test_end_session_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery(ISSUER))

    client = make_client(handler)
    try:
        url = client.end_session_url(
            "https://app.example/",
            id_token_hint="id-token",
            state="state-1",
        )
    finally:
        client.close()
    query = parse_qs(urlsplit(url).query)
    assert query["client_id"] == ["web"]
    assert query["post_logout_redirect_uri"] == ["https://app.example/"]
    assert query["id_token_hint"] == ["id-token"]
    assert query["state"] == ["state-1"]


def test_token_set_rejects_non_bearer() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        return httpx.Response(200, json={"access_token": "a", "token_type": "MAC"})

    client = make_client(handler, redirect_uri="https://app.example/callback")
    try:
        with pytest.raises(YufuError) as exc_info:
            client.exchange_code("code", "a" * 43)
    finally:
        client.close()
    assert exc_info.value.code == "invalid_response"


def test_introspection_inactive() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        return httpx.Response(200, json={"active": False})

    client = make_client(handler)
    try:
        introspection = client.introspect("token")
    finally:
        client.close()
    assert not introspection.active
    assert introspection.subject == ""


def test_discovery_issuer_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery("https://other.example"))

    client = make_client(handler)
    try:
        with pytest.raises(YufuError) as exc_info:
            client.discover()
    finally:
        client.close()
    assert exc_info.value.code == "invalid_discovery"


@pytest.mark.parametrize(
    ("method", "endpoint"),
    [
        ("introspect", "introspection_endpoint"),
        ("revoke", "revocation_endpoint"),
        ("userinfo", "userinfo_endpoint"),
        ("end_session_url", "end_session_endpoint"),
    ],
)
def test_missing_endpoint_is_unsupported(method: str, endpoint: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery(ISSUER, **{endpoint: ""}))

    client = make_client(handler)
    try:
        with pytest.raises(YufuError) as exc_info:
            if method == "introspect":
                client.introspect("token")
            elif method == "revoke":
                client.revoke("token")
            elif method == "userinfo":
                client.userinfo("token")
            else:
                client.end_session_url("https://app.example/")
    finally:
        client.close()
    assert exc_info.value.code == "unsupported"


def test_refresh_keeps_old_refresh_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        return httpx.Response(
            200,
            json={"access_token": "a", "token_type": "Bearer", "expires_in": 300},
        )

    client = make_client(handler)
    try:
        tokens = client.refresh("refresh-1")
    finally:
        client.close()
    assert tokens.refresh_token == "refresh-1"


def test_client_secret_basic_is_sent_as_basic_auth() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        seen["authorization"] = request.headers.get("Authorization", "")
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={"access_token": "a", "token_type": "Bearer", "expires_in": 300},
        )

    client = make_client(
        handler,
        redirect_uri="https://app.example/callback",
        token_auth_method=TokenAuthMethod.CLIENT_SECRET_BASIC,
    )
    try:
        client.exchange_code("code", "a" * 43)
    finally:
        client.close()
    expected = base64.b64encode(b"web:secret").decode("ascii")
    assert seen["authorization"] == f"Basic {expected}"
    assert "client_secret" not in seen["body"]


def test_client_secret_post_is_sent_in_form() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={"access_token": "a", "token_type": "Bearer", "expires_in": 300},
        )

    client = make_client(handler, redirect_uri="https://app.example/callback")
    try:
        client.exchange_code("code", "a" * 43)
    finally:
        client.close()
    form = parse_qs(seen["body"])
    assert form["client_id"] == ["web"]
    assert form["client_secret"] == ["secret"]


def test_exchange_code_accepts_redirect_uri_override() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={"access_token": "a", "token_type": "Bearer", "expires_in": 300},
        )

    client = make_client(handler)
    try:
        client.exchange_code(
            "code",
            "a" * 43,
            redirect_uri="https://app.example/other-callback",
        )
    finally:
        client.close()
    form = parse_qs(seen["body"])
    assert form["redirect_uri"] == ["https://app.example/other-callback"]


async def test_async_introspect_and_revoke() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        if request.url.path == "/oidc/introspect":
            return httpx.Response(
                200,
                json={"active": True, "sub": "42", "client_id": "web"},
            )
        return httpx.Response(200)

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            now=now,
            http_client=http,
        ) as client,
    ):
        introspection = await client.introspect("token", hint="access_token")
        assert introspection.active
        assert introspection.subject == "42"
        await client.revoke("token")


async def test_async_token_set_rejects_non_bearer() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        return httpx.Response(200, json={"access_token": "a", "token_type": "MAC"})

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            redirect_uri="https://app.example/callback",
            now=now,
            http_client=http,
        ) as client,
    ):
        with pytest.raises(YufuError) as exc_info:
            await client.exchange_code("code", "a" * 43)
    assert exc_info.value.code == "invalid_response"


async def test_async_missing_endpoint_is_unsupported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery(ISSUER, introspection_endpoint=""))

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            now=now,
            http_client=http,
        ) as client,
    ):
        with pytest.raises(YufuError) as exc_info:
            await client.introspect("token")
    assert exc_info.value.code == "unsupported"


async def test_async_client_secret_basic() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery(ISSUER))
        seen["authorization"] = request.headers.get("Authorization", "")
        return httpx.Response(
            200,
            json={"access_token": "a", "token_type": "Bearer", "expires_in": 300},
        )

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http,
        AsyncClient(
            issuer=ISSUER,
            client_id="web",
            client_secret="secret",
            redirect_uri="https://app.example/callback",
            token_auth_method=TokenAuthMethod.CLIENT_SECRET_BASIC,
            now=now,
            http_client=http,
        ) as client,
    ):
        await client.exchange_code("code", "a" * 43)
    expected = base64.b64encode(b"web:secret").decode("ascii")
    assert seen["authorization"] == f"Basic {expected}"
