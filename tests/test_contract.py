"""Replay the language-neutral yufu SDK contract fixtures."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from yufu import Client, TokenTypeHint, YufuError

from .conftest import Contract


def _query(url: str) -> dict[str, str]:
    from urllib.parse import parse_qs

    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def test_discovery_and_jwks(client: Client, contract: Contract) -> None:
    discovery = client.discover()
    assert discovery.issuer == contract.issuer
    assert discovery.authorization_endpoint == contract.issuer + "/oidc/authorize"
    assert discovery.backchannel_logout_supported
    assert discovery.backchannel_logout_session_supported

    claims = client.verify_access_token(
        contract.read_token("tokens/access-token.jwt"),
        contract.flow["audience"],
    )
    assert claims.subject == "42"
    assert claims.token_use == "user_session"


def test_authorization_code_flow(client: Client, reader: Client, contract: Contract) -> None:
    flow = contract.flow
    authorization = client.authorize_url(state=flow["state"], nonce=flow["nonce"])
    query = _query(authorization.url)
    assert query["state"] == flow["state"]
    assert query["nonce"] == flow["nonce"]
    assert query["code_challenge_method"] == "S256"
    digest = hashlib.sha256(authorization.code_verifier.encode("ascii")).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert authorization.code_challenge == expected_challenge

    tokens = client.exchange_code(flow["code"], flow["code_verifier"])
    assert tokens.refresh_token == "refresh-1"
    assert tokens.expires_in == 300
    assert tokens.expires_at is not None

    id_claims = client.verify_id_token(tokens.id_token, nonce=flow["nonce"])
    assert id_claims.subject == "42"
    assert id_claims.sid == "sid-1"

    access_claims = client.verify_access_token(tokens.access_token, flow["audience"])
    assert access_claims.audience == flow["audience"]
    assert access_claims.token_use == "user_session"

    info = client.userinfo(tokens.access_token)
    assert info.subject == "42"
    assert info.preferred_username == "alice"

    introspection = reader.introspect(tokens.access_token, hint=TokenTypeHint.ACCESS_TOKEN)
    assert introspection.active
    assert introspection.client_id == "web"
    assert introspection.subject == "42"

    client.revoke(tokens.access_token)
    client.revoke(tokens.access_token)

    end_session = client.end_session_url(flow["post_logout_redirect_uri"])
    end_query = _query(end_session)
    assert end_query["client_id"] == flow["client"]["client_id"]
    assert end_query["post_logout_redirect_uri"] == flow["post_logout_redirect_uri"]


def test_refresh(client: Client, contract: Contract) -> None:
    tokens = client.refresh("refresh-1")
    assert tokens.refresh_token == "refresh-2"
    claims = client.verify_access_token(tokens.access_token, contract.flow["audience"])
    assert claims.jti == "jti-2"


def test_endpoint_errors(client: Client, contract: Contract) -> None:
    flow = contract.flow
    with pytest.raises(YufuError) as exc_info:
        client.exchange_code(flow["code"], flow["wrong_code_verifier"])
    assert exc_info.value.code == "invalid_grant"

    bad_reader = Client(
        issuer=contract.issuer,
        client_id=flow["reader"]["client_id"],
        client_secret="wrong",
        now=contract.now,
    )
    try:
        with pytest.raises(YufuError) as exc_info:
            bad_reader.introspect("any")
        assert exc_info.value.code == "invalid_client"
        assert exc_info.value.status_code == 401
    finally:
        bad_reader.close()

    response = httpx.get(contract.issuer + "/oidc/userinfo")
    assert response.status_code == 401

    response = httpx.post(
        contract.issuer + "/oidc/token",
        data={"grant_type": "client_credentials"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def _call_for_token(
    client: Client | Any,
    kind: str,
    token: str,
    item: dict[str, Any],
) -> Callable[[], object]:
    if kind == "access_token":
        return lambda: client.verify_access_token(token, item["audience"])
    if kind == "id_token":
        return lambda: client.verify_id_token(token, item.get("nonce", ""))
    return lambda: client.verify_logout_token(token)


def test_token_expectations(
    client: Client,
    contract: Contract,
    token_case: tuple[str, dict[str, Any]],
) -> None:
    kind, item = token_case
    token = contract.read_token(item["token"])
    call = _call_for_token(client, kind, token, item)
    if item["expect"] == "accept":
        call()
        return
    with pytest.raises(YufuError) as exc_info:
        call()
    assert exc_info.value.reason == item["reason"]


async def test_async_flow(async_client: Any, async_reader: Any, contract: Contract) -> None:
    flow = contract.flow
    discovery = await async_client.discover()
    assert discovery.issuer == contract.issuer

    authorization = await async_client.authorize_url(state=flow["state"], nonce=flow["nonce"])
    assert _query(authorization.url)["state"] == flow["state"]

    tokens = await async_client.exchange_code(flow["code"], flow["code_verifier"])
    id_claims = await async_client.verify_id_token(tokens.id_token, nonce=flow["nonce"])
    assert id_claims.subject == "42"
    access_claims = await async_client.verify_access_token(tokens.access_token, flow["audience"])
    assert access_claims.token_use == "user_session"
    info = await async_client.userinfo(tokens.access_token)
    assert info.preferred_username == "alice"

    introspection = await async_reader.introspect(
        tokens.access_token, hint=TokenTypeHint.ACCESS_TOKEN
    )
    assert introspection.active
    assert introspection.client_id == "web"

    logout_claims = await async_client.verify_logout_token(
        contract.read_token("tokens/logout-token.jwt")
    )
    assert logout_claims.sid == "sid-1"

    refreshed = await async_client.refresh("refresh-1")
    assert refreshed.refresh_token == "refresh-2"

    await async_client.revoke(tokens.access_token)
    end_session = await async_client.end_session_url(flow["post_logout_redirect_uri"])
    assert _query(end_session)["client_id"] == flow["client"]["client_id"]


async def test_async_token_expectations(
    async_client: Any,
    contract: Contract,
    token_case: tuple[str, dict[str, Any]],
) -> None:
    kind, item = token_case
    token = contract.read_token(item["token"])

    async def call() -> object:
        if kind == "access_token":
            return await async_client.verify_access_token(token, item["audience"])
        if kind == "id_token":
            return await async_client.verify_id_token(token, item.get("nonce", ""))
        return await async_client.verify_logout_token(token)

    if item["expect"] == "accept":
        await call()
        return
    with pytest.raises(YufuError) as exc_info:
        await call()
    assert exc_info.value.reason == item["reason"]
