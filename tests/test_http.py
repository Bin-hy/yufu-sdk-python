from __future__ import annotations

import httpx
import pytest

from yufu import YufuError
from yufu._http import aread_limited, decode_json_object, new_http_error, read_limited


def test_read_limited_rejects_oversized_body() -> None:
    response = httpx.Response(200, content=b"x" * ((1 << 20) + 1))
    with pytest.raises(YufuError) as exc_info:
        read_limited(response)
    assert exc_info.value.code == "network_error"


async def test_aread_limited_rejects_oversized_body() -> None:
    response = httpx.Response(200, content=b"x" * ((1 << 20) + 1))
    with pytest.raises(YufuError) as exc_info:
        await aread_limited(response)
    assert exc_info.value.code == "network_error"


def test_decode_json_object_rejects_invalid_payloads() -> None:
    with pytest.raises(YufuError) as exc_info:
        decode_json_object(b"not-json")
    assert exc_info.value.code == "invalid_response"
    with pytest.raises(YufuError) as exc_info:
        decode_json_object(b"[]")
    assert exc_info.value.code == "invalid_response"
    assert decode_json_object(b"") == {}


def test_new_http_error_uses_reason_when_body_is_not_json() -> None:
    response = httpx.Response(
        502,
        headers={"x-request-id": "req-1"},
        content=b"bad gateway",
    )
    error = new_http_error(response, b"bad gateway")
    assert error.code == "http_error"
    assert error.status_code == 502
    assert error.request_id == "req-1"
    assert error.description == "Bad Gateway"


def test_new_http_error_accepts_code_field() -> None:
    response = httpx.Response(400, content=b'{"code":"invalid_request"}')
    error = new_http_error(response, response.content)
    assert error.code == "invalid_request"
