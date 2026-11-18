"""HTTP response helpers shared by the sync and async clients."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .config import MAX_RESPONSE_SIZE
from .errors import YufuError


def read_limited(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_SIZE:
            raise YufuError(
                code="network_error",
                status_code=response.status_code,
                description="response body exceeds the SDK limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)


async def aread_limited(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_SIZE:
            raise YufuError(
                code="network_error",
                status_code=response.status_code,
                description="response body exceeds the SDK limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def parse_retry_after(value: str, *, now: datetime | None = None) -> float:
    if not value:
        return 0.0
    try:
        seconds = int(value)
    except ValueError:
        seconds = -1
    if seconds >= 0:
        return float(seconds)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return 0.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    delay = (when - current).total_seconds()
    return delay if delay > 0 else 0.0


def new_http_error(response: httpx.Response, body: bytes) -> YufuError:
    request_id = response.headers.get("x-request-id", "")
    retry_after = parse_retry_after(response.headers.get("Retry-After", ""))
    code = ""
    description = ""
    if body:
        try:
            payload = json.loads(body)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            error = payload.get("error")
            error_code = payload.get("code")
            if isinstance(error, str) and error:
                code = error
            elif isinstance(error_code, str) and error_code:
                code = error_code
            value = payload.get("error_description")
            if isinstance(value, str):
                description = value
            value = payload.get("request_id")
            if isinstance(value, str) and value:
                request_id = value
    return YufuError(
        code=code or "http_error",
        description=description or response.reason_phrase or str(response.status_code),
        status_code=response.status_code,
        request_id=request_id,
        retry_after=retry_after,
        body=body,
    )


def decode_json_object(body: bytes, *, status_code: int = 0) -> dict[str, Any]:
    if not body:
        return {}
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise YufuError(
            code="invalid_response",
            description=str(exc),
            status_code=status_code,
            body=body,
            cause=exc,
        ) from exc
    if not isinstance(payload, dict):
        raise YufuError(
            code="invalid_response",
            description="response body is not a JSON object",
            status_code=status_code,
            body=body,
        )
    return payload
