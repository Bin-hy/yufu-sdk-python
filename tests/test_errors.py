from __future__ import annotations

from datetime import datetime, timedelta, timezone

from yufu import YufuError, is_error_code
from yufu._http import parse_retry_after


def test_error_format_and_temporary() -> None:
    error = YufuError(
        "invalid_grant",
        "bad code",
        status_code=400,
        request_id="req-1",
    )
    assert str(error) == "yufu: invalid_grant: status=400: request_id=req-1: bad code"
    assert not error.temporary
    assert is_error_code(error, "invalid_grant")
    assert not is_error_code(error, "invalid_client")


def test_transport_error_is_temporary() -> None:
    error = YufuError("network_error", cause=OSError("boom"))
    assert error.temporary


def test_timeout_error_is_temporary() -> None:
    error = YufuError("timeout", cause=TimeoutError("timed out"))
    assert error.temporary


def test_retry_after_seconds() -> None:
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after("-1") == 0.0
    assert parse_retry_after("") == 0.0
    assert parse_retry_after("not-a-date") == 0.0


def test_retry_after_http_date() -> None:
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    later = now + timedelta(seconds=30)
    value = later.strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(value, now=now) == 30.0
    past = (now - timedelta(seconds=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(past, now=now) == 0.0
