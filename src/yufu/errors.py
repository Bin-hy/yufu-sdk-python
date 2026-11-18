"""Typed errors raised by the yufu Runtime SDK."""

from __future__ import annotations

from typing import Final

_TEMPORARY_STATUS_CODES: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})


class YufuError(Exception):
    """An HTTP, OAuth or token-validation failure.

    ``status_code`` is ``0`` for local validation and transport errors. ``code``
    is the OAuth error code when the server supplied one, otherwise a stable SDK
    code such as ``network_error``, ``invalid_response`` or ``invalid_token``.

    ``reason`` is a language-neutral rejection category used by the shared
    contract fixtures (for example ``expired`` or ``bad_signature``). It is
    ``None`` when the failure is not a token-validation rejection.
    """

    def __init__(
        self,
        code: str,
        description: str = "",
        *,
        status_code: int = 0,
        request_id: str = "",
        retry_after: float = 0.0,
        body: bytes = b"",
        reason: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.code = code
        self.description = description
        self.status_code = status_code
        self.request_id = request_id
        self.retry_after = retry_after
        self.body = body
        self.reason = reason
        self.cause = cause
        super().__init__(self._format())

    def _format(self) -> str:
        parts = ["yufu"]
        if self.code:
            parts.append(self.code)
        if self.status_code:
            parts.append(f"status={self.status_code}")
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        if self.description:
            parts.append(self.description)
        if self.cause is not None:
            parts.append(str(self.cause))
        return ": ".join(parts)

    @property
    def temporary(self) -> bool:
        """Whether retrying the request may succeed."""

        if self.cause is not None and self.status_code == 0:
            return True
        return self.status_code in _TEMPORARY_STATUS_CODES

    def __str__(self) -> str:
        return self._format()


# Go SDK parity: callers migrating from Go can keep using ``Error``.
Error = YufuError


def is_error_code(error: BaseException, code: str) -> bool:
    """Return ``True`` when ``error`` is a :class:`YufuError` with ``code``."""

    return isinstance(error, YufuError) and error.code == code
