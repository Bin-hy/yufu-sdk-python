from __future__ import annotations

import string

import pytest

from yufu._pkce import challenge, new_verifier, validate_verifier


def test_new_verifier_is_rfc7636_shaped() -> None:
    verifier = new_verifier()
    assert len(verifier) == 43
    assert set(verifier) <= set(string.ascii_letters + string.digits + "-._~")
    validate_verifier(verifier)


def test_s256_challenge_matches_rfc7636_example() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize(
    "verifier",
    [
        "a" * 42,
        "a" * 129,
        "a" * 42 + "!",
        "a" * 42 + " ",
    ],
)
def test_validate_verifier_rejects_invalid_values(verifier: str) -> None:
    with pytest.raises(ValueError):
        validate_verifier(verifier)
