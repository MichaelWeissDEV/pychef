"""Tests for error handling confidentiality and secret masking (Phase 5)."""

from __future__ import annotations

import json

import pytest

from pychef import (
    Chef,
    OperationError,
    Pipeline,
    Recipe,
)

SECRET_INPUT = "TEST_SECRET_INPUT_12345"
SECRET_PASSWORD = "TEST_SECRET_PASSWORD_12345"
SECRET_API_KEY = "TEST_SECRET_API_KEY_12345"
SECRET_SESSION_COOKIE = "TEST_SECRET_SESSION_COOKIE"

ALL_SECRETS = (
    SECRET_INPUT,
    SECRET_PASSWORD,
    SECRET_API_KEY,
    SECRET_SESSION_COOKIE,
)


def assert_secrets_not_leaked(exc: OperationError, secrets: tuple[str, ...]) -> None:
    """Verify that none of the given secrets appear unmasked in any error representation."""
    reps: list[str] = [
        str(exc.message),
        str(exc.safe_message),
        str(exc),
        repr(exc),
        json.dumps(exc.to_dict()),
    ]
    for rep in reps:
        for secret in secrets:
            assert secret not in rep, f"Secret '{secret}' was leaked in: {rep}"


def test_error_confidentiality_args_secret() -> None:
    """Exception caused by invalid operation arguments must not leak secrets."""
    # AES Decrypt with secret key but invalid ciphertext
    recipe = [
        {
            "op": "AES Decrypt",
            "args": [
                {"option": "UTF8", "string": SECRET_PASSWORD},
                {"option": "Hex", "string": "00112233445566778899aabbccddeeff"},
                "CBC",
                "Raw",
                "Raw",
                {"option": "Hex", "string": ""},
            ],
        }
    ]
    with pytest.raises(OperationError) as exc_info:
        Chef().bake("invalid-not-aes-data", recipe)

    exc = exc_info.value
    assert_secrets_not_leaked(exc, (SECRET_PASSWORD,))
    assert "[REDACTED]" in exc.message or SECRET_PASSWORD not in exc.message


def test_error_confidentiality_input_secret() -> None:
    """Exception caused during processing of secret input must not leak secrets."""
    # From Base64 on invalid base64 input that contains secret input
    bad_input = f"{SECRET_INPUT}!!bad@@base64##"
    with pytest.raises(OperationError) as exc_info:
        Chef().bake(bad_input, ["From Base64"])

    exc = exc_info.value
    assert_secrets_not_leaked(exc, (SECRET_INPUT,))


def test_error_confidentiality_regex_credential_patterns() -> None:
    """Credential patterns (Bearer token, cookie, api_key) must be scrubbed."""
    from pychef.recipe import _sanitize_error_message

    raw_msg = (
        f"Request failed: Authorization: Bearer {SECRET_API_KEY}, "
        f"cookie={SECRET_SESSION_COOKIE}, api_key: {SECRET_PASSWORD}"
    )
    sanitized = _sanitize_error_message(raw_msg, args=[], value=None)

    for secret in ALL_SECRETS:
        assert secret not in sanitized

    assert "Bearer [REDACTED]" in sanitized
    assert "cookie=[REDACTED]" in sanitized
    assert "api_key: [REDACTED]" in sanitized


def test_error_confidentiality_in_pipeline_execution() -> None:
    """Pipeline transformation failures must also scrub secrets from all representations."""
    pipeline = Pipeline().then(
        "AES Decrypt",
        {"option": "UTF8", "string": SECRET_PASSWORD},
        {"option": "Hex", "string": "00112233445566778899aabbccddeeff"},
        "CBC",
        "Raw",
        "Raw",
        {"option": "Hex", "string": ""},
    )
    with pytest.raises(OperationError) as exc_info:
        pipeline.transform(f"malformed-payload-{SECRET_INPUT}")

    exc = exc_info.value
    assert_secrets_not_leaked(exc, (SECRET_PASSWORD, SECRET_INPUT))


def test_error_confidentiality_bake_result_captured_error() -> None:
    """When Chef.bake_result captures an error (raise_errors=False), it must be sanitized."""
    recipe = Recipe(
        [
            {
                "op": "AES Decrypt",
                "args": [
                    {"option": "UTF8", "string": SECRET_PASSWORD},
                    {"option": "Hex", "string": "00112233445566778899aabbccddeeff"},
                    "CBC",
                    "Raw",
                    "Raw",
                    {"option": "Hex", "string": ""},
                ],
            }
        ]
    )
    res = Chef().bake_result(f"data-{SECRET_INPUT}", recipe, raise_errors=False)
    assert res.error is not None
    assert isinstance(res.error, OperationError)
    assert_secrets_not_leaked(res.error, (SECRET_PASSWORD, SECRET_INPUT))
