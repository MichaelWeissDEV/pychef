"""Official HMAC JWT and Flask session vectors."""

from __future__ import annotations

import json

import pytest

from pychef import OperationError, bake

_PAYLOAD = '{"String":"SomeString","Number":42,"iat":1}'


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        (
            "HS256",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJTdHJpbmciOiJTb21lU3RyaW5nIiwiTnVtYmVyIjo0MiwiaWF0IjoxfQ."
            "0ha6-j4FwvEIKPVZ-hf3S_R9Hy_UtXzq4dnedXcUrXk",
        ),
        (
            "HS384",
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJTdHJpbmciOiJTb21lU3RyaW5nIiwiTnVtYmVyIjo0MiwiaWF0IjoxfQ."
            "_bPK-Y3mIACConbJqkGFMQ_L3vbxgKXy9gSxtL9hA5XTganozTSXxD0vX0N1yT5s",
        ),
        (
            "HS512",
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9."
            "eyJTdHJpbmciOiJTb21lU3RyaW5nIiwiTnVtYmVyIjo0MiwiaWF0IjoxfQ."
            "vZIJU4XYMFt3FLE1V_RZOxEetmV4RvxtPZQGzJthK_d47pjwlEb6pQE23YxHFmOj8H5RLEdqqLPw4jNsOyHRzA",
        ),
    ],
)
def test_jwt_sign_official_hmac_vectors(algorithm: str, expected: str) -> None:
    token = bake(_PAYLOAD, [{"op": "JWT Sign", "args": ["secret_cat", algorithm, "{}"]}])
    assert token == expected
    assert json.loads(bake(token, [{"op": "JWT Verify", "args": ["secret_cat"]}])) == json.loads(
        _PAYLOAD
    )


def test_jwt_custom_header_and_security_checks() -> None:
    token = bake(
        _PAYLOAD,
        [{"op": "JWT Sign", "args": ["secret_cat", "HS256", '{"kid":"custom.key"}']}],
    )
    assert isinstance(token, str)
    assert token.endswith("kXln8btJburfRlND8IDZAQ8NZGFFZhvHyooHa6N9za8")
    with pytest.raises(OperationError, match="invalid JWT signature"):
        bake(token, [{"op": "JWT Verify", "args": ["wrong"]}])
    unsigned = "eyJhbGciOiJub25lIn0.e30."
    with pytest.raises(OperationError, match="rejects asymmetric or unsigned"):
        bake(unsigned, [{"op": "JWT Verify", "args": [""]}])


@pytest.mark.parametrize(
    ("token", "algorithm"),
    [
        (
            "eyJyb2xlIjoic3VwZXJ1c2VyIiwidXNlciI6ImFkbWluIn0.aZ-KEw.E_x6bOhA4GU9t72pMinJUjN-O3I",
            "sha1",
        ),
        (
            "eyJyb2xlIjoic3VwZXJ1c2VyIiwidXNlciI6ImFkbWluIn0.aab3Ew."
            "Jsx2DOx_H9anZg0YcvhsASxQ11897EFHeQfS2oja4y8",
            "sha256",
        ),
    ],
)
def test_flask_session_official_vectors(token: str, algorithm: str) -> None:
    expected = {"role": "superuser", "user": "admin"}
    assert json.loads(bake(token, [{"op": "Flask Session Decode", "args": [False]}])) == expected
    args = [
        {"string": "mysecretkey", "option": "UTF8"},
        {"string": "cookie-session", "option": "UTF8"},
        algorithm,
        False,
    ]
    assert json.loads(bake(token, [{"op": "Flask Session Verify", "args": args}])) == {
        "valid": True,
        "payload": expected,
    }
    wrong = [{"string": "notTheKey", "option": "UTF8"}, args[1], algorithm, False]
    assert bake(token, [{"op": "Flask Session Verify", "args": wrong}]) == "Invalid signature!"


def test_flask_session_sign_round_trip() -> None:
    payload = '{"role":"superuser","user":"admin"}'
    sign_args = [
        {"string": "mysecretkey", "option": "UTF8"},
        {"string": "cookie-session", "option": "UTF8"},
        "sha256",
    ]
    token = bake(payload, [{"op": "Flask Session Sign", "args": sign_args}])
    verify_args = [*sign_args, False]
    assert json.loads(bake(token, [{"op": "Flask Session Verify", "args": verify_args}]))[
        "payload"
    ] == json.loads(payload)
