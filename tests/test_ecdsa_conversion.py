"""Official CyberChef ECDSA signature conversion vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_ASN1 = (
    "3046022100e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff1"
    "35145127022100b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77"
    "b8b324388d"
)
_P1363 = (
    "e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff135145127"
    "b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77b8b324388d"
)
_JWS = "4GkFYIovp9vanihMKnlZ37aPtSel8AOy15df8TUUUSe2uqJTeTM0-Lk-od1iK8YAEk2AkLq9gH7-P3e4syQ4jQ"
_JSON = (
    '{"r":"00e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff135145127",'
    '"s":"00b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77b8b324388d"}'
)


@pytest.mark.parametrize(
    ("input_format", "value"),
    [
        ("ASN.1 HEX", _ASN1),
        ("P1363 HEX", _P1363),
        ("JSON Web Signature", _JWS),
        ("Raw JSON", _JSON),
    ],
)
@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("ASN.1 HEX", _ASN1),
        ("P1363 HEX", _P1363),
        ("JSON Web Signature", _JWS),
        ("Raw JSON", _JSON),
    ],
)
def test_ecdsa_signature_conversion_all_explicit_formats(
    input_format: str,
    value: str,
    output_format: str,
    expected: str,
) -> None:
    assert (
        bake(
            value,
            [{"op": "ECDSA Signature Conversion", "args": [input_format, output_format]}],
        )
        == expected
    )


@pytest.mark.parametrize("value", [_ASN1, _P1363, _JWS, _JSON])
def test_ecdsa_signature_conversion_auto_detection(value: str) -> None:
    assert (
        bake(value, [{"op": "ECDSA Signature Conversion", "args": ["Auto", "P1363 HEX"]}]) == _P1363
    )


def test_ecdsa_signature_conversion_validation() -> None:
    with pytest.raises(OperationError, match="could not be detected"):
        bake(
            "not a signature", [{"op": "ECDSA Signature Conversion", "args": ["Auto", "ASN.1 HEX"]}]
        )
    with pytest.raises(OperationError, match='No "r"'):
        bake(
            '{"s":"01"}', [{"op": "ECDSA Signature Conversion", "args": ["Raw JSON", "ASN.1 HEX"]}]
        )
    with pytest.raises(OperationError, match='No "s"'):
        bake(
            '{"r":"01"}', [{"op": "ECDSA Signature Conversion", "args": ["Raw JSON", "ASN.1 HEX"]}]
        )
