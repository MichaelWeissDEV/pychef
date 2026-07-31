"""Official CyberChef and BLAKE3 reference vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("value", "size", "key", "expected"),
    [
        ("Hello world", 8, "", "e7e6fb7d2869d109"),
        ("Hello world 2", 16, "", "2a3df5fe5f0d3fcdd995fc203c7f7c52"),
        (
            "Hello world",
            32,
            "",
            "e7e6fb7d2869d109b62cdb1227208d4016cdaa0af6603d95223c6a698137d945",
        ),
        ("Hello world", 8, "ThiskeyisexactlythirtytwoBytesLo", "59dd23ac9d025690"),
        ("Hello world", 8, "ThiskeyisexactlythirtytwoByteslo", "c8302c9634c1da42"),
        (
            "",
            131,
            "",
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
            "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a2"
            "6f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7"
            "001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce"
            "14d",
        ),
        (
            "",
            131,
            "whats the Elvish word for friend",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"
            "b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3"
            "b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758"
            "be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851"
            "bc8f",
        ),
    ],
)
def test_blake3_official_vectors(value: str, size: int, key: str, expected: str) -> None:
    assert bake(value, [{"op": "BLAKE3", "args": [size, key]}]) == expected


def test_blake3_official_binary_keyed_vector() -> None:
    expected = (
        "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600"
        "48eb5e68ce6dea1eb0229e144f578b3aa7e9f4f85febd135df8525e6fe40c6f0"
        "340d13dd09b255ccd5112a94238f2be3c0b5b7ecde06580426a93e0708555a265"
        "305abf86d874e34b4995b788e37a823491f25127a502fe0704baa6bfdf04e76c1"
        "3276"
    )
    assert (
        bake(
            bytes.fromhex("0001020304050607"),
            [{"op": "BLAKE3", "args": [131, "whats the Elvish word for friend"]}],
        )
        == expected
    )


def test_blake3_extended_output_and_validation() -> None:
    output = bake("test", [{"op": "BLAKE3", "args": [16390, ""]}])
    assert isinstance(output, str)
    assert len(output) == 32780
    assert output.startswith("4878")
    assert output.endswith("555fe06b242738d5")
    with pytest.raises(OperationError, match="exactly 32 bytes"):
        bake("test", [{"op": "BLAKE3", "args": [32, "short"]}])
    with pytest.raises(OperationError, match="between 1 and 65535"):
        bake("test", [{"op": "BLAKE3", "args": [0, ""]}])
