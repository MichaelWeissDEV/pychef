"""Official CyberChef text-encoding brute-force examples."""

from __future__ import annotations

import json

from pychef import bake


def test_text_encoding_brute_force_official_encode_vector() -> None:
    mojibake = "Р‘СѓР»РєС– РїСЂР°Р· Р»СЏРЅС–РІР° СЃР°Р±Р°РєСѓ."  # noqa: RUF001
    result = bake(mojibake, [{"op": "Text Encoding Brute Force", "args": ["Encode"]}])
    assert isinstance(result, str)
    values = json.loads(result)
    assert values["Windows-1251 Cyrillic (1251)"] == "Булкі праз ляніва сабаку."


def test_text_encoding_brute_force_official_decode_vector() -> None:
    encoded = "Áóëê³ ïðàç ëÿí³âà ñàáàêó."
    result = bake(encoded, [{"op": "Text Encoding Brute Force", "args": ["Decode"]}])
    assert isinstance(result, str)
    values = json.loads(result)
    assert values["Windows-1251 Cyrillic (1251)"] == "Булкі праз ляніва сабаку."
    assert len(values) == 152
