"""Official CyberChef RC2 vectors translated from the upstream suite."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_PLAINTEXT = (
    "7a0e643132750e96d805d11e9e48e281fa39a41039286423cc1c045e5442b40b"
    "f1c3f2822bded3f9c8ef11cb25da64dda9c7ab87c246bd305385150c98f31465"
    "c2a6180fe81d31ea289b916504d5a12e1de26cb10adba84a0cb0c86f94bc14bc"
    "554f3018"
)


@pytest.mark.parametrize(
    ("key", "iv", "ciphertext"),
    [
        (
            "",
            "",
            "d3644d898b51a544f690b506c3fd0caeb7a1e6097f7ea28f69b909a4d8805c9a"
            "05f4cade8b281d3f044fa069374efb90e94723622c86afc17caee394ffbee0abe"
            "627de299208460eb981c9d56f9df885091c6c89e2ee173264b2820b8e6767521"
            "4e6545a05dc0d3f",
        ),
        (
            "eb970554bb213430f4bb4e5988a6a218",
            "ae817c784a097e0c",
            "d25e5bc6c9311ef196d6f21cc4b0274b29fcca366aba5256406e02bf4ae628398"
            "f84e7d72ad92025ede76df4752d1510fe9c3492efb1dcf0be2cd41d619e10b9d"
            "d5a2304c2efbd3598d3b87f1a21f326d45e65537563436cfb6e4a41ec3733182"
            "ddc058f96f74a6c",
        ),
        (
            "eb970554bb213430f4bb4e5988a6a218",
            "",
            "a160bf23b2a85eaa43d26753e51aaa899f162ec0da7280fffd41b705c5309c7fe"
            "f2bbb56bf261cab4eadd3a5c69e0a67d45e426d1097187cc9a959b4d979a9d40"
            "df26f3dc8d030453fe27701438b78d3ce044330b4b5dca7832537ecf40b914f1"
            "b1dc16d4e6d7229",
        ),
    ],
)
def test_rc2_official_vectors(key: str, iv: str, ciphertext: str) -> None:
    args = [
        {"option": "Hex", "string": key},
        {"option": "Hex", "string": iv},
        "Hex",
        "Hex",
    ]
    assert bake(_PLAINTEXT, [{"op": "RC2 Encrypt", "args": args}]) == ciphertext
    assert bake(ciphertext, [{"op": "RC2 Decrypt", "args": args}]) == _PLAINTEXT


def test_rc2_raw_formats_and_validation() -> None:
    args = [
        {"option": "UTF8", "string": "variable key"},
        {"option": "Hex", "string": ""},
        "Raw",
        "Raw",
    ]
    encrypted = bake("RC2 raw data", [{"op": "RC2 Encrypt", "args": args}])
    assert isinstance(encrypted, bytes)
    assert bake(encrypted, [{"op": "RC2 Decrypt", "args": args}]) == b"RC2 raw data"
    with pytest.raises(OperationError, match="8-byte IV"):
        bake("data", [{"op": "RC2 Encrypt", "args": [args[0], {"option": "Hex", "string": "00"}]}])
