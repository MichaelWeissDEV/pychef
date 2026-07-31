"""Official Microsoft Script Decoder vector from CyberChef."""

from __future__ import annotations

from pychef import bake


def test_microsoft_script_decoder_official_vector() -> None:
    encoded = (
        "#@~^RQAAAA==-mD~sX|:/TP{~J:+dYbxL~@!F@*@!+@*@!&@*eEI@#@&@#@&"
        "\x7fjm.raY 214Wv:zms/obI0xEAAA==^#~@"
    )
    assert bake(encoded, ["Microsoft Script Decoder"]) == (
        'var my_msg = "Testing <1><2><3>!";\r\n\r\nWScript.Echo(my_msg);'
    )


def test_microsoft_script_decoder_returns_empty_for_plain_text() -> None:
    assert bake("not encoded", ["Microsoft Script Decoder"]) == ""
