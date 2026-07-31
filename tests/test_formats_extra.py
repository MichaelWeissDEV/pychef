"""Official PHP, Rison, YAML, and Bifid vectors."""

from __future__ import annotations

import json

import pytest

from pychef import OperationError, bake


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("a:0:{}", "{}"),
        ("i:10;", "10"),
        ('s:17:"PHP Serialization";', '"PHP Serialization"'),
        (
            'a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}',
            '{"a": 10,"0": {"ab": true}}',
        ),
    ],
)
def test_php_deserialize_official_vectors(source: str, expected: str) -> None:
    assert bake(source, [{"op": "PHP Deserialize", "args": [True]}]) == expected


def test_php_deserialize_non_json_and_malformed() -> None:
    source = 'a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}'
    assert bake(source, [{"op": "PHP Deserialize", "args": [False]}]) == (
        '{"a": 10,0: {"ab": true}}'
    )
    with pytest.raises(OperationError, match="end of input"):
        bake('s:5:"bad', ["PHP Deserialize"])


def test_rison_official_vectors() -> None:
    assert bake('{"any":"json","yes":true}', [{"op": "Rison Encode", "args": ["Encode"]}]) == (
        "(any:json,yes:!t)"
    )
    assert (
        bake(
            '{"supportsObjects":true,"ints":435}',
            [{"op": "Rison Encode", "args": ["Encode Object"]}],
        )
        == "ints:435,supportsObjects:!t"
    )
    assert (
        bake(
            '["A","B",{"supportsObjects":true}]',
            [{"op": "Rison Encode", "args": ["Encode Array"]}],
        )
        == "A,B,(supportsObjects:!t)"
    )
    decoded = bake("(any:json,yes:!t)", [{"op": "Rison Decode", "args": ["Decode"]}])
    assert json.loads(decoded) == {"any": "json", "yes": True}


def test_rison_nested_round_trip_and_validation() -> None:
    source = '{"text":"needs spaces!","items":[1,false,null,{"x":"y"}]}'
    encoded = bake(source, [{"op": "Rison Encode", "args": ["Encode"]}])
    assert json.loads(bake(encoded, [{"op": "Rison Decode", "args": ["Decode"]}])) == json.loads(
        source
    )
    with pytest.raises(OperationError, match="expects an array"):
        bake("{}", [{"op": "Rison Encode", "args": ["Encode Array"]}])


def test_yaml_official_vectors() -> None:
    source = "number: 3\nplain: string\nblock: |\n  two\n  lines"
    assert json.loads(bake(source, ["YAML to JSON"])) == {
        "number": 3,
        "plain": "string",
        "block": "two\nlines\n",
    }
    assert bake('{ "number": 3, "plain": "string" }', ["JSON to YAML"]) == (
        "number: 3\nplain: string\n"
    )


def test_bifid_official_vectors() -> None:
    source = (
        "We recreate conditions similar to the Van-Allen radiation belt in our secure facilities."
    )
    encoded = bake(source, [{"op": "Bifid Cipher Encode", "args": [""]}])
    assert encoded == (
        "Vq daqcliho rmltofvlnc qbdhlcr nt qdq Fbm-Rdkkm vuoottnoi aitp al axf tdtmvt owppkaodtx."
    )
    assert bake(encoded, [{"op": "Bifid Cipher Decode", "args": [""]}]) == source
    keyed = bake(source, [{"op": "Bifid Cipher Encode", "args": ["Schrodinger"]}])
    assert keyed == (
        "Wc snpsigdd cpfrrcxnfi hikdnnp dm crc Fcb-Pdeug vueageacc vtyl sa zxm crebzp lyoeuaiwpv."
    )
    assert bake(keyed, [{"op": "Bifid Cipher Decode", "args": ["Schrodinger"]}]) == source
    with pytest.raises(OperationError, match="only of letters"):
        bake(source, [{"op": "Bifid Cipher Encode", "args": ["abc123"]}])
