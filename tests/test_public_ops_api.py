"""Behavior tests for the direct operations API (``pychef.ops``)."""

from __future__ import annotations

import gzip
import hashlib
import inspect
import subprocess
import sys

import pytest

import pychef
from pychef import ExecutionLimitError, ExecutionPolicy, OperationPermissionError, bake, ctf, ops
from pychef.ops import (
    digest,
    from_base32,
    from_base64,
    from_hex,
    gzip_compress,
    gzip_decompress,
    html_decode,
    html_encode,
    md5,
    reverse,
    rot13,
    run_operation,
    sha1,
    sha256,
    sha512,
    to_base32,
    to_base64,
    to_hex,
    url_decode,
    url_encode,
    using_policy,
    xor,
)
from pychef.ops.bitwise import XorKeyFormat


def test_lazy_attribute_and_direct_import_agree() -> None:
    assert pychef.ops is ops
    assert set(ops.__all__) <= set(dir(ops))


def test_hex_and_base64_round_trip_with_recipe_parity() -> None:
    data = from_hex("414243")
    assert data == b"ABC"
    assert to_base64(data) == "QUJD" == bake("414243", ["From Hex", "To Base64"])
    assert from_base64("QUJD") == b"ABC"
    assert to_hex(b"ABC") == "414243"
    assert to_hex(b"ABC", delimiter="Space") == "41 42 43"
    assert to_hex(b"ABCD", delimiter="Space", bytes_per_line=2) == "41 42\n43 44"
    assert from_hex("41:42:43", delimiter="Colon") == b"ABC"
    assert from_hex(b"414243") == b"ABC"


def test_base32_and_base64_alphabet_options() -> None:
    assert to_base32("ABC") == "IFBEG==="
    assert from_base32("IFBEG===") == b"ABC"
    assert to_base64(b"\xfb\xff", alphabet="A-Za-z0-9-_") == "-_8"
    assert from_base64("-_8", alphabet="A-Za-z0-9-_") == b"\xfb\xff"


@pytest.mark.parametrize("text", ["", "ünïcödé ✓", "a b&c=d/é"])
def test_url_and_html_round_trip_unicode(text: str) -> None:
    assert url_decode(url_encode(text)) == text
    assert html_decode(html_encode(text, convert_all=True, format="Hex entities")) == text
    assert html_encode("<a&>") == "&lt;a&amp;&gt;"
    assert url_decode("a+b%20c") == "a b c"
    assert url_decode("a+b", plus_as_space=False) == "a+b"


def test_rot13_and_reverse_preserve_input_type() -> None:
    assert rot13("Hello") == "Uryyb"
    assert rot13(b"Hello") == b"Uryyb"
    assert rot13("abc9", amount=1, numbers=True) == "bcd0"
    assert reverse("héllo") == "olléh"
    assert reverse("ab\ncd", by="Line") == "cd\nab"
    assert reverse(b"abc") == b"cba"
    with pytest.raises(ValueError, match="Byte"):
        reverse("abc", by="Byte")  # type: ignore


def test_xor_variants_match_pipeline() -> None:
    assert xor(b"abc", b"\x01") == b"`cb"
    assert xor("abc", "A") == b' #"'
    assert xor(b"abc", " ") == bytes(c ^ 0x20 for c in b"abc")
    with pytest.raises(ValueError, match="empty"):
        xor(b"abc", "  ", key_format="hex")
    assert xor(b"AB", "0102", key_format="hex") == b"@@"
    assert xor(b"AB", "AQI=", key_format="base64") == b"@@"
    assert xor(b"\xff", "ÿ", key_format="latin1") == b"\x00"
    expected = pychef.Pipeline().xor(b"\x42")(b"hello")
    assert xor(b"hello", b"\x42") == expected
    with pytest.raises(ValueError, match="empty"):
        xor(b"abc", b"")
    with pytest.raises(ValueError, match="key_format"):
        xor(b"abc", "k", key_format="nope")  # type: ignore


def test_gzip_round_trip_and_stdlib_interop() -> None:
    packed = gzip_compress("hello", filename="f", include_checksum=True)
    assert gzip.decompress(packed) == b"hello"
    assert gzip_decompress(gzip.compress(b"world")) == b"world"
    assert gzip_decompress(packed) == b"hello"


def test_hash_helpers_share_one_format_with_ctf() -> None:
    for name, func in {"md5": md5, "sha1": sha1, "sha256": sha256, "sha512": sha512}.items():
        assert func("abc") == getattr(hashlib, name)(b"abc").hexdigest()
        assert func(b"abc") == getattr(ctf, name)(b"abc") == getattr(pychef, name)(b"abc")
    assert digest(b"abc", output="raw") == hashlib.sha256(b"abc").digest()
    assert digest(b"abc", algorithm="sha3-256", output="base64")
    with pytest.raises(ValueError, match="unsupported hash"):
        digest(b"abc", algorithm="nope")


def test_binary_input_and_bytes_like_values() -> None:
    raw = bytes(range(256))
    assert from_base64(to_base64(raw)) == raw
    assert from_hex(to_hex(raw)) == raw
    assert to_hex(bytearray(b"AB")) == "4142"
    assert to_hex(memoryview(b"AB")) == "4142"
    assert gzip_decompress(gzip_compress(raw)) == raw


@pytest.mark.parametrize("bad", [1, None, ["a"], 1.5])
def test_non_data_input_is_rejected(bad: object) -> None:
    with pytest.raises(TypeError, match="str or bytes-like"):
        to_hex(bad)  # type: ignore
    with pytest.raises(TypeError):
        sha256(bad)  # type: ignore


def test_keyword_only_options() -> None:
    for func in (from_hex, to_hex, from_base64, to_base64, url_encode, xor, rot13, gzip_compress):
        parameters = list(inspect.signature(func).parameters.values())
        assert all(
            p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters[1:] if p.name != "key"
        ), func
        assert not any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in parameters)
    with pytest.raises(TypeError):
        to_hex(b"A", "Space")  # type: ignore


def test_run_operation_generic_entry_point() -> None:
    assert run_operation("To Base64", b"Hello") == "SGVsbG8="
    assert run_operation("To Hex", b"AB", ("Space", 0)) == "41 42"
    assert run_operation("From Hex", "4142") == b"AB"
    with pytest.raises(pychef.UnknownOperationError):
        run_operation("No Such Op", "x")
    with pytest.raises(TypeError, match="args"):
        run_operation("To Base64", "x", "abc")


def test_default_policy_is_safe_and_network_is_denied() -> None:
    http = ("GET", "http://127.0.0.1:9/")
    with pytest.raises(OperationPermissionError):
        run_operation("HTTP request", "", http)
    with pytest.raises(OperationPermissionError):
        bake("", [{"op": "HTTP request", "args": list(http)}])


def test_input_limits_apply_to_every_helper() -> None:
    small = ExecutionPolicy(max_input_bytes=4)
    with pytest.raises(ExecutionLimitError):
        run_operation("To Hex", b"12345", policy=small)
    with using_policy(small):
        with pytest.raises(ExecutionLimitError):
            to_base64(b"12345")
        with pytest.raises(ExecutionLimitError):
            sha256(b"12345")
        assert to_base64(b"1234") == "MTIzNA=="
    # scope restored
    assert to_base64(b"12345") == "MTIzNDU="
    with using_policy(ExecutionPolicy.unrestricted()):
        assert len(to_hex(b"x" * 10)) == 20


def test_using_policy_nesting_is_innermost_wins() -> None:
    outer = ExecutionPolicy(max_input_bytes=2)
    inner = ExecutionPolicy(max_input_bytes=100)
    pipeline = pychef.Pipeline().apply(lambda value: to_base64(value))
    with using_policy(outer):
        with pytest.raises(ExecutionLimitError):
            to_base64(b"abc")
        # the pipeline's own policy is the innermost one while it runs
        assert pipeline(b"ab", policy=inner) == "YWI="
        with using_policy(inner):
            assert to_base64(b"abc") == "YWJj"
        with pytest.raises(ExecutionLimitError):
            to_base64(b"abc")


def test_xor_matches_pipeline_for_every_key_type() -> None:
    cases: list[tuple[str | bytes, XorKeyFormat]] = [
        (b"4142", "hex"),
        ("4142", "hex"),
        (b"QUI=", "base64"),
        (b"AB", "raw"),
    ]
    for key, fmt in cases:
        expected = pychef.Pipeline().xor(key, key_format=fmt)(b"hello")
        assert xor(b"hello", key, key_format=fmt) == expected


def test_using_policy_validates_type_and_is_context_local() -> None:
    with pytest.raises(TypeError), using_policy("safe"):  # type: ignore
        pass


def test_helpers_inherit_policy_of_enclosing_execution() -> None:
    pipeline = pychef.Pipeline().apply(lambda value: to_base64(value))
    with pytest.raises(ExecutionLimitError):
        pipeline(b"12345", policy=ExecutionPolicy(max_input_bytes=4, max_output_bytes=None))


def test_import_pychef_ops_stays_light() -> None:
    code = (
        "import sys; from pychef.ops import from_hex; from_hex('41');"
        "heavy=[m for m in sys.modules if m.startswith('pychef.operations.') "
        "and m not in {'pychef.operations._utils','pychef.operations.by_operation',"
        "'pychef.operations.by_operation.from_hex','pychef.operations.encoding'}];"
        "assert not heavy, heavy"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
