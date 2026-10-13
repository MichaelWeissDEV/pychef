"""Tests for the fluent CTF-oriented Python API."""

from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest

from pychef import (
    ExecutionLimitError,
    ExecutionPolicy,
    OperationPermissionError,
    Pipeline,
    RecipeError,
    aes_decrypt,
    aes_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    chunks,
    cyclic,
    cyclic_find,
    decode_bytes,
    digest,
    digests,
    encode_bytes,
    flat,
    hexdump,
    p8,
    p16,
    p16be,
    p16le,
    p32,
    p64,
    rol,
    ror,
    swap_endian,
    u8,
    u16,
    u16be,
    u16le,
    u32,
    u64,
    xor_bytes,
)


def test_pipeline_chains_operations_is_reusable_and_exports_recipe() -> None:
    pipeline = Pipeline().from_hex().xor(b"\xff").to_hex()
    assert pipeline("0001feff") == "fff e0100".replace(" ", "")
    assert "0001feff" | pipeline == "fffe0100"
    assert pipeline.transform_many(["00", "ff"]) == ("ff", "00")
    assert pipeline.steps == ("From Hex", "xor", "To Hex")
    with pytest.raises(RecipeError, match="Python"):
        _recipe = pipeline.recipe

    recipe_pipeline = Pipeline(["ROT13"]).then("To Upper case")
    assert recipe_pipeline.recipe.execute("hello")[0] == "URYYB"


def test_pipeline_composition_concat_append_select_and_trace() -> None:
    composed = Pipeline().from_hex() | Pipeline().to_base64()
    assert composed("414243") == "QUJD"

    hashes = Pipeline().concat(
        Pipeline().digest("md5"),
        Pipeline().digest("sha1"),
        separator=":",
    )
    assert hashes(b"abc") == f"{hashlib.md5(b'abc').hexdigest()}:{hashlib.sha1(b'abc').hexdigest()}"
    assert Pipeline().apply(bytes.upper).append(b"!")(b"ctf") == b"CTF!"
    assert Pipeline().apply(bytes.upper).prepend(b"> ")(b"ctf") == b"> CTF"

    selector = Pipeline().apply(lambda value: {"packets": [{"port": value}]})
    selector = selector.select("packets", 0, "port")
    assert selector(31337) == 31337
    trace = composed.trace("41")
    assert [entry.name for entry in trace] == ["From Hex", "To Base64"]
    assert trace[-1].output == "QQ=="


def test_pipeline_concat_rejects_mixed_output_types() -> None:
    pipeline = Pipeline().concat(lambda value: value, lambda _value: b"bytes", separator="")
    with pytest.raises(TypeError, match="string separator"):
        pipeline("text")
    with pytest.raises(ValueError, match="at least one"):
        Pipeline().concat()


def test_pack_unpack_endian_flat_chunks_and_bit_helpers() -> None:
    assert p8(0x41) == b"A"
    assert p16(0x1234) == b"\x34\x12"
    assert p16le(0x1234) == b"\x34\x12"
    assert p16be(0x1234) == b"\x12\x34"
    assert p32(0x12345678) == b"xV4\x12"
    assert p64(1) == b"\x01" + b"\0" * 7
    assert u8(b"A") == 0x41
    assert u16(b"\x34\x12") == 0x1234
    assert u16le(b"\x34\x12") == 0x1234
    assert u16be(b"\x12\x34") == 0x1234
    assert u32(b"xx\x78\x56\x34\x12", offset=2) == 0x12345678
    assert u64(b"\x01" + b"\0" * 7) == 1
    assert flat(b"AA", 0x42424242, ["CC", b"DD"]) == b"AABBBBCCDD"
    assert chunks(b"abcdef", 2) == (b"ab", b"cd", b"ef")
    assert chunks("abcde", 2, drop_incomplete=True) == ("ab", "cd")
    assert swap_endian(bytes.fromhex("11223344aabbccdd"), 4) == bytes.fromhex("44332211ddccbbaa")
    assert Pipeline().swap_endian(2).unpack(16, endian="big")(b"\x12\x34") == 0x3412
    assert Pipeline().pack(32)(0x41424344) == b"DCBA"
    assert "|ABC|" in Pipeline().hexdump()(b"ABC")
    assert rol(0x80000001, 1) == 3
    assert ror(3, 1) == 0x80000001
    with pytest.raises(ValueError, match="does not fit"):
        p8(256)
    with pytest.raises(ValueError, match="divisible"):
        swap_endian(b"abc", 2)


def test_encoding_xor_hash_and_hexdump_helpers() -> None:
    assert decode_bytes("41 42", format="hex") == b"AB"
    assert decode_bytes("QUI=", format="base64") == b"AB"
    assert encode_bytes(b"AB", format="hex") == "4142"
    assert encode_bytes(b"AB", format="base64") == "QUI="
    assert xor_bytes(b"ABC", b"\x01") == b"@CB"
    assert digest("abc") == hashlib.sha256(b"abc").hexdigest()
    assert digest("abc", algorithm="sha3-256") == hashlib.sha3_256(b"abc").hexdigest()
    assert digest(b"abc", algorithm="sha1", output="bytes") == hashlib.sha1(b"abc").digest()
    assert digests(b"abc", ["md5", "sha1"]) == {
        "md5": hashlib.md5(b"abc").hexdigest(),
        "sha1": hashlib.sha1(b"abc").hexdigest(),
    }
    dump = hexdump(b"ABC\x00", start=0x1000)
    assert "00001000" in dump and "41 42 43 00" in dump and "|ABC.|" in dump


@pytest.mark.parametrize("mode", ["ECB", "CBC", "CFB", "OFB", "CTR"])
def test_direct_aes_modes_round_trip(mode: str) -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = None if mode == "ECB" else bytes(range(16, 32))
    ciphertext = aes_encrypt(b"CTF payload that is not block aligned", key, mode=mode, iv=iv)
    assert (
        aes_decrypt(ciphertext, key, mode=mode, iv=iv) == b"CTF payload that is not block aligned"
    )


def test_direct_and_pipeline_aes_gcm_support_attached_and_detached_tags() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    ciphertext, tag = aes_gcm_encrypt(b"secret", key, iv=nonce, aad=b"header")
    assert aes_gcm_decrypt(ciphertext, key, iv=nonce, tag=tag, aad=b"header") == b"secret"
    attached = aes_encrypt(b"secret", key, mode="GCM", iv=nonce, aad=b"header")
    assert attached == ciphertext + tag
    assert aes_decrypt(attached, key, mode="GCM", iv=nonce, aad=b"header") == b"secret"

    pipeline = Pipeline().aes_encrypt(key, mode="GCM", iv=nonce, aad=b"header")
    pipeline = pipeline.aes_decrypt(key, mode="GCM", iv=nonce, aad=b"header")
    assert pipeline(b"secret") == b"secret"
    with pytest.raises(ValueError, match="explicit IV"):
        aes_encrypt(b"secret", key, mode="CBC")
    with pytest.raises(ValueError, match="Unable to decrypt"):
        aes_gcm_decrypt(ciphertext, key, iv=nonce, tag=b"\0" * 16, aad=b"header")


def test_cyclic_patterns_find_integer_and_bytes_offsets() -> None:
    pattern = cyclic(256)
    needle = pattern[80:84]
    assert cyclic_find(needle) == 80
    assert cyclic_find(int.from_bytes(needle, "little")) == 80
    assert cyclic(0) == b""
    with pytest.raises(ValueError, match="unique cycle"):
        cyclic(5, alphabet=b"ab", n=2)


def test_pipeline_trace_enforces_policy_limits() -> None:
    pipeline = Pipeline().to_hex().to_base64()
    # Step limit reached
    with pytest.raises(ExecutionLimitError) as info:
        pipeline.trace("hello", policy=ExecutionPolicy(max_steps=1))
    assert info.value.limit == "max_steps"

    # Trace buffer limit reached
    with pytest.raises(ExecutionLimitError) as info:
        pipeline.trace("hello", policy=ExecutionPolicy(max_trace_bytes=50))
    assert info.value.limit == "max_trace_bytes"


def test_pipeline_trace_enforces_network_policy() -> None:
    pipeline = Pipeline(["HTTP request"])
    # Default policy blocks network
    with pytest.raises(OperationPermissionError):
        pipeline.trace("http://example.test/", policy=ExecutionPolicy.safe())


def test_pipeline_trace_sizes_and_preview_truncation() -> None:
    pipeline = Pipeline().to_hex().to_base64()
    trace = pipeline.trace("hello world", max_preview_bytes=4)
    assert len(trace) == 2
    assert trace[0].input == "hell"
    assert trace[0].truncated is True
    assert trace[0].input_size == len("hello world")
    assert trace[1].truncated is True
    assert trace[1].output_size > 4


def test_pipeline_output_limit_enforced_after_non_string_stage() -> None:
    # A stage returning a non-string/bytes object, followed by a stage returning large bytes
    pipeline = Pipeline().apply(lambda _val: {"size": 1000}).apply(lambda d: b"A" * d["size"])
    policy = ExecutionPolicy(max_output_bytes=50)

    # In transform()
    with pytest.raises(ExecutionLimitError) as info:
        pipeline.transform("start", policy=policy)
    assert info.value.limit == "max_output_bytes"

    # In trace()
    with pytest.raises(ExecutionLimitError) as info_trace:
        pipeline.trace("start", policy=policy)
    assert info_trace.value.limit == "max_output_bytes"


def test_pipeline_trace_preview_bounds_and_zero() -> None:
    pipeline = Pipeline().to_hex()

    # max_preview_bytes = 0
    trace_zero = pipeline.trace("hello", max_preview_bytes=0)
    assert trace_zero[0].input == ""
    assert trace_zero[0].truncated is True
    assert trace_zero[0].output == ""
    assert trace_zero[0].input_size == 5

    # max_preview_bytes negative raises ValueError
    with pytest.raises(ValueError, match="max_preview_bytes"):
        pipeline.trace("hello", max_preview_bytes=-1)

    with pytest.raises(ValueError, match="max_preview_bytes"):
        pipeline.trace("hello", max_preview_bytes=cast(Any, "ten"))


def test_pipeline_trace_multibyte_utf8_truncation() -> None:
    # "münchen" in UTF-8: 'm' (1 byte), 'ü' (2 bytes: \xc3\xbc), 'n' ...
    # Slicing at 2 bytes cuts the 'ü' in half; our handler drops partial bytes safely
    pipeline = Pipeline().apply(lambda x: x)
    trace = pipeline.trace("münchen", max_preview_bytes=2)
    assert trace[0].input == "m"  # only 1 complete character fits in 2 bytes
    assert trace[0].truncated is True
    assert trace[0].input_size == len("münchen".encode())
