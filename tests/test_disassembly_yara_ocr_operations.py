from __future__ import annotations

import re

import pytest

from pychef import bake
from pychef.operations.image_ops import _Image, _png_encode


@pytest.mark.parametrize(
    ("machine_code", "args", "pattern"),
    [
        ("00 00 a0 e1", ["ARM (32-bit)", "ARM", "Little Endian", 0, True, True], r"mov\s+r0,\s*r0"),
        ("1e ff 2f e1", ["ARM (32-bit)", "ARM", "Little Endian", 0, True, True], r"bx\s+lr"),
        (
            "00 48 2d e9",
            ["ARM (32-bit)", "ARM", "Little Endian", 0, True, True],
            r"push\s+\{fp,\s*lr\}",
        ),
        (
            "10 b5",
            ["ARM (32-bit)", "Thumb", "Little Endian", 0, True, True],
            r"push\s+\{r4,\s*lr\}",
        ),
        ("c0 03 5f d6", ["ARM64 (AArch64)", "ARM", "Little Endian", 0, True, True], r"ret"),
        (
            "fd 7b c1 a8",
            ["ARM64 (AArch64)", "ARM", "Little Endian", 0, True, True],
            r"ldp\s+x29,\s*x30",
        ),
        (
            "20 7c 02 9b",
            ["ARM64 (AArch64)", "ARM", "Little Endian", 0, True, True],
            r"mul\s+x0,\s*x1,\s*x2",
        ),
    ],
)
def test_disassemble_arm_official_vectors(
    machine_code: str, args: list[object], pattern: str
) -> None:
    assert re.search(pattern, str(bake(machine_code, [{"op": "Disassemble ARM", "args": args}])))


def test_disassemble_x86_common_function() -> None:
    result = bake(
        "55 48 89 e5 b8 01 00 00 00 5d c3",
        [{"op": "Disassemble x86", "args": ["64", "Full x86 architecture", 16, 0, True, True]}],
    )
    assert isinstance(result, str)
    assert "push rbp" in result
    assert "mov rbp, rsp" in result
    assert "mov eax, 0x1" in result
    assert result.endswith("ret\r\n")


def test_disassemble_x86_unsupported_compatibility() -> None:
    # Knights Corner is not supported by PyChef's x86 disassembler
    with pytest.raises(Exception, match="Unsupported Compatibility mode"):
        bake(
            "55 48 89 e5",
            [{"op": "Disassemble x86", "args": ["64", "Knights Corner", 16, 0, True, True]}],
        )


def test_yara_official_regex_output() -> None:
    rules = (
        "rule foo {strings: $re1 = /foo/ condition: $re1} "
        "rule bar {strings: $re1 = /bar/ condition: $re1}"
    )
    result = bake(
        "foobar foobar bar foo foobar",
        [{"op": "YARA Rules", "args": [rules, True, True, True, True]}],
    )
    assert isinstance(result, str)
    assert result.count('Rule "') == 2
    assert 'Pos 22, length 3, identifier $re1, data: "foo"' in result
    assert 'Rule "bar" matches (4 times):' in result


def test_yara_hash_module_conditions() -> None:
    rules = """
import "hash"
rule HelloWorldMD5 {
  condition: hash.md5(0,filesize) == "ed076287532e86365e841e92bfc50d8c"
}
rule HelloWorldSHA256 {
  condition:
    hash.sha256(0,filesize) ==
      "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
}
"""
    assert bake("Hello World!", [{"op": "YARA Rules", "args": [rules]}]) == (
        'Input matches rule "HelloWorldMD5".\nInput matches rule "HelloWorldSHA256".\n'
    )


def test_dependency_free_bitmap_ocr() -> None:
    blank = _png_encode(_Image(180, 35, [(255, 255, 255, 255)] * (180 * 35)))
    rendered = bake(
        blank,
        [
            {
                "op": "Add Text To Image",
                "args": ["HELLO", "None", "None", 2, 2, 28, "Sans-serif", 0, 0, 0, 255],
            }
        ],
    )
    assert (
        bake(rendered, [{"op": "Optical Character Recognition", "args": [False, "Tesseract only"]}])
        == "HELLO"
    )
    confident = bake(
        rendered, [{"op": "Optical Character Recognition", "args": [True, "Tesseract only"]}]
    )
    assert confident == "Confidence: 100%\n\nHELLO"


def test_ocr_unsupported_engine_mode() -> None:
    blank = _png_encode(_Image(180, 35, [(255, 255, 255, 255)] * (180 * 35)))
    # LSTM only is not supported by PyChef's dependency-free OCR
    with pytest.raises(Exception, match=r"OCR Engine Mode.*not supported"):
        bake(blank, [{"op": "Optical Character Recognition", "args": [False, "LSTM only"]}])
