"""CyberChef ELF Info compatibility vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake

_ELF32_LE = bytes.fromhex(
    "7f454c460101010000000000000000000200030001000000502106083400000054000000000000003400200001002800"
    "030000000600000034000000348004083480040800010000000100000500000004000000000000000300000000000000"
    "00000000cc0000001c0000000000000000000000000000000000000009000000020000000000000000000000e6000000"
    "100000000000000000000000000000001000000011000000030000000000000000000000f50000000400000000000000"
    "0000000000000000000000002e73687374726162002e73796d746162002e737472746162000000000000000000000000"
    "000000000074657374"
)


def test_elf_info_official_32_bit_little_endian_vector() -> None:
    result = bake(_ELF32_LE, ["ELF Info"])
    assert isinstance(result, str)
    assert result.startswith(
        "============================== ELF Header ==============================\n"
        "Magic:                        \x7fELF\n"
        "Format:                       32-bit\n"
        "Endianness:                   Little"
    )
    assert "Program Header Type:          Program Header Table" in result
    assert "Section Name:                 .shstrab" in result
    assert result.endswith("Symbol Name:                  test")


def test_elf_info_rejects_invalid_input() -> None:
    with pytest.raises(OperationError, match="Invalid ELF"):
        bake(b"\x7f\0\0\0", ["ELF Info"])
