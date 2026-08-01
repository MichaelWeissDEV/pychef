"""Python ports of CyberChef's GenerateAllChecksums formatting/filter tests."""

from __future__ import annotations

from pychef import bake


def _run(length: str = "All", include_names: bool = True) -> str:
    result = bake(
        "123456789",
        [{"op": "Generate all checksums", "args": [length, include_names]}],
    )
    assert isinstance(result, str)
    return result


def test_generate_all_checksums_has_every_official_entry_in_order() -> None:
    lines = _run().splitlines()
    assert len(lines) == 176
    assert lines[:5] == [
        "CRC-3/GSM:                4",
        "CRC-3/ROHC:               6",
        "CRC-4/G-704:              7",
        "CRC-4/INTERLAKEN:         b",
        "CRC-4/ITU:                7",
    ]
    assert "Fletcher-8:               0c" in lines
    assert "Fletcher-16:              1ede" in lines
    assert "Adler-32:                 091e01de" in lines
    assert "Fletcher-32:              df09d509" in lines
    assert "Fletcher-64:              0d0803376c6a689f" in lines
    assert lines[-1] == "CRC-82/DARC:              09ea83f625023801fd612"


def test_generate_all_checksums_without_names_preserves_values_and_order() -> None:
    named = _run().splitlines()
    unnamed = _run(include_names=False).splitlines()
    assert len(unnamed) == len(named) == 176
    assert unnamed == [line.split()[-1] for line in named]


def test_generate_all_checksums_official_small_width_filters() -> None:
    assert (
        _run("3")
        == """CRC-3/GSM:                4
CRC-3/ROHC:               6
"""
    )
    assert (
        _run("4")
        == """CRC-4/G-704:              7
CRC-4/INTERLAKEN:         b
CRC-4/ITU:                7
"""
    )
    assert (
        _run("8")
        == """CRC-8:                    f4
CRC-8/8H2F:               df
CRC-8/AES:                97
CRC-8/AUTOSAR:            df
CRC-8/BLUETOOTH:          26
CRC-8/CDMA2000:           da
CRC-8/DARC:               15
CRC-8/DVB-S2:             bc
CRC-8/EBU:                97
CRC-8/GSM-A:              37
CRC-8/GSM-B:              94
CRC-8/HITAG:              b4
CRC-8/I-432-1:            a1
CRC-8/I-CODE:             7e
CRC-8/ITU:                a1
CRC-8/LTE:                ea
CRC-8/MAXIM:              a1
CRC-8/MAXIM-DOW:          a1
CRC-8/MIFARE-MAD:         99
CRC-8/NRSC-5:             f7
CRC-8/OPENSAFETY:         3e
CRC-8/ROHC:               d0
CRC-8/SAE-J1850:          4b
CRC-8/SAE-J1850-ZERO:     37
CRC-8/SMBUS:              f4
CRC-8/TECH-3250:          97
CRC-8/WCDMA:              25
Fletcher-8:               0c
"""
    )


def test_generate_all_checksums_high_width_filter() -> None:
    assert _run("82") == "CRC-82/DARC:              09ea83f625023801fd612\n"
