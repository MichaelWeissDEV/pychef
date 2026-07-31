"""Pure-Python analysis operation tests."""

from __future__ import annotations

from pychef import bake


def test_detect_file_type_signatures_and_unknown() -> None:
    assert bake(b"\x89PNG\r\n\x1a\nrest", ["Detect File Type"]) == (
        "File type:   Portable Network Graphics\nExtension:   png\nMIME type:   image/png\n"
    )
    assert bake(b"%PDF-1.7", ["Detect File Type"]) == (
        "File type:   Portable Document Format\nExtension:   pdf\nMIME type:   application/pdf\n"
    )
    unknown = bake(b"plain text", ["Detect File Type"])
    assert isinstance(unknown, str)
    assert unknown.startswith("Unknown file type.")


def test_parse_user_agent_browser_vector() -> None:
    firefox = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
    result = bake(firefox, ["Parse User Agent"])
    assert isinstance(result, str)
    assert "Name: Firefox" in result
    assert "Version: 47.0" in result
    assert "Name: Windows" in result
    assert "Architecture: amd64" in result

    safari = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"
    )
    result = bake(safari, ["Parse User Agent"])
    assert isinstance(result, str)
    assert "Name: Safari" in result
