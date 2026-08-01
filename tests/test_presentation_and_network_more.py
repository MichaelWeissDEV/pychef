"""Tests for rendering, charts, coordinates, HTTP, and DNS-over-HTTPS."""

from __future__ import annotations

import base64
import json
import socket
from collections.abc import Sequence
from typing import Any

import pytest

from pychef import registry
from pychef.operations import network


def run(name: str, value: str | bytes, args: Sequence[Any] | None = None) -> Any:
    return registry.get(name).run(value, args or [])


@pytest.mark.parametrize("name", ["Scatter chart", "Heatmap chart", "Hex Density chart"])
def test_point_chart_operations_emit_standalone_svg(name: str) -> None:
    svg = run(name, "x,y\n1,2\n2,4\n3,1")
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "<title>" in svg


def test_series_chart_uses_official_three_column_records() -> None:
    svg = run("Series chart", "alpha,one,1\nalpha,two,2\nbeta,one,3")
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "alpha" in svg and "beta" in svg
    assert svg.count("<circle") == 3


def test_chart_options_and_empty_data() -> None:
    scatter = run(
        "Scatter chart",
        "1;2;red\n2;3;blue",
        ["Line feed", "Semi-colon", False, "Time", "Value", "black", 3, True],
    )
    assert 'fill="red"' in scatter and 'r="3.00"' in scatter
    series = run(
        "Series chart",
        "a,one,2\na,two,3\nb,one,3\nb,two,4",
        ["Line feed", "Comma", "X axis", 2, "red, blue"],
    )
    assert series.count("<path") >= 3
    assert 'r="2.00"' in series
    assert run("Series chart", "", []).endswith("</svg>")


def test_chart_headers_option_indexes_and_validation() -> None:
    heatmap = run(
        "Heatmap chart",
        "Horizontal,Vertical\n1,2\n2,3",
        ["Line feed", "Comma", 4, 5, True, "ignored-x", "ignored-y", True, "white", "red"],
    )
    assert "Horizontal" in heatmap and "Vertical" in heatmap
    assert 'stroke="rgba(0,0,0,.5)"' in heatmap
    density = run(
        "Hex Density chart",
        "x,y\n1,2\n2,3",
        ["Line feed", "Comma", 20, 7, True, "", "", True, "white", "blue", False],
    )
    assert 'stroke="black"' in density and "x" in density and "y" in density
    with pytest.raises(ValueError, match="exactly 2"):
        run("Heatmap chart", "1,2,3", ["Line feed", "Comma", 2, 2, False])
    with pytest.raises(ValueError, match="base-10"):
        run("Scatter chart", "not-a-number,2", ["Line feed", "Comma", False])


def test_chart_user_controlled_text_is_html_escaped() -> None:
    svg = run(
        "Scatter chart",
        '1,2,"red\\" onload=\\"alert(1)"',
        ["Line feed", "Comma", False, "<x>", "<y>", "black", 1, True],
    )
    assert "<x>" not in svg and "&lt;x&gt;" in svg
    assert 'onload="alert' not in svg


def test_render_markdown_features_are_escaped() -> None:
    markdown = """# Heading
**bold** and *italic* and `code`
- item
[site](https://example.com)
```
<script>alert(1)</script>
```
"""
    rendered = run("Render Markdown", markdown, [True, True, True])
    assert "<h1>Heading</h1>" in rendered
    assert "<strong>bold</strong>" in rendered
    assert 'target="_blank" rel="noopener noreferrer"' in rendered
    assert "&lt;script&gt;" in rendered and "<script>" not in rendered
    assert "<pre><code>" in rendered


def test_pdf_rendering_raw_base64_empty_and_invalid() -> None:
    pdf = b"%PDF-1.4\n%%EOF"
    assert run("Render PDF", pdf, ["Raw"]) == pdf
    assert run("Render PDF", base64.b64encode(pdf).decode(), ["Base64"]) == pdf
    assert run("Render PDF", "", ["Raw"]) == b""
    with pytest.raises(ValueError):
        run("Render PDF", b"not pdf", ["Raw"])


@pytest.mark.parametrize("input_format", ["Raw", "Hex", "Base64"])
def test_play_media_input_formats(input_format: str) -> None:
    media = b"ID3\x04\0\0\0\0\0\0"
    values: dict[str, str | bytes] = {
        "Raw": media,
        "Hex": media.hex(),
        "Base64": base64.b64encode(media).decode(),
    }
    assert run("Play Media", values[input_format], [input_format]) == media
    with pytest.raises(ValueError):
        run("Play Media", b"not media", ["Raw"])


def test_syntax_highlighter_escapes_and_marks_tokens() -> None:
    rendered = run("Syntax highlighter", 'def f():\n return "<tag>" + 12', ["Python"])
    assert 'data-language="Python"' in rendered
    assert "&lt;tag&gt;" in rendered
    assert rendered.count('class="token"') >= 3


def test_coordinate_conversion_dd_dms_ddm_and_geohash() -> None:
    dms = run(
        "Convert co-ordinate format",
        "51.5074, -0.1278",
        ["Decimal Degrees", "Comma", "Degrees Minutes Seconds", "Comma", "After", 2],
    )
    assert dms == "51° 30' 26.64\" N,0° 7' 40.08\" W"
    dd = run(
        "Convert co-ordinate format",
        dms,
        ["Degrees Minutes Seconds", "Auto", "Decimal Degrees", "Comma", "None", 4],
    )
    assert dd == "51.5074,-0.1278"
    ddm = run(
        "Convert co-ordinate format",
        "N 51 30.444 W 0 7.668",
        ["Degrees Decimal Minutes", "Direction Preceding", "Decimal Degrees", "Space", "Before", 4],
    )
    assert ddm == "N 51.5074 W 0.1278"
    geohash = run(
        "Convert co-ordinate format",
        "51.5074,-0.1278",
        ["Decimal Degrees", "Comma", "Geohash", "Space", "None", 8],
    )
    assert geohash == "gcpvj0du"
    decoded = run(
        "Convert co-ordinate format",
        geohash,
        ["Geohash", "Auto", "Decimal Degrees", "Comma", "None", 3],
    )
    assert decoded.startswith("51.507,-0.128")
    assert run("Convert co-ordinate format", "   ") == "   "


def test_coordinate_validation_and_map() -> None:
    svg = run("Show on map", "48.137,11.575", [15, "Decimal Degrees", "Comma"])
    assert svg.startswith("<svg") and "48.137000, 11.575000" in svg
    with pytest.raises(ValueError):
        run("Convert co-ordinate format", "999,999", ["Decimal Degrees"])
    with pytest.raises(ValueError):
        run(
            "Convert co-ordinate format",
            "51,-1",
            ["Decimal Degrees", "Comma", "Universal Transverse Mercator"],
        )


def test_safe_public_url_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    assert network._safe_public_url("https://example.com/path") == "https://example.com/path"
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))],
    )
    with pytest.raises(ValueError):
        network._safe_public_url("http://localhost/")
    with pytest.raises(ValueError):
        network._safe_public_url("file:///tmp/test")


def test_http_request_body_metadata_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def fake_request(
        url: str, method: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, str, dict[str, str], bytes]:
        calls.append((url, method, headers, body))
        return 201, "Created", {"Content-Type": "text/plain"}, b"response"

    monkeypatch.setattr(network, "_request", fake_request)
    assert run("HTTP request", "ignored", ["GET", "https://example.com", "X-Test: yes"]) == (
        "response"
    )
    metadata = run(
        "HTTP request",
        "body",
        ["POST", "https://example.com", "Content-Type: text/plain", "CORS", True],
    )
    assert "Status: 201 Created" in metadata and "response" in metadata
    assert calls[-1][3] == b"body"
    assert run("HTTP request", "", ["GET", ""]) == ""
    with pytest.raises(ValueError):
        run("HTTP request", "", ["INVALID", "https://example.com"])
    with pytest.raises(ValueError):
        run("HTTP request", "", ["GET", "https://example.com", "Host: evil"])
    with pytest.raises(ValueError):
        run("HTTP request", "", ["GET", "https://example.com", "broken"])


def test_dns_over_https_full_and_answer_only(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        {"Status": 0, "Answer": [{"name": "example.com.", "type": 1, "data": "93.184.216.34"}]}
    ).encode()

    def fake_request(
        url: str, method: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, str, dict[str, str], bytes]:
        assert "name=example.com" in url and "type=A" in url
        assert headers == {"Accept": "application/dns-json"} and body is None
        return 200, "OK", {}, payload

    monkeypatch.setattr(network, "_request", fake_request)
    full = json.loads(run("DNS over HTTPS", "example.com", []))
    assert full["Status"] == 0
    answers = json.loads(
        run(
            "DNS over HTTPS",
            "example.com",
            ["https://dns.example/resolve?source=test", "A", True, True],
        )
    )
    assert answers == ["93.184.216.34"]
    with pytest.raises(ValueError):
        run("DNS over HTTPS", "bad domain !", [])


def test_dns_http_error_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network, "_request", lambda *args: (500, "Error", {}, b"{}"))
    with pytest.raises(ValueError):
        run("DNS over HTTPS", "example.com", [])
    monkeypatch.setattr(network, "_request", lambda *args: (200, "OK", {}, b"not-json"))
    with pytest.raises(ValueError):
        run("DNS over HTTPS", "example.com", [])
