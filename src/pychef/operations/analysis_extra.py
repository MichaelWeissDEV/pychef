"""Dependency-free file signature and user-agent analysis."""

from __future__ import annotations

import re

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text

_FILE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "Portable Network Graphics", "png", "image/png"),
    (b"\xff\xd8\xff", "JPEG image", "jpg, jpeg", "image/jpeg"),
    (b"GIF87a", "Graphics Interchange Format", "gif", "image/gif"),
    (b"GIF89a", "Graphics Interchange Format", "gif", "image/gif"),
    (b"%PDF-", "Portable Document Format", "pdf", "application/pdf"),
    (b"PK\x03\x04", "ZIP archive", "zip, docx, xlsx, pptx", "application/zip"),
    (b"\x1f\x8b", "Gzip archive", "gz", "application/gzip"),
    (b"BZh", "Bzip2 archive", "bz2", "application/x-bzip2"),
    (b"\x7fELF", "Executable and Linkable Format", "elf", "application/x-elf"),
    (b"MZ", "DOS/Windows executable", "exe, dll", "application/vnd.microsoft.portable-executable"),
    (b"SQLite format 3\0", "SQLite database", "sqlite, db", "application/vnd.sqlite3"),
)


@implementation("Detect File Type", category="Analysis")
def detect_file_type(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    matches = [entry for entry in _FILE_SIGNATURES if data.startswith(entry[0])]
    if not matches:
        return (
            "Unknown file type. Have you tried checking the entropy of this data to determine "
            "whether it might be encrypted or compressed?"
        )
    return "\n".join(
        f"File type:   {name}\nExtension:   {extension}\nMIME type:   {mime}\n"
        for _signature, name, extension, mime in matches
    )


def _first(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else "unknown"


@implementation("Parse User Agent", category="Analysis")
def parse_user_agent(value: Data, _args: Args) -> str:
    text = to_text(value).removeprefix("User-Agent:").strip()
    browser_name = "unknown"
    browser_version = "unknown"
    for name, pattern in (
        ("Edge", r"(?:Edg|Edge)/([\d.]+)"),
        ("Chrome", r"(?:Chrome|CriOS)/([\d.]+)"),
        ("Firefox", r"(?:Firefox|FxiOS)/([\d.]+)"),
        ("Safari", r"Version/([\d.]+).*Safari/"),
    ):
        if match := re.search(pattern, text):
            browser_name, browser_version = name, match.group(1)
            break
    os_name, os_version = "unknown", "unknown"
    if "Windows NT" in text:
        os_name, os_version = "Windows", _first(r"Windows NT ([\d.]+)", text)
    elif "Android" in text:
        os_name, os_version = "Android", _first(r"Android ([\d.]+)", text)
    elif re.search(r"(?:iPhone|CPU) OS", text):
        os_name, os_version = "iOS", _first(r"(?:iPhone|CPU) OS ([\d_]+)", text).replace("_", ".")
    elif "Mac OS X" in text:
        os_name, os_version = "Mac OS", _first(r"Mac OS X ([\d_]+)", text).replace("_", ".")
    elif "Linux" in text:
        os_name = "Linux"
    if browser_name in {"Chrome", "Edge"}:
        engine = "Blink"
    elif browser_name == "Firefox":
        engine = "Gecko"
    elif browser_name == "Safari":
        engine = "WebKit"
    else:
        engine = "unknown"
    if re.search(r"x86_64|Win64|x64|amd64", text, re.I):
        architecture = "amd64"
    elif re.search(r"aarch64|arm64", text, re.I):
        architecture = "arm64"
    else:
        architecture = "unknown"
    return (
        f"Browser\n    Name: {browser_name}\n    Version: {browser_version}"
        "\nDevice\n    Model: unknown\n    Type: unknown\n    Vendor: unknown"
        f"\nEngine\n    Name: {engine}\n    Version: unknown"
        f"\nOS\n    Name: {os_name}\n    Version: {os_version}"
        f"\nCPU\n    Architecture: {architecture}"
    )
