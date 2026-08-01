"""Parse the structured fields of a modular bcrypt hash string."""

from __future__ import annotations

import re

from ..registry import implementation
from ..types import Args, Data, to_text

_BCRYPT_RE = re.compile(r"^\$(2[abxy])\$(\d{2})\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$")


@implementation("Bcrypt parse", category="Hashing")
def bcrypt_parse(value: Data, args: Args) -> Data:
    del args
    text = to_text(value)
    match = _BCRYPT_RE.fullmatch(text)
    if match is None or not 4 <= int(match.group(2)) <= 31:
        raise ValueError("Error: Error: invalid hash provided")
    rounds = int(match.group(2))
    salt = text[:29]
    return f"Rounds: {rounds}\nSalt: {salt}\nPassword hash: {text[29:]}\nFull hash: {text}"
