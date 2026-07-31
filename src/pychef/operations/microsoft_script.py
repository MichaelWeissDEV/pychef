"""Decoder for Microsoft's legacy JScript.Encode and VBScript.Encode format."""

from __future__ import annotations

import re

from ..registry import operation
from ..types import Args, Data, to_text

_DECODE_TRIPLES = bytes.fromhex(
    "576e7b4a4c410b0b0b0c0c0c4a4c410e0e0e0f0f0f10101011111112121213"
    "13131414141515151616161717171818181919191a1a1a1b1b1b1c1c1c1d1d1d"
    "1e1e1e1f1f1f2e2d324775307a522156602942715b6a5e382f4933265c3d4962"
    "58417d3a3429353236655b2039767c5c727a56437f73386b6639634e703345452b"
    "6b6868627151594f667809765e62317d44644a23546d7543714a4c417e3a604a4c"
    "415e7e53404c407745424a2c27612a485d74722227754b37316f44374e794d3b59"
    "524c2f22506f5467266a2a72477d6a6474392d547b202b3f7f2d382e2c774c3067"
    "5d6e537e6b476c66346f357879255d742130436423264d5a76525b25636c243f48"
    "2b7b5528787023296941282e34734c0959212a3324447f4e3f6d507755093b5356"
    "557c73693a35615f6163654b50465867583b5131574969224f6c6d465a4d684825"
    "7c2728365c46703d4a6e24327a79412f373d5f605f4b514f5a20422c366557"
)
_COMBINATION = (
    0,
    1,
    2,
    0,
    1,
    2,
    1,
    2,
    2,
    1,
    2,
    1,
    0,
    2,
    1,
    2,
    0,
    2,
    1,
    2,
    0,
    0,
    1,
    2,
    2,
    1,
    0,
    2,
    1,
    2,
    2,
    1,
    0,
    0,
    2,
    1,
    2,
    1,
    2,
    0,
    2,
    0,
    0,
    1,
    2,
    0,
    2,
    1,
    0,
    2,
    1,
    2,
    0,
    0,
    1,
    2,
    2,
    0,
    0,
    1,
    2,
    0,
    2,
    1,
)
_SCRIPT_PATTERN = re.compile(r"#@~\^.{6}==(.+).{6}==\^#~@")


def _decode(data: str) -> str:
    data = (
        data.replace("@&", "\n")
        .replace("@#", "\r")
        .replace("@*", ">")
        .replace("@!", "<")
        .replace("@$", "@")
    )
    result = []
    index = -1
    for character in data:
        code = ord(character)
        if code < 128:
            index += 1
        if (code == 9 or 31 < code < 128) and code not in {60, 62, 64}:
            offset = 3 * (code - 9) + _COMBINATION[index % 64]
            character = chr(_DECODE_TRIPLES[offset])
        result.append(character)
    return "".join(result)


@operation("Microsoft Script Decoder", category="Default")
def microsoft_script_decoder(value: Data, _args: Args) -> Data:
    match = _SCRIPT_PATTERN.search(to_text(value))
    return _decode(match.group(1)) if match else ""
