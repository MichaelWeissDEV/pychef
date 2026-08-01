"""Pure-Python RIPEMD-128/160/256/320 implementations."""

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF

_ZL = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13,
)
_ZR = (
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11,
)
_SL = (
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6,
)
_SR = (
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11,
)


def _rol(value: int, amount: int) -> int:
    value &= _MASK
    return ((value << amount) | (value >> (32 - amount))) & _MASK


def _f(index: int, x: int, y: int, z: int) -> int:
    if index < 16:
        return x ^ y ^ z
    if index < 32:
        return (x & y) | (~x & z)
    if index < 48:
        return (x | ~y) ^ z
    if index < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _left_term(index: int, x: int, y: int, z: int) -> int:
    constants = (0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    return (_f(index, x, y, z) + constants[index // 16]) & _MASK


def _right_term(index: int, x: int, y: int, z: int, rounds: int) -> int:
    if rounds == 64:
        functions = (3, 2, 1, 0)
        constants = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0)
    else:
        functions = (4, 3, 2, 1, 0)
        constants = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0)
    group = index // 16
    return (_f(functions[group] * 16, x, y, z) + constants[group]) & _MASK


def _compress_128(state: list[int], words: tuple[int, ...]) -> None:
    al, bl, cl, dl = state
    ar, br, cr, dr = state
    for index in range(64):
        temporary = _rol(al + words[_ZL[index]] + _left_term(index, bl, cl, dl), _SL[index])
        al, bl, cl, dl = dl, temporary, bl, cl
        temporary = _rol(ar + words[_ZR[index]] + _right_term(index, br, cr, dr, 64), _SR[index])
        ar, br, cr, dr = dr, temporary, br, cr
    temporary = (state[1] + cl + dr) & _MASK
    state[1] = (state[2] + dl + ar) & _MASK
    state[2] = (state[3] + al + br) & _MASK
    state[3] = (state[0] + bl + cr) & _MASK
    state[0] = temporary


def _compress_160(state: list[int], words: tuple[int, ...]) -> None:
    al, bl, cl, dl, el = state
    ar, br, cr, dr, er = state
    for index in range(80):
        temporary = _rol(al + words[_ZL[index]] + _left_term(index, bl, cl, dl), _SL[index])
        temporary = (temporary + el) & _MASK
        al, bl, cl, dl, el = el, temporary, bl, _rol(cl, 10), dl
        temporary = _rol(ar + words[_ZR[index]] + _right_term(index, br, cr, dr, 80), _SR[index])
        temporary = (temporary + er) & _MASK
        ar, br, cr, dr, er = er, temporary, br, _rol(cr, 10), dr
    temporary = (state[1] + cl + dr) & _MASK
    state[1] = (state[2] + dl + er) & _MASK
    state[2] = (state[3] + el + ar) & _MASK
    state[3] = (state[4] + al + br) & _MASK
    state[4] = (state[0] + bl + cr) & _MASK
    state[0] = temporary


def _compress_256(state: list[int], words: tuple[int, ...]) -> None:
    al, bl, cl, dl, ar, br, cr, dr = state
    for index in range(64):
        temporary = _rol(al + words[_ZL[index]] + _left_term(index, bl, cl, dl), _SL[index])
        al, bl, cl, dl = dl, temporary, bl, cl
        temporary = _rol(ar + words[_ZR[index]] + _right_term(index, br, cr, dr, 64), _SR[index])
        ar, br, cr, dr = dr, temporary, br, cr
        if index == 15:
            al, ar = ar, al
        elif index == 31:
            bl, br = br, bl
        elif index == 47:
            cl, cr = cr, cl
        elif index == 63:
            dl, dr = dr, dl
    values = (al, bl, cl, dl, ar, br, cr, dr)
    state[:] = [(left + right) & _MASK for left, right in zip(state, values, strict=True)]


def _compress_320(state: list[int], words: tuple[int, ...]) -> None:
    al, bl, cl, dl, el, ar, br, cr, dr, er = state
    for index in range(80):
        temporary = _rol(al + words[_ZL[index]] + _left_term(index, bl, cl, dl), _SL[index])
        temporary = (temporary + el) & _MASK
        al, bl, cl, dl, el = el, temporary, bl, _rol(cl, 10), dl
        temporary = _rol(ar + words[_ZR[index]] + _right_term(index, br, cr, dr, 80), _SR[index])
        temporary = (temporary + er) & _MASK
        ar, br, cr, dr, er = er, temporary, br, _rol(cr, 10), dr
        if index == 15:
            bl, br = br, bl
        elif index == 31:
            dl, dr = dr, dl
        elif index == 47:
            al, ar = ar, al
        elif index == 63:
            cl, cr = cr, cl
        elif index == 79:
            el, er = er, el
    values = (al, bl, cl, dl, el, ar, br, cr, dr, er)
    state[:] = [(left + right) & _MASK for left, right in zip(state, values, strict=True)]


def digest(data: bytes, bits: int = 160) -> bytes:
    """Return the RIPEMD digest for one of the four standardized sizes."""

    initial_states = {
        128: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
        160: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        256: [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0x76543210,
            0xFEDCBA98,
            0x89ABCDEF,
            0x01234567,
        ],
        320: [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
            0x76543210,
            0xFEDCBA98,
            0x89ABCDEF,
            0x01234567,
            0x3C2D1E0F,
        ],
    }
    if bits not in initial_states:
        raise ValueError("RIPEMD digest size must be 128, 160, 256, or 320")
    state = initial_states[bits].copy()
    padded = data + b"\x80"
    padded += b"\0" * ((56 - len(padded)) % 64)
    padded += struct.pack("<Q", (len(data) * 8) & 0xFFFFFFFFFFFFFFFF)
    compressors = {128: _compress_128, 160: _compress_160, 256: _compress_256, 320: _compress_320}
    compress = compressors[bits]
    for offset in range(0, len(padded), 64):
        compress(state, struct.unpack("<16I", padded[offset : offset + 64]))
    return struct.pack(f"<{len(state)}I", *state)
