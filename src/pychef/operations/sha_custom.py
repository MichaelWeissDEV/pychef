"""Dependency-free SHA-1 and SHA-2 implementations with configurable rounds."""

from __future__ import annotations

_K256 = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

_K512 = (
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)

_IV256 = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_IV224 = (
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
)
_IV512 = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)
_IV384 = (
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
)
_IV512_256 = (
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
)
_IV512_224 = (
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
)


def _rotate_left(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def _rotate_right(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value >> amount) | (value << (width - amount))) & mask


def _padding(data: bytes, block_size: int, length_size: int) -> bytes:
    bit_length = len(data) * 8
    zeros = (block_size - length_size - (len(data) + 1) % block_size) % block_size
    return data + b"\x80" + bytes(zeros) + bit_length.to_bytes(length_size, "big")


def sha1(data: bytes, rounds: int = 80) -> bytes:
    if not 16 <= rounds <= 80:
        raise ValueError("SHA-1 rounds must be between 16 and 80")
    mask = 0xFFFFFFFF
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = _padding(data, 64, 8)
    for offset in range(0, len(padded), 64):
        words = [
            int.from_bytes(padded[offset + index : offset + index + 4], "big")
            for index in range(0, 64, 4)
        ]
        for index in range(16, rounds):
            words.append(
                _rotate_left(
                    words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16],
                    1,
                    32,
                )
            )
        a, b, c, d, e = state
        for index in range(rounds):
            if index < 20:
                function, constant = (b & c) | (~b & d), 0x5A827999
            elif index < 40:
                function, constant = b ^ c ^ d, 0x6ED9EBA1
            elif index < 60:
                function, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                function, constant = b ^ c ^ d, 0xCA62C1D6
            temporary = (_rotate_left(a, 5, 32) + e + words[index] + constant + function) & mask
            a, b, c, d, e = temporary, a, _rotate_left(b, 30, 32), c, d
        state = [(value + work) & mask for value, work in zip(state, (a, b, c, d, e), strict=True)]
    return b"".join(value.to_bytes(4, "big") for value in state)


def sha256(data: bytes, bits: int = 256, rounds: int = 64) -> bytes:
    if bits not in {224, 256}:
        raise ValueError("SHA-256 core supports 224- or 256-bit output")
    if not 16 <= rounds <= 64:
        raise ValueError("SHA-256 rounds must be between 16 and 64")
    mask = 0xFFFFFFFF
    state = list(_IV224 if bits == 224 else _IV256)
    padded = _padding(data, 64, 8)
    for offset in range(0, len(padded), 64):
        words = [
            int.from_bytes(padded[offset + index : offset + index + 4], "big")
            for index in range(0, 64, 4)
        ]
        for index in range(16, rounds):
            first = (
                _rotate_right(words[index - 15], 7, 32)
                ^ _rotate_right(words[index - 15], 18, 32)
                ^ (words[index - 15] >> 3)
            )
            second = (
                _rotate_right(words[index - 2], 17, 32)
                ^ _rotate_right(words[index - 2], 19, 32)
                ^ (words[index - 2] >> 10)
            )
            words.append((words[index - 16] + first + words[index - 7] + second) & mask)
        a, b, c, d, e, f, g, h = state
        for index in range(rounds):
            first = _rotate_right(e, 6, 32) ^ _rotate_right(e, 11, 32) ^ _rotate_right(e, 25, 32)
            choice = (e & f) ^ (~e & g)
            temporary1 = (h + first + choice + _K256[index] + words[index]) & mask
            second = _rotate_right(a, 2, 32) ^ _rotate_right(a, 13, 32) ^ _rotate_right(a, 22, 32)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (second + majority) & mask
            a, b, c, d, e, f, g, h = (
                (temporary1 + temporary2) & mask,
                a,
                b,
                c,
                (d + temporary1) & mask,
                e,
                f,
                g,
            )
        state = [
            (value + work) & mask
            for value, work in zip(state, (a, b, c, d, e, f, g, h), strict=True)
        ]
    return b"".join(value.to_bytes(4, "big") for value in state)[: bits // 8]


def sha512(data: bytes, bits: int = 512, rounds: int = 160) -> bytes:
    ivs = {224: _IV512_224, 256: _IV512_256, 384: _IV384, 512: _IV512}
    if bits not in ivs:
        raise ValueError("SHA-512 core supports 224, 256, 384, or 512-bit output")
    if not 32 <= rounds <= 160:
        raise ValueError("SHA-512 rounds must be between 32 and 160")
    iterations = (rounds + 1) // 2
    mask = 0xFFFFFFFFFFFFFFFF
    state = list(ivs[bits])
    padded = _padding(data, 128, 16)
    for offset in range(0, len(padded), 128):
        words = [
            int.from_bytes(padded[offset + index : offset + index + 8], "big")
            for index in range(0, 128, 8)
        ]
        for index in range(16, iterations):
            first = (
                _rotate_right(words[index - 15], 1, 64)
                ^ _rotate_right(words[index - 15], 8, 64)
                ^ (words[index - 15] >> 7)
            )
            second = (
                _rotate_right(words[index - 2], 19, 64)
                ^ _rotate_right(words[index - 2], 61, 64)
                ^ (words[index - 2] >> 6)
            )
            words.append((words[index - 16] + first + words[index - 7] + second) & mask)
        a, b, c, d, e, f, g, h = state
        for index in range(iterations):
            first = _rotate_right(e, 14, 64) ^ _rotate_right(e, 18, 64) ^ _rotate_right(e, 41, 64)
            choice = (e & f) ^ (~e & g)
            temporary1 = (h + first + choice + _K512[index] + words[index]) & mask
            second = _rotate_right(a, 28, 64) ^ _rotate_right(a, 34, 64) ^ _rotate_right(a, 39, 64)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (second + majority) & mask
            a, b, c, d, e, f, g, h = (
                (temporary1 + temporary2) & mask,
                a,
                b,
                c,
                (d + temporary1) & mask,
                e,
                f,
                g,
            )
        state = [
            (value + work) & mask
            for value, work in zip(state, (a, b, c, d, e, f, g, h), strict=True)
        ]
    return b"".join(value.to_bytes(8, "big") for value in state)[: bits // 8]
