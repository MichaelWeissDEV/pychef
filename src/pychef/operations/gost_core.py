"""Pure-Python GOST 28147-89, Magma, and Kuznyechik primitives.

The byte ordering and mode behavior intentionally match the implementation
used by CyberChef.  The functions in this module do not depend on OpenSSL or
any third-party package.
"""

# ruff: noqa: E501 -- compact hexadecimal S-box constants are easier to audit intact.

from __future__ import annotations

from collections.abc import Callable

_SBOX_HEX = {
    "E-TEST": "04020f05090100080e030b0c0d070a060c090f0e0801030a0207040d06000b050d080e0c0703090a01050204060f000b0e090b02050f0701000d0c060a040308030e05090608000d0a0b070c02010f04080f060b01090c050d03070a000e0204090b0c000306070504080e0f010a020d0c0605020b00090d030e070a0f040108",
    "E-A": "09060302080b01070a040e0f0c000d0503070e09080a0f000502060c0b040d010e0406020b030d080c0f050a000701090e070a0c0d01030900020b040f0805060b050109080d0f000e0402030c070a06030a0d0c0102000b07050904080f0e06010d0209070a0600080c04050f030b0e0b0a0f05000c0e080602030901070d04",
    "E-B": "08040b0103050009020e0a0c0d06070f0001020a040d050c0907030f0b08060e0e0c000a09020d0b0705080f030601040705000d0b060102030a0c0f040e090802070c0f09050a0b0104000d06080e0308030206040d0e0b0c01070f0a00090505020a0b09010c0307040d00060f080e00040b0e080307010a0209060f0d050c",
    "E-C": "010b0c02090d000f0405080e0a0706030001070d0b040502080e0f0c090a06030802050004090f0a03070c0d060e010b03060001050d0a080b0209070e0f0c04080d0b000405010209030c0e060f0a070c090b01080e0204070306050a000f0d0a0906080d0e02000f03050b04010c07070400050a020f0e0c06010b0d090308",
    "E-D": "0f0c020a0604050007090e0d010b08030b0603040c0f0e02070d0800050a0901010c0b000f0e06050a0d04080903070201050e0c0a07000d06020b0409030f08000c08090d020a0b07030605040e0f0108000f0302050e0b010a04070c090d060300060f010e09020d080c040b0a0507010a06080f0b00040c030509070d020e",
    "E-SC": "0306010005070d09040b080c0e0f020a07010502080b090c0d00030a0f0e04060f0104060c0809020e03070a0b0d050003040f0c05090e000608070a010b0d02060900070b08040c020e0a0f010d05030601020f000b090c070d0a0508040e0300020e0c09010407030f06080a0d0b0505020b08040c07010a060e0009030d0f",
    "E-Z": "0c0406020a050b090e080d0700030f0106080203090a050c010e04070b0d000f0b030508020f0a0d0e0107040c0906000c0802010d040f0607000a05030e090b070f050a0801060d0009030e0b04020c050d0f0609020c0a0b07080104030e00080e02050609010c0f040b000d0a030701070e0d00050803040f0a06090c0b02",
    "D-TEST": "040a09020d08000e060b010c070f05030e0b040c060d0f0a02030801000705090508010d0a0304020e0f0c070600090b070d0a010008090f0e04060c0b020503060c0701050f0d08040a090e00030b02040b0a000702010d03060805090c0f0e0d0b0401030f0509000a0e070608020c010f0d0005070a040902030e060b080c",
    "D-A": "0a040506080103070d0c0e0009020b0f050f0400020d0b09010706030c0e0a08070f0c0e09040100030b0502060a080d040a070c000f02080e0106050d0b09030706040b090c020a0108000e0f0d0305070602040d090f000a01050b080e0c030d0e04010700050a030c080f0602090b01030a09050b040f0806070e0d00020c",
    "D-SC": "0b0d07000504010f090e060a030c0802010207090d0b0f080e0c040005060a0305010d030f060c0709080b02040e000a0d010b04090c0e000705080f06020a03020d0a0f090b0307080c050e060001040004060c0503080d0a0b0f020109070e01030c080a060b00020e07090f04050d0a0b0600010304070e0d050f0802090c",
}
SBOXES = {name: bytes.fromhex(value) for name, value in _SBOX_HEX.items()}

_PI = bytes(
    [
        252,
        238,
        221,
        17,
        207,
        110,
        49,
        22,
        251,
        196,
        250,
        218,
        35,
        197,
        4,
        77,
        233,
        119,
        240,
        219,
        147,
        46,
        153,
        186,
        23,
        54,
        241,
        187,
        20,
        205,
        95,
        193,
        249,
        24,
        101,
        90,
        226,
        92,
        239,
        33,
        129,
        28,
        60,
        66,
        139,
        1,
        142,
        79,
        5,
        132,
        2,
        174,
        227,
        106,
        143,
        160,
        6,
        11,
        237,
        152,
        127,
        212,
        211,
        31,
        235,
        52,
        44,
        81,
        234,
        200,
        72,
        171,
        242,
        42,
        104,
        162,
        253,
        58,
        206,
        204,
        181,
        112,
        14,
        86,
        8,
        12,
        118,
        18,
        191,
        114,
        19,
        71,
        156,
        183,
        93,
        135,
        21,
        161,
        150,
        41,
        16,
        123,
        154,
        199,
        243,
        145,
        120,
        111,
        157,
        158,
        178,
        177,
        50,
        117,
        25,
        61,
        255,
        53,
        138,
        126,
        109,
        84,
        198,
        128,
        195,
        189,
        13,
        87,
        223,
        245,
        36,
        169,
        62,
        168,
        67,
        201,
        215,
        121,
        214,
        246,
        124,
        34,
        185,
        3,
        224,
        15,
        236,
        222,
        122,
        148,
        176,
        188,
        220,
        232,
        40,
        80,
        78,
        51,
        10,
        74,
        167,
        151,
        96,
        115,
        30,
        0,
        98,
        68,
        26,
        184,
        56,
        130,
        100,
        159,
        38,
        65,
        173,
        69,
        70,
        146,
        39,
        94,
        85,
        47,
        140,
        163,
        165,
        125,
        105,
        213,
        149,
        59,
        7,
        88,
        179,
        64,
        134,
        172,
        29,
        247,
        48,
        55,
        107,
        228,
        136,
        217,
        231,
        137,
        225,
        27,
        131,
        73,
        76,
        63,
        248,
        254,
        141,
        83,
        170,
        144,
        202,
        216,
        133,
        97,
        32,
        113,
        103,
        164,
        45,
        43,
        9,
        91,
        203,
        155,
        37,
        208,
        190,
        229,
        108,
        82,
        89,
        166,
        116,
        210,
        230,
        244,
        180,
        192,
        209,
        102,
        175,
        194,
        57,
        75,
        99,
        182,
    ]
)
_REVERSE_PI = bytes(sorted(range(256), key=_PI.__getitem__))
_L_COEFFICIENTS = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
_MESHING_CONSTANT = bytes.fromhex(
    "6900722264c904238d3adb9646e92ac418feac9400ed0712c086dcc2ef4ca92b"
)


def _normalize_key(key: bytes) -> bytes:
    """Reproduce the typed-array zero fill used by the upstream library."""
    return key[:32].ljust(32, b"\0")


def _rotl32(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def _round(left: int, right: int, key: int, sbox: bytes) -> tuple[int, int]:
    mixed = (left + key) & 0xFFFFFFFF
    substituted = 0
    for index in range(8):
        substituted |= sbox[index * 16 + ((mixed >> (index * 4)) & 15)] << (index * 4)
    return _rotl32(substituted, 11) ^ right, left


def _schedule_64(key: bytes, decrypt: bool, *, magma: bool) -> tuple[int, ...]:
    key = _normalize_key(key)
    byteorder = "big" if magma else "little"
    words = tuple(int.from_bytes(key[index : index + 4], byteorder) for index in range(0, 32, 4))
    return words + tuple(reversed(words)) * 3 if decrypt else words * 3 + tuple(reversed(words))


def gost89_block(block: bytes, key: bytes, sbox: str = "E-A", decrypt: bool = False) -> bytes:
    if len(block) != 8:
        raise ValueError("GOST 28147 requires an 8-byte block")
    try:
        table = SBOXES[sbox.upper()]
    except KeyError as exc:
        raise ValueError(f"Unknown GOST S-box: {sbox}") from exc
    left = int.from_bytes(block[:4], "little")
    right = int.from_bytes(block[4:], "little")
    for round_key in _schedule_64(key, decrypt, magma=False):
        left, right = _round(left, right, round_key, table)
    return right.to_bytes(4, "little") + left.to_bytes(4, "little")


def magma_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if len(block) != 8:
        raise ValueError("Magma requires an 8-byte block")
    left = int.from_bytes(block[4:], "big")
    right = int.from_bytes(block[:4], "big")
    for round_key in _schedule_64(key, decrypt, magma=True):
        left, right = _round(left, right, round_key, SBOXES["E-Z"])
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        carry = left & 0x80
        left = (left << 1) & 0xFF
        if carry:
            left ^= 0xC3
        right >>= 1
    return result


def _r(data: bytearray) -> None:
    total = 0
    for coefficient, value in zip(_L_COEFFICIENTS, data, strict=True):
        total ^= _gf_multiply(coefficient, value)
    data[1:] = data[:-1]
    data[0] = total


def _reverse_r(data: bytearray) -> None:
    first = data[0]
    data[:-1] = data[1:]
    data[-1] = first
    total = 0
    for coefficient, value in zip(_L_COEFFICIENTS, data, strict=True):
        total ^= _gf_multiply(coefficient, value)
    data[-1] = total


def _l(data: bytearray) -> None:
    for _ in range(16):
        _r(data)


def _reverse_l(data: bytearray) -> None:
    for _ in range(16):
        _reverse_r(data)


def _lsx(data: bytearray, key: bytes | bytearray) -> None:
    for index, value in enumerate(key):
        data[index] = _PI[data[index] ^ value]
    _l(data)


def _reverse_lsx(data: bytearray, key: bytes) -> None:
    for index, value in enumerate(key):
        data[index] ^= value
    _reverse_l(data)
    for index, value in enumerate(data):
        data[index] = _REVERSE_PI[value]


def _kuznyechik_keys(key: bytes) -> tuple[bytes, ...]:
    normalized = _normalize_key(key)
    first = bytearray(normalized[:16])
    second = bytearray(normalized[16:])
    keys = [bytes(first), bytes(second)]
    for iteration in range(1, 33):
        constant = bytearray(16)
        constant[15] = iteration
        _l(constant)
        old_first = bytes(first)
        _lsx(first, constant)
        for index, value in enumerate(second):
            first[index] ^= value
        second[:] = old_first
        if iteration % 8 == 0:
            keys.extend((bytes(first), bytes(second)))
    return tuple(keys)


def kuznyechik_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if len(block) != 16:
        raise ValueError("Kuznyechik requires a 16-byte block")
    keys = _kuznyechik_keys(key)
    state = bytearray(block)
    if decrypt:
        for index in range(9, 0, -1):
            _reverse_lsx(state, keys[index])
        for index, value in enumerate(keys[0]):
            state[index] ^= value
    else:
        for index in range(9):
            _lsx(state, keys[index])
        for index, value in enumerate(keys[9]):
            state[index] ^= value
    return bytes(state)


def cipher_parameters(version: str, sbox: str = "E-A") -> tuple[int, Callable[..., bytes]]:
    if "Kuznyechik" in version:
        return 16, kuznyechik_block
    if "Magma" in version:
        return 8, magma_block

    def process(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
        return gost89_block(block, key, sbox, decrypt)

    return 8, process


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _pad(data: bytes, block_size: int, padding: str) -> bytes:
    # crypto-gost-js checks for "PKCS5P", while CyberChef passes "PKCS5".
    # Preserve that public behavior: PKCS5 therefore falls through to zero padding.
    if padding == "BIT":
        amount = block_size - len(data) % block_size
        return data + b"\x01" + b"\0" * (amount - 1)
    if padding == "RANDOM":
        # Deterministic random padding would be misleading; the bytes are never removed.
        import secrets

        amount = (-len(data)) % block_size
        return data + secrets.token_bytes(amount)
    amount = (-len(data)) % block_size
    return data + b"\0" * amount


def _unpad(data: bytes, padding: str) -> bytes:
    if padding != "BIT":
        return data
    index = len(data)
    while index > 1 and data[index - 1] == 0:
        index -= 1
    if not index or data[index - 1] != 1:
        raise ValueError("Invalid GOST bit padding")
    return data[: index - 1]


def _mesh_key(
    key: bytes,
    state: bytearray,
    processed_blocks: int,
    block_size: int,
    process: Callable[..., bytes],
    decrypt: bool,
) -> bytes:
    if processed_blocks * block_size % 1024:
        return key
    new_key = b"".join(
        process(_MESHING_CONSTANT[index : index + block_size], key, True)
        for index in range(0, 32, block_size)
    )
    for index in range(0, len(state), block_size):
        state[index : index + block_size] = process(
            bytes(state[index : index + block_size]), new_key, False
        )
    del decrypt  # key schedules are created per block in this Python implementation
    return new_key


def crypt(
    data: bytes,
    key: bytes,
    iv: bytes,
    *,
    version: str,
    sbox: str = "E-A",
    mode: str = "ECB",
    key_meshing: str = "NO",
    padding: str = "ZERO",
    decrypt: bool = False,
) -> bytes:
    """Encrypt or decrypt with the CyberChef GOST cipher options."""
    block_size, process = cipher_parameters(version, sbox)
    mode = mode.upper()
    padding = padding.upper()
    stream_mode = mode in {"CFB", "OFB", "CTR"}
    if mode not in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        raise ValueError(f"Unknown GOST block mode: {mode}")
    if not iv:
        iv = b"\0" * block_size
    if version.startswith("GOST 28147") and len(iv) != 8:
        raise ValueError("GOST 28147 IV must contain 8 bytes")
    if mode == "CTR" and block_size == 16:
        if len(iv) != 8:
            raise ValueError("Kuznyechik CTR IV must contain 8 bytes")
    elif len(iv) % block_size:
        raise ValueError(f"GOST IV length must be a multiple of {block_size} bytes")
    if not decrypt and not stream_mode:
        data = _pad(data, block_size, padding)
    if not stream_mode and len(data) % block_size:
        raise ValueError(f"GOST input must contain complete {block_size}-byte blocks")

    normalized_key = _normalize_key(key)
    state = bytearray(iv if mode != "CTR" or block_size != 16 else iv + b"\0" * 8)
    result = bytearray()
    if mode == "CTR" and block_size == 8:
        state[:] = process(bytes(state), normalized_key, False)

    for block_index, offset in enumerate(range(0, len(data), block_size), 1):
        block = data[offset : offset + block_size]
        if mode == "ECB":
            output = process(block, normalized_key, decrypt)
        elif mode == "CBC":
            if decrypt:
                previous = bytes(state[:block_size])
                output = _xor(process(block, normalized_key, True), previous)
                state[:] = state[block_size:] + block
            else:
                output = process(_xor(block, bytes(state[:block_size])), normalized_key, False)
                state[:] = state[block_size:] + output
        elif mode == "CFB":
            source = bytes(state)
            gamma = process(bytes(state[:block_size]), normalized_key, False)
            output = _xor(block, gamma[: len(block)])
            feedback = block if decrypt else output
            state[:] = source[len(block) :] + feedback
        elif mode == "OFB":
            source = bytes(state)
            gamma = process(bytes(state[:block_size]), normalized_key, False)
            output = _xor(block, gamma[: len(block)])
            state[:] = source[block_size:] + gamma
        else:
            if block_size == 8:
                low = (int.from_bytes(state[:4], "little") + 0x01010101) & 0xFFFFFFFF
                high_sum = int.from_bytes(state[4:], "little") + 0x01010104
                high = high_sum if high_sum < 0x100000000 else high_sum - 0xFFFFFFFF
                state[:] = low.to_bytes(4, "little") + high.to_bytes(4, "little")
            gamma = process(bytes(state), normalized_key, False)
            output = _xor(block, gamma[: len(block)])
            if block_size == 16:
                counter = (int.from_bytes(state, "big") + 1) & ((1 << 128) - 1)
                state[:] = counter.to_bytes(16, "big")
        result.extend(output)
        if key_meshing.upper() == "CP" and block_index * block_size % 1024 == 0:
            normalized_key = _mesh_key(
                normalized_key, state, block_index, block_size, process, decrypt
            )
    return _unpad(bytes(result), padding) if decrypt and not stream_mode else bytes(result)


def mac(
    data: bytes,
    key: bytes,
    iv: bytes,
    *,
    version: str,
    sbox: str = "E-A",
    bits: int = 32,
) -> bytes:
    """Calculate the GOST imitation insert / CMAC used by CyberChef."""
    if bits < 1:
        raise ValueError("GOST MAC length must be positive")
    block_size, process = cipher_parameters(version, sbox)
    if not iv:
        iv = b"\0" * block_size
    if len(iv) != block_size:
        raise ValueError(f"GOST MAC IV must contain {block_size} bytes")
    key = _normalize_key(key)
    state = bytearray(iv)
    if version.startswith("GOST 28147"):
        padded = data + b"\0" * ((-len(data)) % block_size)
        schedule = _schedule_64(key, False, magma=False)
        table = SBOXES[sbox.upper()]
        for offset in range(0, len(padded), block_size):
            state[:] = _xor(bytes(state), padded[offset : offset + block_size])
            left = int.from_bytes(state[:4], "little")
            right = int.from_bytes(state[4:], "little")
            for round_key in schedule[:16]:
                left, right = _round(left, right, round_key, table)
            state[:] = left.to_bytes(4, "little") + right.to_bytes(4, "little")
    else:
        subkey = bytearray(process(b"\0" * block_size, key, False))

        def double(value: bytearray) -> None:
            carry = 0
            for index in range(len(value) - 1, -1, -1):
                next_carry = value[index] >> 7
                value[index] = ((value[index] << 1) & 0xFF) | carry
                carry = next_carry
            if carry:
                value[-1] ^= 0x87 if len(value) == 16 else 0x1B

        double(subkey)
        if len(data) % block_size:
            data = data + b"\x01" + b"\0" * (block_size - len(data) % block_size - 1)
            double(subkey)
        for offset in range(0, len(data), block_size):
            state[:] = _xor(bytes(state), data[offset : offset + block_size])
            if offset + block_size == len(data):
                state[:] = _xor(bytes(state), bytes(subkey))
            state[:] = process(bytes(state), key, False)
    return bytes(state[: (bits + 7) // 8])


_GOST94_C2 = bytes.fromhex("00ff00ff00ff00ffff00ff00ff00ff0000ffff00ff0000ffff000000ffff00ff")


def _gost94_a(data: bytearray) -> None:
    mixed = bytes(data[index] ^ data[index + 8] for index in range(8))
    data[:] = data[8:] + mixed


def _gost94_p(data: bytes | bytearray) -> bytes:
    result = bytearray(32)
    for index in range(8):
        result[index * 4 : index * 4 + 4] = bytes(
            (data[index], data[8 + index], data[16 + index], data[24 + index])
        )
    return bytes(result)


def _gost94_fw(data: bytearray) -> None:
    words = [int.from_bytes(data[index : index + 2], "little") for index in range(0, 32, 2)]
    last = words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[12] ^ words[15]
    words = [*words[1:], last]
    data[:] = b"".join(word.to_bytes(2, "little") for word in words)


def _gost94_process(block: bytes, state: bytearray, sbox: str) -> None:
    source = bytearray(block)
    left = bytearray(state)
    right = bytearray(source)
    encrypted = bytearray(32)
    constants = (bytes(32), bytes(32), _GOST94_C2, bytes(32))
    for index in range(4):
        if index:
            _gost94_a(left)
            for position, value in enumerate(constants[index]):
                left[position] ^= value
            _gost94_a(right)
            _gost94_a(right)
        key = _gost94_p(bytes(a ^ b for a, b in zip(left, right, strict=True)))
        encrypted[index * 8 : index * 8 + 8] = gost89_block(
            bytes(state[index * 8 : index * 8 + 8]), key, sbox
        )
    for _ in range(12):
        _gost94_fw(encrypted)
    for index, value in enumerate(source):
        encrypted[index] ^= value
    _gost94_fw(encrypted)
    for index, value in enumerate(state):
        encrypted[index] ^= value
    for _ in range(61):
        _gost94_fw(encrypted)
    state[:] = encrypted


def gost94(data: bytes, sbox: str = "D-A") -> bytes:
    """Return a GOST R 34.11-94 digest."""
    if sbox.upper() not in SBOXES:
        raise ValueError(f"Unknown GOST S-box: {sbox}")
    state = bytearray(32)
    checksum = bytearray(32)

    def add_checksum(block: bytes) -> None:
        carry = 0
        for index, value in enumerate(block):
            total = checksum[index] + value + carry
            checksum[index] = total & 0xFF
            carry = total >> 8

    full_blocks, remainder = divmod(len(data), 32)
    for index in range(full_blocks):
        block = data[index * 32 : index * 32 + 32]
        add_checksum(block)
        _gost94_process(block, state, sbox.upper())
    if remainder:
        block = data[full_blocks * 32 :].ljust(32, b"\0")
        add_checksum(block)
        _gost94_process(block, state, sbox.upper())
    length = (len(data) * 8).to_bytes(32, "little")
    _gost94_process(length, state, sbox.upper())
    _gost94_process(bytes(checksum), state, sbox.upper())
    return bytes(state)


def _diversify_key(key: bytes, ukm: bytes, version: str, sbox: str, block_size: int) -> bytes:
    # Keep the original typed-array length here.  The upstream diversification
    # routine encrypts the key object itself, so a short key remains short while
    # missing 32-bit words read as zero during scheduling.
    current = key
    for byte in ukm[:block_size]:
        padded = _normalize_key(current)
        words = [int.from_bytes(padded[index : index + 4], "little") for index in range(0, 32, 4)]
        available_words = len(current) // 4
        sums = [0, 0]
        for index, word in enumerate(words):
            target = 0 if byte & (1 << index) else 1
            # Adding JS ``undefined`` produces NaN, which a subsequent bitwise
            # conversion stores as zero in the Int32Array.
            sums[target] = (sums[target] + word) & 0xFFFFFFFF if index < available_words else 0
        first, second = sums
        sync = first.to_bytes(4, "little") + second.to_bytes(4, "little")
        current = crypt(
            current,
            current,
            sync,
            version=version,
            sbox=sbox,
            mode="CFB",
            padding="NO",
        )
    return current


def wrap_key(
    content_key: bytes,
    wrapping_key: bytes,
    ukm: bytes,
    *,
    version: str,
    sbox: str,
    method: str,
) -> bytes:
    block_size, _ = cipher_parameters(version, sbox)
    if len(ukm) != block_size:
        raise ValueError(f"GOST UKM must contain {block_size} bytes")
    if method.upper() == "SC":
        key = _unpack_sc_key(wrapping_key, version, sbox, block_size)
        encrypted = crypt(
            content_key, key, b"", version=version, sbox=sbox, mode="ECB", padding="ZERO"
        )
        checksum = mac(content_key, key, b"", version=version, sbox=sbox, bits=block_size * 4)
        result = bytearray(32 + block_size // 2)
        result[: len(encrypted)] = encrypted
        result[32:] = checksum
        return bytes(result)
    key = (
        _diversify_key(wrapping_key, ukm, version, sbox, block_size)
        if method.upper() == "CP"
        else _normalize_key(wrapping_key)
    )
    checksum = mac(content_key, key, ukm, version=version, sbox=sbox, bits=block_size * 4)
    encrypted = crypt(content_key, key, b"", version=version, sbox=sbox, mode="ECB", padding="ZERO")
    result = bytearray(32 + block_size // 2)
    result[: len(encrypted)] = encrypted
    result[32:] = checksum
    return bytes(result)


def unwrap_key(
    wrapped_key: bytes,
    wrapping_key: bytes,
    ukm: bytes,
    *,
    version: str,
    sbox: str,
    method: str,
) -> bytes:
    block_size, _ = cipher_parameters(version, sbox)
    expected_size = 32 + block_size // 2
    if len(wrapped_key) != expected_size:
        raise ValueError(f"GOST wrapped key must contain {expected_size} bytes")
    if len(ukm) != block_size:
        raise ValueError(f"GOST UKM must contain {block_size} bytes")
    if method.upper() == "SC":
        key = _unpack_sc_key(wrapping_key, version, sbox, block_size)
        encrypted, checksum = wrapped_key[:32], wrapped_key[32:]
        content = crypt(
            encrypted,
            key,
            b"",
            version=version,
            sbox=sbox,
            mode="ECB",
            padding="ZERO",
            decrypt=True,
        )
        expected = mac(content, key, b"", version=version, sbox=sbox, bits=block_size * 4)
        if expected != checksum:
            raise ValueError("Invalid SignalCom wrapped-key MAC")
        return content
    key = (
        _diversify_key(wrapping_key, ukm, version, sbox, block_size)
        if method.upper() == "CP"
        else _normalize_key(wrapping_key)
    )
    encrypted, checksum = wrapped_key[:32], wrapped_key[32:]
    content = crypt(
        encrypted,
        key,
        b"",
        version=version,
        sbox=sbox,
        mode="ECB",
        padding="ZERO",
        decrypt=True,
    )
    expected = mac(content, key, ukm, version=version, sbox=sbox, bits=block_size * 4)
    if expected != checksum:
        raise ValueError("GOST wrapped-key authentication failed")
    return content


def _unpack_sc_key(key: bytes, version: str, sbox: str, block_size: int) -> bytes:
    if len(key) == 32:
        return key
    mac_size = block_size // 2
    if len(key) < mac_size + 34 or key[0] != 0x22:
        raise ValueError("Invalid SignalCom packed wrapping key")
    mask_count = key[1]
    expected_size = 2 + mac_size + mask_count * 32
    if mask_count < 1 or len(key) != expected_size:
        raise ValueError("Invalid SignalCom packed wrapping-key length")
    checksum = key[2 : 2 + mac_size]
    combined = bytearray(32)
    for offset in range(2 + mac_size, len(key), 32):
        for index, value in enumerate(key[offset : offset + 32]):
            combined[index] ^= value
    candidate_sboxes = [sbox]
    if version.startswith("GOST 28147"):
        candidate_sboxes.extend(
            name for name in ("E-A", "E-B", "E-C", "E-D", "E-SC") if name != sbox
        )
    for candidate in candidate_sboxes:
        actual = mac(
            bytes(32),
            bytes(combined),
            b"",
            version=version,
            sbox=candidate,
            bits=block_size * 4,
        )
        if actual == checksum:
            return bytes(combined)
    raise ValueError("Invalid SignalCom main-key MAC")
