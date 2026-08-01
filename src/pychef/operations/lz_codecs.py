"""Dependency-free LZ4 frames, LZString, and LZNT1 decompression."""

from __future__ import annotations

from collections.abc import Sequence

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg

_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


class _BitWriter:
    def __init__(self, bits_per_character: int) -> None:
        self.bits_per_character = bits_per_character
        self.value = 0
        self.position = 0
        self.output: list[int] = []

    def write(self, value: int, bit_count: int) -> None:
        for _index in range(bit_count):
            self.value = (self.value << 1) | (value & 1)
            if self.position == self.bits_per_character - 1:
                self.output.append(self.value)
                self.value = 0
                self.position = 0
            else:
                self.position += 1
            value >>= 1

    def finish(self) -> list[int]:
        while True:
            self.value <<= 1
            if self.position == self.bits_per_character - 1:
                self.output.append(self.value)
                return self.output
            self.position += 1


class _BitReader:
    def __init__(self, values: Sequence[int], reset_value: int) -> None:
        self.values = values
        self.reset_value = reset_value
        self.value = values[0] if values else 0
        self.position = reset_value
        self.index = 1

    def read(self, bit_count: int) -> int:
        bits = 0
        power = 1
        for _index in range(bit_count):
            bit = self.value & self.position
            self.position >>= 1
            if not self.position:
                self.position = self.reset_value
                self.value = self.values[self.index] if self.index < len(self.values) else 0
                self.index += 1
            if bit:
                bits |= power
            power <<= 1
        return bits


def _utf16_units(text: str) -> str:
    encoded = text.encode("utf-16-be", "surrogatepass")
    return "".join(
        chr(int.from_bytes(encoded[index : index + 2], "big"))
        for index in range(0, len(encoded), 2)
    )


def _from_utf16_units(text: str) -> str:
    encoded = b"".join(ord(character).to_bytes(2, "big") for character in text)
    return encoded.decode("utf-16-be", "surrogatepass")


def _lzstring_compress(text: str, bits_per_character: int) -> list[int]:
    text = _utf16_units(text)
    dictionary: dict[str, int] = {}
    pending: set[str] = set()
    dictionary_size = 3
    number_of_bits = 2
    enlarge_in = 2
    writer = _BitWriter(bits_per_character)

    def grow() -> None:
        nonlocal enlarge_in, number_of_bits
        if not enlarge_in:
            enlarge_in = 1 << number_of_bits
            number_of_bits += 1

    def emit(word: str) -> None:
        nonlocal enlarge_in
        if word in pending:
            codepoint = ord(word[0])
            writer.write(0 if codepoint < 256 else 1, number_of_bits)
            writer.write(codepoint, 8 if codepoint < 256 else 16)
            enlarge_in -= 1
            grow()
            pending.remove(word)
        else:
            writer.write(dictionary[word], number_of_bits)
        enlarge_in -= 1
        grow()

    word = ""
    for character in text:
        if character not in dictionary:
            dictionary[character] = dictionary_size
            dictionary_size += 1
            pending.add(character)
        combined = word + character
        if combined in dictionary:
            word = combined
            continue
        emit(word)
        dictionary[combined] = dictionary_size
        dictionary_size += 1
        word = character
    if word:
        emit(word)
    writer.write(2, number_of_bits)
    return writer.finish()


def _lzstring_decompress(values: Sequence[int], reset_value: int) -> str:
    if not values:
        return ""
    reader = _BitReader(values, reset_value)
    first_code = reader.read(2)
    if first_code == 0:
        first = chr(reader.read(8))
    elif first_code == 1:
        first = chr(reader.read(16))
    elif first_code == 2:
        return ""
    else:
        raise ValueError("invalid LZString stream")

    dictionary: dict[int, str] = {3: first}
    dictionary_size = 4
    number_of_bits = 3
    enlarge_in = 4
    word = first
    result = [first]
    while True:
        if reader.index > len(values):
            raise ValueError("truncated LZString stream")
        code = reader.read(number_of_bits)
        if code in {0, 1}:
            character = chr(reader.read(8 if code == 0 else 16))
            dictionary[dictionary_size] = character
            code = dictionary_size
            dictionary_size += 1
            enlarge_in -= 1
        elif code == 2:
            return _from_utf16_units("".join(result))
        if not enlarge_in:
            enlarge_in = 1 << number_of_bits
            number_of_bits += 1
        if code in dictionary:
            entry = dictionary[code]
        elif code == dictionary_size:
            entry = word + word[0]
        else:
            raise ValueError("invalid LZString dictionary reference")
        result.append(entry)
        dictionary[dictionary_size] = word + entry[0]
        dictionary_size += 1
        enlarge_in -= 1
        word = entry
        if not enlarge_in:
            enlarge_in = 1 << number_of_bits
            number_of_bits += 1


@implementation("LZString Compress", category="Compression")
def lzstring_compress(value: Data, args: Args) -> str:
    output_format = str(arg(args, 0, "default"))
    text = to_text(value)
    if output_format == "Base64":
        result = "".join(_BASE64_ALPHABET[code] for code in _lzstring_compress(text, 6))
        return result + "=" * ((4 - len(result) % 4) % 4)
    if output_format == "UTF16":
        return "".join(chr(code + 32) for code in _lzstring_compress(text, 15)) + " "
    if output_format == "default":
        return "".join(chr(code) for code in _lzstring_compress(text, 16))
    raise ValueError(f"unknown LZString format: {output_format}")


@implementation("LZString Decompress", category="Compression")
def lzstring_decompress(value: Data, args: Args) -> str:
    input_format = str(arg(args, 0, "default"))
    text = to_text(value)
    if not text:
        return ""
    if input_format == "Base64":
        values = [_BASE64_ALPHABET.index(character) for character in text]
        return _lzstring_decompress(values, 32)
    if input_format == "UTF16":
        return _lzstring_decompress([ord(character) - 32 for character in text], 16384)
    if input_format == "default":
        return _lzstring_decompress([ord(character) for character in text], 32768)
    raise ValueError(f"unknown LZString format: {input_format}")


def _lz4_block_decompress(data: bytes) -> bytes:
    output = bytearray()
    position = 0

    def extended_length(initial: int) -> int:
        nonlocal position
        length = initial
        if initial == 15:
            while True:
                if position >= len(data):
                    raise ValueError("truncated LZ4 length")
                extra = data[position]
                position += 1
                length += extra
                if extra != 255:
                    break
        return length

    while position < len(data):
        token = data[position]
        position += 1
        literal_length = extended_length(token >> 4)
        if position + literal_length > len(data):
            raise ValueError("truncated LZ4 literals")
        output.extend(data[position : position + literal_length])
        position += literal_length
        if position == len(data):
            break
        if position + 2 > len(data):
            raise ValueError("truncated LZ4 match offset")
        offset = int.from_bytes(data[position : position + 2], "little")
        position += 2
        if not offset or offset > len(output):
            raise ValueError("invalid LZ4 match offset")
        match_length = extended_length(token & 0x0F) + 4
        for _index in range(match_length):
            output.append(output[-offset])
    return bytes(output)


@implementation("LZ4 Compress", category="Compression")
def lz4_compress(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    output = bytearray(b"\x04\x22\x4d\x18\x40\x70\xdf")
    block_limit = 4 * 1024 * 1024
    for position in range(0, len(data), block_limit):
        block = data[position : position + block_limit]
        output.extend((len(block) | 0x80000000).to_bytes(4, "little"))
        output.extend(block)
    output.extend(b"\0\0\0\0")
    return bytes(output)


@implementation("LZ4 Decompress", category="Compression")
def lz4_decompress(value: Data, _args: Args) -> bytes:
    data = to_bytes(value)
    if len(data) < 7 or data[:4] != b"\x04\x22\x4d\x18":
        raise ValueError("invalid LZ4 frame")
    flags = data[4]
    position = 6
    if flags & 0x08:
        position += 8
    if flags & 0x01:
        position += 4
    position += 1
    if position > len(data):
        raise ValueError("truncated LZ4 frame header")
    output = bytearray()
    while True:
        if position + 4 > len(data):
            raise ValueError("truncated LZ4 block header")
        block_header = int.from_bytes(data[position : position + 4], "little")
        position += 4
        if not block_header:
            break
        uncompressed = bool(block_header & 0x80000000)
        block_length = block_header & 0x7FFFFFFF
        if position + block_length > len(data):
            raise ValueError("truncated LZ4 block")
        block = data[position : position + block_length]
        position += block_length
        output.extend(block if uncompressed else _lz4_block_decompress(block))
        if flags & 0x10:
            position += 4
    if flags & 0x04 and position + 4 > len(data):
        raise ValueError("truncated LZ4 content checksum")
    return bytes(output)


@implementation("LZNT1 Decompress", category="Compression")
def lznt1_decompress(value: Data, _args: Args) -> bytes:
    compressed = to_bytes(value)
    output = bytearray()
    position = 0
    while position + 2 <= len(compressed):
        output_start = len(output)
        header = int.from_bytes(compressed[position : position + 2], "little")
        position += 2
        size = header & 0xFFF
        block_end = position + size + 1
        if not size:
            break
        if block_end > len(compressed):
            raise ValueError("truncated LZNT1 block")
        if header & 0x8000:
            while position < block_end:
                flags = compressed[position]
                position += 1
                for _index in range(8):
                    if position >= block_end:
                        break
                    if not flags & 1:
                        output.append(compressed[position])
                        position += 1
                    else:
                        if position + 2 > block_end:
                            raise ValueError("truncated LZNT1 pointer")
                        pointer = int.from_bytes(compressed[position : position + 2], "little")
                        position += 2
                        displacement = 0
                        offset = len(output) - output_start - 1
                        while offset >= 0x10:
                            offset >>= 1
                            displacement += 1
                        symbol_offset = (pointer >> (12 - displacement)) + 1
                        symbol_length = (pointer & (0xFFF >> displacement)) + 3
                        source = len(output) - symbol_offset
                        if source < output_start:
                            raise ValueError("invalid LZNT1 back-reference")
                        for delta in range(symbol_length):
                            output.append(output[source + delta])
                    flags >>= 1
        else:
            output.extend(compressed[position:block_end])
            position = block_end
    return bytes(output)
