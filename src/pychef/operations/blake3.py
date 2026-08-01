"""Pure-Python BLAKE3 hashing, keyed hashing, and extendable output."""

from __future__ import annotations

from dataclasses import dataclass

from ..registry import implementation
from ..types import Args, Data, to_bytes
from ._utils import arg, require_int

_MASK32 = 0xFFFFFFFF
_BLOCK_LEN = 64
_CHUNK_LEN = 1024
_CHUNK_START = 1
_CHUNK_END = 2
_PARENT = 4
_ROOT = 8
_KEYED_HASH = 16
_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_MESSAGE_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _mix(state: list[int], a: int, b: int, c: int, d: int, first: int, second: int) -> None:
    state[a] = (state[a] + state[b] + first) & _MASK32
    state[d] = _rotate_right(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotate_right(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + second) & _MASK32
    state[d] = _rotate_right(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotate_right(state[b] ^ state[c], 7)


def _round(state: list[int], message: tuple[int, ...]) -> None:
    _mix(state, 0, 4, 8, 12, message[0], message[1])
    _mix(state, 1, 5, 9, 13, message[2], message[3])
    _mix(state, 2, 6, 10, 14, message[4], message[5])
    _mix(state, 3, 7, 11, 15, message[6], message[7])
    _mix(state, 0, 5, 10, 15, message[8], message[9])
    _mix(state, 1, 6, 11, 12, message[10], message[11])
    _mix(state, 2, 7, 8, 13, message[12], message[13])
    _mix(state, 3, 4, 9, 14, message[14], message[15])


def _compress(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_length: int,
    flags: int,
) -> tuple[int, ...]:
    state = (
        list(chaining_value)
        + list(_IV[:4])
        + [
            counter & _MASK32,
            (counter >> 32) & _MASK32,
            block_length,
            flags,
        ]
    )
    message = block_words
    for round_number in range(7):
        _round(state, message)
        if round_number != 6:
            message = tuple(message[index] for index in _MESSAGE_PERMUTATION)
    return tuple(
        [state[index] ^ state[index + 8] for index in range(8)]
        + [state[index + 8] ^ chaining_value[index] for index in range(8)]
    )


def _words(block: bytes) -> tuple[int, ...]:
    padded = block.ljust(_BLOCK_LEN, b"\0")
    return tuple(
        int.from_bytes(padded[position : position + 4], "little")
        for position in range(0, _BLOCK_LEN, 4)
    )


@dataclass(frozen=True, slots=True)
class _Output:
    input_chaining_value: tuple[int, ...]
    block_words: tuple[int, ...]
    counter: int
    block_length: int
    flags: int

    def chaining_value(self) -> tuple[int, ...]:
        return _compress(
            self.input_chaining_value,
            self.block_words,
            self.counter,
            self.block_length,
            self.flags,
        )[:8]

    def root_bytes(self, length: int) -> bytes:
        result = bytearray()
        output_block_counter = 0
        while len(result) < length:
            words = _compress(
                self.input_chaining_value,
                self.block_words,
                output_block_counter,
                self.block_length,
                self.flags | _ROOT,
            )
            result.extend(b"".join(word.to_bytes(4, "little") for word in words))
            output_block_counter += 1
        return bytes(result[:length])


def _chunk_output(
    chunk: bytes,
    chunk_counter: int,
    key_words: tuple[int, ...],
    flags: int,
) -> _Output:
    chaining_value = key_words
    block_count = max(1, (len(chunk) + _BLOCK_LEN - 1) // _BLOCK_LEN)
    for block_index in range(block_count - 1):
        block = chunk[block_index * _BLOCK_LEN : (block_index + 1) * _BLOCK_LEN]
        block_flags = flags | (_CHUNK_START if block_index == 0 else 0)
        chaining_value = _compress(
            chaining_value,
            _words(block),
            chunk_counter,
            _BLOCK_LEN,
            block_flags,
        )[:8]
    final_block = chunk[(block_count - 1) * _BLOCK_LEN :]
    final_flags = flags | _CHUNK_END | (_CHUNK_START if block_count == 1 else 0)
    return _Output(
        chaining_value, _words(final_block), chunk_counter, len(final_block), final_flags
    )


def _parent_output(
    left: _Output,
    right: _Output,
    key_words: tuple[int, ...],
    flags: int,
) -> _Output:
    return _Output(
        key_words,
        left.chaining_value() + right.chaining_value(),
        0,
        _BLOCK_LEN,
        flags | _PARENT,
    )


def _hash(data: bytes, length: int, key: bytes | None = None) -> bytes:
    key_words = (
        _IV
        if key is None
        else tuple(
            int.from_bytes(key[position : position + 4], "little") for position in range(0, 32, 4)
        )
    )
    flags = 0 if key is None else _KEYED_HASH
    chunks = [
        data[position : position + _CHUNK_LEN] for position in range(0, len(data), _CHUNK_LEN)
    ]
    if not chunks:
        chunks = [b""]
    outputs = [
        _chunk_output(chunk, chunk_counter, key_words, flags)
        for chunk_counter, chunk in enumerate(chunks)
    ]
    while len(outputs) > 1:
        outputs = [
            _parent_output(outputs[index], outputs[index + 1], key_words, flags)
            if index + 1 < len(outputs)
            else outputs[index]
            for index in range(0, len(outputs), 2)
        ]
    return outputs[0].root_bytes(length)


@implementation("BLAKE3", category="Hashing")
def blake3(value: Data, args: Args) -> Data:
    length = require_int(arg(args, 0, 16), name="size")
    if not 1 <= length <= 65535:
        raise ValueError("size must be between 1 and 65535 bytes")
    key_text = str(arg(args, 1, ""))
    key = key_text.encode() if key_text else None
    if key is not None and len(key) != 32:
        raise ValueError("The key must be exactly 32 bytes long")
    return _hash(to_bytes(value), length, key).hex()
