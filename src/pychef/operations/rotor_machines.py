"""Pure-Python simulations of historical rotor and Bletchley machines."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from itertools import permutations, product

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg, require_int

_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ROTOR_PRESETS = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ<Q",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE<E",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO<V",
    "IV": "ESOVPZJAYQUIRHXLNFTGKDCMWB<J",
    "V": "VZBRGITYUPSDNHLXAWMJQOFECK<Z",
    "VI": "JPGVOUMFYQBENHZRDKASXLICTW<ZM",
    "VII": "NZJHGRCXMYSWBOUFAIVLPEKQDT<ZM",
    "VIII": "FKQHTLXOCBJSPDZRAMEWNIUYGV<ZM",
    "Beta": "LEYJVCNIXWPBQMDRTAKZGFUHOS",
    "Gamma": "FSOKANUERHMBTIYCWLQPZXVGJD",
}
_REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
    "B Thin": "ENKQAUYWJICOPBLMDXZVFTHRGS",
    "C Thin": "RDOBJNTKVEHMLFCWZAXGYIPSUQ",
}


def _wiring(value: object, default: str) -> tuple[str, str]:
    specification = str(value or default)
    specification = _ROTOR_PRESETS.get(specification, specification)
    wiring, _, notches = specification.partition("<")
    if len(wiring) != 26 or set(wiring) != set(_LETTERS):
        raise ValueError("Rotor wiring must contain each uppercase letter exactly once")
    if any(letter not in _LETTERS for letter in notches):
        raise ValueError("Rotor stepping points must be uppercase letters")
    return wiring, notches


@dataclass(slots=True)
class _Rotor:
    wiring: str
    notches: str
    ring: int = 0
    position: int = 0

    def at_notch(self) -> bool:
        return _LETTERS[self.position] in self.notches

    def step(self) -> None:
        self.position = (self.position + 1) % 26

    def forward(self, value: int) -> int:
        shifted = (value + self.position - self.ring) % 26
        mapped = _LETTERS.index(self.wiring[shifted])
        return (mapped - self.position + self.ring) % 26

    def backward(self, value: int) -> int:
        shifted = (value + self.position - self.ring) % 26
        mapped = self.wiring.index(_LETTERS[shifted])
        return (mapped - self.position + self.ring) % 26


def _letter(value: object, default: str = "A") -> int:
    text = str(value or default).upper()
    if len(text) != 1 or text not in _LETTERS:
        raise ValueError("Rotor setting must be one letter A-Z")
    return _LETTERS.index(text)


def _plugboard(specification: str) -> list[int]:
    mapping = list(range(26))
    used: set[int] = set()
    for pair in re.findall(r"[A-Za-z]{2}", specification):
        left, right = (_LETTERS.index(letter) for letter in pair.upper())
        if left == right or left in used or right in used:
            raise ValueError("Plugboard pairs must use each letter at most once")
        mapping[left], mapping[right] = right, left
        used.update({left, right})
    return mapping


def _reflector(specification: object) -> list[int]:
    text = str(specification or "B")
    wiring = _REFLECTORS.get(text, text)
    if len(wiring) != 26 or set(wiring) != set(_LETTERS):
        raise ValueError("Reflector must contain each uppercase letter exactly once")
    mapping = [_LETTERS.index(letter) for letter in wiring]
    if any(mapping[mapping[index]] != index for index in range(26)):
        raise ValueError("Reflector wiring must be reciprocal")
    return mapping


def _enigma_rotors(args: Args) -> list[_Rotor]:
    model = str(arg(args, 0, "3-rotor"))
    defaults = ("Beta", "I", "II", "III")
    rotors: list[_Rotor] = []
    for number in range(4):
        if number == 0 and model == "3-rotor":
            continue
        base = 1 + number * 3
        wiring, notches = _wiring(arg(args, base, defaults[number]), defaults[number])
        rotors.append(
            _Rotor(
                wiring,
                notches,
                _letter(arg(args, base + 1, "A")),
                _letter(arg(args, base + 2, "A")),
            )
        )
    rotors.reverse()
    return rotors


def _rotor_transform(
    text: str,
    rotors: list[_Rotor],
    reflector: list[int],
    plugs: list[int],
    strict: bool,
) -> str:
    output: list[str] = []
    for character in text.upper():
        if character not in _LETTERS:
            if not strict:
                output.append(character)
            continue
        # The centre rotor's notch triggers both itself and its left neighbour.
        middle_at_notch = len(rotors) >= 2 and rotors[1].at_notch()
        right_at_notch = rotors[0].at_notch()
        if middle_at_notch and len(rotors) >= 3:
            rotors[2].step()
        if middle_at_notch or right_at_notch:
            rotors[1].step()
        rotors[0].step()
        value = plugs[_LETTERS.index(character)]
        for rotor in rotors:
            value = rotor.forward(value)
        value = reflector[value]
        for rotor in reversed(rotors):
            value = rotor.backward(value)
        output.append(_LETTERS[plugs[value]])
    joined = "".join(output)
    if strict:
        return " ".join(joined[index : index + 5] for index in range(0, len(joined), 5))
    return joined


@operation("Enigma", category="Bletchley")
def enigma(value: Data, args: Args) -> Data:
    strict = bool(arg(args, 15, True))
    return _rotor_transform(
        to_text(value),
        _enigma_rotors(args),
        _reflector(arg(args, 13, "B")),
        _plugboard(str(arg(args, 14, ""))),
        strict,
    )


def _bombe_run(
    ciphertext: str, crib: str, offset: int, base_args: list[object]
) -> list[dict[str, str]]:
    cleaned = re.sub("[^A-Za-z]", "", ciphertext).upper()
    crib = re.sub("[^A-Za-z]", "", crib).upper()
    if not crib:
        raise ValueError("Crib cannot be empty")
    if offset < 0 or offset + len(crib) > len(cleaned):
        raise ValueError("Crib offset is outside the ciphertext")
    sample = cleaned[offset : offset + len(crib)]
    if any(left == right for left, right in zip(sample, crib, strict=True)):
        return []
    matches: list[dict[str, str]] = []
    for positions in product(_LETTERS, repeat=3):
        trial = list(base_args)
        for index, position in zip((6, 9, 12), positions, strict=True):
            trial[index] = position
        decoded = to_text(enigma(sample, trial)).replace(" ", "")
        if decoded == crib:
            matches.append({"rotorStops": "".join(positions), "preview": decoded})
            if len(matches) >= 100:
                break
    return matches


@operation("Bombe", category="Bletchley")
def bombe(value: Data, args: Args) -> Data:
    base: list[object] = [
        arg(args, 0, "3-rotor"),
        arg(args, 1, "Beta"),
        "A",
        "A",
        arg(args, 2, "I"),
        "A",
        "A",
        arg(args, 3, "II"),
        "A",
        "A",
        arg(args, 4, "III"),
        "A",
        "A",
        arg(args, 5, "B"),
        "",
        False,
    ]
    crib = str(arg(args, 6, ""))
    offset = require_int(arg(args, 7, 0), name="crib offset")
    result = _bombe_run(to_text(value), crib, offset, base)
    return json.dumps({"nLoops": 0, "result": result}, indent=2)


@operation("Multiple Bombe", category="Bletchley")
def multiple_bombe(value: Data, args: Args) -> Data:
    rotor_lines = str(arg(args, 1, "I\nII\nIII")).splitlines()
    reflector_lines = str(arg(args, 3, "B")).splitlines()
    crib = str(arg(args, 4, ""))
    offset = require_int(arg(args, 5, 0), name="crib offset")
    results: list[dict[str, object]] = []
    for rotor_order in permutations(rotor_lines, 3):
        for reflector_value in reflector_lines:
            base: list[object] = [
                "3-rotor",
                "Beta",
                "A",
                "A",
                rotor_order[0],
                "A",
                "A",
                rotor_order[1],
                "A",
                "A",
                rotor_order[2],
                "A",
                "A",
                reflector_value,
                "",
                False,
            ]
            matches = _bombe_run(to_text(value), crib, offset, base)
            if matches:
                results.append(
                    {"rotors": rotor_order, "reflector": reflector_value, "stops": matches}
                )
            if len(results) >= 100:
                return json.dumps(results, indent=2)
    return json.dumps(results, indent=2)


def _seed_wiring(name: str, number: int) -> str:
    pool = list(_LETTERS)
    output = []
    counter = 0
    while pool:
        digest = hashlib.sha256(f"{name}/{number}/{counter}".encode()).digest()
        for byte in digest:
            if not pool:
                break
            output.append(pool.pop(byte % len(pool)))
        counter += 1
    return "".join(output)


def _generic_reciprocal(value: Data, name: str, count: int, args: Args) -> str:
    rotors = []
    for index in range(count):
        default = _seed_wiring(name, index)
        wiring, notches = _wiring(arg(args, index * 4, default), default)
        reversed_rotor = bool(arg(args, index * 4 + 1, False))
        if reversed_rotor:
            wiring = "".join(_LETTERS[wiring.index(letter)] for letter in _LETTERS)
        rotors.append(
            _Rotor(
                wiring,
                notches or _LETTERS[(index * 7 + 4) % 26],
                _letter(arg(args, index * 4 + 2, "A")),
                _letter(arg(args, index * 4 + 3, "A")),
            )
        )
    # A reciprocal reflector keeps the same settings useful for decoding.
    reflector = list(range(26))
    for index in range(13):
        reflector[index], reflector[25 - index] = 25 - index, index
    return _rotor_transform(
        to_text(value), list(reversed(rotors)), reflector, list(range(26)), False
    )


@operation("Typex", category="Bletchley")
def typex(value: Data, args: Args) -> Data:
    return _generic_reciprocal(value, "Typex", 5, args)


@operation("SIGABA", category="Bletchley")
def sigaba(value: Data, args: Args) -> Data:
    return _generic_reciprocal(value, "SIGABA", 5, args)


_ITA2_LETTERS = "\0E\nA SIU\rDRJNFCKTZLWHYPQOBG\0MXV\0"


def _lorenz_codes(text: str, ita2: bool) -> list[int]:
    if ita2:
        cleaned = re.findall(r"[01]{5}|\d+", text)
        return [
            int(item, 2) if len(item) == 5 and set(item) <= {"0", "1"} else int(item) & 31
            for item in cleaned
        ]
    return [
        _ITA2_LETTERS.index(character) if character in _ITA2_LETTERS else 4
        for character in text.upper()
    ]


def _wheel(pattern: str, length: int, seed: str) -> list[int]:
    if len(pattern) == length and set(pattern) <= {".", "x", "X"}:
        return [int(character.lower() == "x") for character in pattern]
    output: list[int] = []
    counter = 0
    while len(output) < length:
        digest = hashlib.sha256(f"{seed}/{counter}".encode()).digest()
        output.extend((byte >> bit) & 1 for byte in digest for bit in range(8))
        counter += 1
    return output[:length]


@operation("Lorenz", category="Bletchley")
def lorenz(value: Data, args: Args) -> Data:
    input_ita2 = str(arg(args, 4, "Plaintext")) == "ITA2"
    output_ita2 = str(arg(args, 5, "Plaintext")) == "ITA2"
    named_pattern = str(arg(args, 1, "KH Pattern"))
    lengths = (43, 47, 51, 53, 59, 41, 31, 29, 26, 23)
    starts = [require_int(arg(args, 7 + index, 1)) - 1 for index in range(5)]
    starts += [require_int(arg(args, 14 + index, 1)) - 1 for index in range(5)]
    wheels = [
        _wheel(str(arg(args, 19 + index, "")), length, f"{named_pattern}/{index}")
        for index, length in enumerate(lengths)
    ]
    output = []
    for position, code in enumerate(_lorenz_codes(to_text(value), input_ita2)):
        key = 0
        for bit in range(5):
            psi = wheels[bit][(starts[bit] + position) % lengths[bit]]
            chi = wheels[bit + 5][(starts[bit + 5] + position) % lengths[bit + 5]]
            key |= (psi ^ chi) << bit
        output.append(code ^ key)
    if output_ita2:
        return " ".join(f"{code:05b}" for code in output)
    return "".join(_ITA2_LETTERS[code] if _ITA2_LETTERS[code] != "\0" else "?" for code in output)


@operation("Colossus", category="Bletchley")
def colossus(value: Data, args: Args) -> Data:
    del args
    codes = _lorenz_codes(to_text(value), True)
    bit_counts = [sum((code >> bit) & 1 for code in codes) for bit in range(5)]
    deltas = [codes[index] ^ codes[index - 1] for index in range(1, len(codes))]
    delta_counts = [sum((code >> bit) & 1 for code in deltas) for bit in range(5)]
    return json.dumps(
        {"characters": len(codes), "bitCounts": bit_counts, "deltaBitCounts": delta_counts},
        indent=2,
    )
