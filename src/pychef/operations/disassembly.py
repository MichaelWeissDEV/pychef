"""Small dependency-free ARM/AArch64 and x86 machine-code disassemblers."""

from __future__ import annotations

import re

from ..registry import implementation
from ..types import Args, Data, to_text
from ._utils import arg, require_int


def _machine_bytes(value: Data) -> bytes:
    text = re.sub(r"\s", "", to_text(value))
    if not re.fullmatch(r"[0-9a-fA-F]*", text):
        raise ValueError("Invalid hexadecimal input. Please provide valid hex characters only.")
    if len(text) % 2:
        raise ValueError("Invalid hexadecimal input. Length must be even.")
    return bytes.fromhex(text)


def _register_list(mask: int, *, extra: str = "") -> str:
    names = [
        "fp"
        if index == 11
        else "ip"
        if index == 12
        else "sp"
        if index == 13
        else "lr"
        if index == 14
        else "pc"
        if index == 15
        else f"r{index}"
        for index in range(16)
        if mask & (1 << index)
    ]
    if extra:
        names.append(extra)
    return "{" + ", ".join(names) + "}"


def _arm32(word: int, address: int) -> str:
    if word & 0x0FFFFFF0 == 0x012FFF10:
        register = word & 15
        return f"bx {'lr' if register == 14 else f'r{register}'}"
    if word & 0x0FFF0000 == 0x092D0000:
        return f"push {_register_list(word & 0xFFFF)}"
    if word & 0x0FFF0000 == 0x08BD0000:
        return f"pop {_register_list(word & 0xFFFF)}"
    if word & 0x0FC000F0 == 0x00000090:
        rd, rs, rm = (word >> 16) & 15, (word >> 8) & 15, word & 15
        return f"mul r{rd}, r{rm}, r{rs}"
    if word & 0x0E000000 == 0x0A000000:
        displacement = word & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 1 << 24
        target = address + 8 + displacement * 4
        return f"{'bl' if word & 0x01000000 else 'b'} #0x{target:x}"
    if word & 0x0C000000 == 0x04000000:
        load = bool(word & (1 << 20))
        rn, rd = (word >> 16) & 15, (word >> 12) & 15
        base = "sp" if rn == 13 else f"r{rn}"
        destination = "sp" if rd == 13 else f"r{rd}"
        offset = word & 0xFFF
        suffix = "" if not offset else f", #{'' if word & (1 << 23) else '-'}0x{offset:x}"
        return f"{'ldr' if load else 'str'} {destination}, [{base}{suffix}]"
    if word & 0x0C000000 == 0:
        opcode = (word >> 21) & 15
        immediate = bool(word & (1 << 25))
        rn, rd = (word >> 16) & 15, (word >> 12) & 15
        names = {0: "and", 1: "eor", 2: "sub", 4: "add", 10: "cmp", 12: "orr", 13: "mov"}
        name = names.get(opcode)
        if name:
            if immediate:
                rotate = ((word >> 8) & 15) * 2
                raw = word & 0xFF
                operand = ((raw >> rotate) | (raw << (32 - rotate))) & 0xFFFFFFFF if rotate else raw
                source = f"#0x{operand:x}" if operand > 9 else f"#{operand}"
            else:
                rm = word & 15
                source = "sp" if rm == 13 else "lr" if rm == 14 else f"r{rm}"
            rd_name = "fp" if rd == 11 else "sp" if rd == 13 else f"r{rd}"
            rn_name = "fp" if rn == 11 else "sp" if rn == 13 else f"r{rn}"
            if name == "mov":
                return f"mov {rd_name}, {source}"
            if name == "cmp":
                return f"cmp {rn_name}, {source}"
            return f"{name} {rd_name}, {rn_name}, {source}"
    return f".word 0x{word:08x}"


def _thumb(halfword: int, address: int) -> str:
    if halfword & 0xFF87 == 0x4700:
        register = (halfword >> 3) & 15
        return f"bx {'lr' if register == 14 else f'r{register}'}"
    if halfword & 0xFC00 == 0x4400 and halfword & 0x0300 == 0x0200:
        destination = (halfword & 7) | ((halfword >> 4) & 8)
        source = (halfword >> 3) & 15
        return f"mov r{destination}, r{source}"
    if halfword & 0xFE00 == 0xB400:
        extra = "lr" if halfword & 0x100 else ""
        return f"push {_register_list(halfword & 0xFF, extra=extra)}"
    if halfword & 0xFE00 == 0xBC00:
        extra = "pc" if halfword & 0x100 else ""
        return f"pop {_register_list(halfword & 0xFF, extra=extra)}"
    if halfword & 0xF800 == 0x2000:
        return f"mov r{(halfword >> 8) & 7}, #{halfword & 0xFF}"
    if halfword & 0xF800 == 0xE000:
        displacement = halfword & 0x7FF
        if displacement & 0x400:
            displacement -= 0x800
        return f"b #0x{address + 4 + displacement * 2:x}"
    if halfword == 0xBF00:
        return "nop"
    return f".hword 0x{halfword:04x}"


def _xreg(index: int, *, wide: bool = True, stack: bool = False) -> str:
    if index == 31:
        return "sp" if stack else ("xzr" if wide else "wzr")
    return f"{'x' if wide else 'w'}{index}"


def _arm64(word: int, address: int) -> str:
    if word & 0xFFFFFC1F == 0xD65F0000:
        register = (word >> 5) & 31
        return "ret" if register == 30 else f"ret x{register}"
    if word & 0x7F800000 == 0x52800000:
        wide = bool(word >> 31)
        immediate = ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
        return f"mov {_xreg(word & 31, wide=wide)}, #{immediate}"
    if word & 0x7F000000 in {0x11000000, 0x51000000}:
        wide = bool(word >> 31)
        subtract = bool(word & 0x40000000)
        immediate = (word >> 10) & 0xFFF
        if word & (1 << 22):
            immediate <<= 12
        rd, rn = word & 31, (word >> 5) & 31
        if not subtract and immediate == 0:
            return f"mov {_xreg(rd, wide=wide, stack=True)}, {_xreg(rn, wide=wide, stack=True)}"
        operation_name = "sub" if subtract else "add"
        destination = _xreg(rd, wide=wide, stack=True)
        source = _xreg(rn, wide=wide, stack=True)
        return f"{operation_name} {destination}, {source}, #0x{immediate:x}"
    if word & 0x7F200000 in {0x0B000000, 0x4B000000}:
        wide = bool(word >> 31)
        subtract = bool(word & 0x40000000)
        rm, rn, rd = (word >> 16) & 31, (word >> 5) & 31, word & 31
        operation_name = "sub" if subtract else "add"
        return (
            f"{operation_name} {_xreg(rd, wide=wide)}, {_xreg(rn, wide=wide)}, "
            f"{_xreg(rm, wide=wide)}"
        )
    if word & 0xFFE0FC00 == 0x9B007C00:
        rm, rn, rd = (word >> 16) & 31, (word >> 5) & 31, word & 31
        return f"mul x{rd}, x{rn}, x{rm}"
    if word & 0x7E000000 == 0x34000000:
        nonzero = bool(word & 0x01000000)
        wide = bool(word >> 31)
        displacement = (word >> 5) & 0x7FFFF
        if displacement & 0x40000:
            displacement -= 0x80000
        operation_name = "cbnz" if nonzero else "cbz"
        target = address + displacement * 4
        return f"{operation_name} {_xreg(word & 31, wide=wide)}, #0x{target:x}"
    if word & 0x7C000000 == 0x14000000:
        displacement = word & 0x3FFFFFF
        if displacement & 0x2000000:
            displacement -= 0x4000000
        return f"{'bl' if word & 0x80000000 else 'b'} #0x{address + displacement * 4:x}"
    if word & 0xFFC00000 in {0xF9000000, 0xF9400000, 0xB9000000, 0xB9400000}:
        load = bool(word & 0x00400000)
        wide = bool(word >> 30 & 1)
        rt, rn = word & 31, (word >> 5) & 31
        offset = ((word >> 10) & 0xFFF) * (8 if wide else 4)
        suffix = "" if not offset else f", #0x{offset:x}"
        return (
            f"{'ldr' if load else 'str'} {_xreg(rt, wide=wide)}, [{_xreg(rn, stack=True)}{suffix}]"
        )
    if word & 0x3A000000 == 0x28000000:
        load = bool(word & (1 << 22))
        wide = bool(word >> 31)
        rt, rt2, rn = word & 31, (word >> 10) & 31, (word >> 5) & 31
        displacement = (word >> 15) & 0x7F
        if displacement & 0x40:
            displacement -= 0x80
        displacement *= 8 if wide else 4
        mode = (word >> 23) & 3
        base = _xreg(rn, stack=True)
        if mode == 3:
            memory = f"[{base}, #{displacement}]!"
        elif mode == 1:
            memory = f"[{base}], #{displacement}"
        else:
            memory = f"[{base}{'' if displacement == 0 else f', #{displacement}'}]"
        return (
            f"{'ldp' if load else 'stp'} {_xreg(rt, wide=wide)}, {_xreg(rt2, wide=wide)}, {memory}"
        )
    return f".word 0x{word:08x}"


def _format_arm(
    address: int, raw: bytes, instruction: str, show_hex: bool, show_position: bool
) -> str:
    output = f"0x{address:08x}  " if show_position else ""
    if show_hex:
        output += raw.hex().ljust(16) + "  "
    return output + instruction


@implementation("Disassemble ARM", category="Shellcode")
def disassemble_arm(value: Data, args: Args) -> str:
    data = _machine_bytes(value)
    if not data:
        return ""
    architecture = str(arg(args, 0, "ARM (32-bit)"))
    mode = str(arg(args, 1, "ARM"))
    endian = "big" if str(arg(args, 2, "Little Endian")) == "Big Endian" else "little"
    address = require_int(arg(args, 3, 0), name="starting address")
    show_hex, show_position = bool(arg(args, 4, True)), bool(arg(args, 5, True))
    width = 2 if architecture == "ARM (32-bit)" and mode.startswith("Thumb") else 4
    if len(data) % width:
        raise ValueError(f"Incomplete {architecture} instruction at end of input")
    output = []
    for offset in range(0, len(data), width):
        raw = data[offset : offset + width]
        word = int.from_bytes(raw, endian)
        if architecture == "ARM64 (AArch64)":
            instruction = _arm64(word, address + offset)
        elif width == 2:
            instruction = _thumb(word, address + offset)
        else:
            instruction = _arm32(word, address + offset)
        output.append(_format_arm(address + offset, raw, instruction, show_hex, show_position))
    return "\n".join(output)


_X86_REGISTERS = {
    16: ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"),
    32: ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"),
    64: (
        "rax",
        "rcx",
        "rdx",
        "rbx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ),
}


def _signed(data: bytes) -> int:
    return int.from_bytes(data, "little", signed=True)


def _modrm(data: bytes, position: int, bits: int, rex: int) -> tuple[str, str, int]:
    if position >= len(data):
        raise ValueError("Truncated x86 ModR/M byte")
    byte = data[position]
    position += 1
    mode, reg_index, rm_index = (
        byte >> 6,
        ((byte >> 3) & 7) | (((rex >> 2) & 1) * 8),
        (byte & 7) | ((rex & 1) * 8),
    )
    registers = _X86_REGISTERS[bits]
    reg = registers[reg_index]
    if mode == 3:
        return reg, registers[rm_index], position
    address_bits = 64 if bits == 64 else bits
    address_registers = _X86_REGISTERS[address_bits]
    base = address_registers[rm_index]
    index_text = ""
    if (byte & 7) == 4 and bits != 16:
        if position >= len(data):
            raise ValueError("Truncated x86 SIB byte")
        sib = data[position]
        position += 1
        scale = 1 << (sib >> 6)
        index = ((sib >> 3) & 7) | (((rex >> 1) & 1) * 8)
        base_index = (sib & 7) | ((rex & 1) * 8)
        base = address_registers[base_index]
        if index != 4:
            index_text = f"+{address_registers[index]}*{scale}"
    displacement = 0
    if mode == 0 and (byte & 7) == 5:
        if position + 4 > len(data):
            raise ValueError("Truncated x86 displacement")
        displacement = _signed(data[position : position + 4])
        position += 4
        base = "rip" if bits == 64 else ""
    elif mode == 1:
        displacement = _signed(data[position : position + 1])
        position += 1
    elif mode == 2:
        displacement = _signed(data[position : position + 4])
        position += 4
    suffix = f"{displacement:+#x}" if displacement else ""
    return reg, f"[{base}{index_text}{suffix}]", position


def _x86_instruction(data: bytes, start: int, address: int, mode: int) -> tuple[str, int]:
    position = start
    prefixes: list[str] = []
    operand_bits = 16 if mode == 16 else 32
    rex = 0
    while position < len(data):
        byte = data[position]
        if byte == 0x66:
            operand_bits = 32 if mode == 16 else 16
            position += 1
        elif byte in {0xF0, 0xF2, 0xF3}:
            prefixes.append({0xF0: "lock", 0xF2: "repne", 0xF3: "rep"}[byte])
            position += 1
        elif mode == 64 and 0x40 <= byte <= 0x4F:
            rex = byte & 15
            if rex & 8:
                operand_bits = 64
            position += 1
        else:
            break
    if position >= len(data):
        return "db " + ", ".join(f"0x{byte:02x}" for byte in data[start:]), len(data)
    opcode = data[position]
    position += 1
    simple = {0x90: "nop", 0xC3: "ret", 0xCB: "retf", 0xCC: "int3", 0xC9: "leave", 0xF4: "hlt"}
    if opcode in simple:
        instruction = simple[opcode]
    elif 0x50 <= opcode <= 0x5F:
        index = (opcode & 7) | ((rex & 1) * 8)
        operation_name = "push" if opcode < 0x58 else "pop"
        instruction = f"{operation_name} {_X86_REGISTERS[64 if mode == 64 else mode][index]}"
    elif 0xB8 <= opcode <= 0xBF:
        index = (opcode & 7) | ((rex & 1) * 8)
        width = 8 if operand_bits == 64 else operand_bits // 8
        immediate = int.from_bytes(data[position : position + width], "little")
        position += width
        instruction = f"mov {_X86_REGISTERS[operand_bits][index]}, 0x{immediate:x}"
    elif opcode in {0xE8, 0xE9}:
        displacement = _signed(data[position : position + 4])
        position += 4
        instruction = (
            f"{'call' if opcode == 0xE8 else 'jmp'} 0x{address + position - start + displacement:x}"
        )
    elif opcode == 0xEB:
        displacement = _signed(data[position : position + 1])
        position += 1
        instruction = f"jmp 0x{address + position - start + displacement:x}"
    elif 0x70 <= opcode <= 0x7F:
        conditions = (
            "jo",
            "jno",
            "jb",
            "jae",
            "je",
            "jne",
            "jbe",
            "ja",
            "js",
            "jns",
            "jp",
            "jnp",
            "jl",
            "jge",
            "jle",
            "jg",
        )
        displacement = _signed(data[position : position + 1])
        position += 1
        instruction = f"{conditions[opcode & 15]} 0x{address + position - start + displacement:x}"
    elif opcode in {0x89, 0x8B, 0x8D, 0x31, 0x33, 0x01, 0x03, 0x29, 0x2B, 0x39, 0x3B, 0x85}:
        reg, rm, position = _modrm(data, position, operand_bits, rex)
        names = {
            0x89: "mov",
            0x8B: "mov",
            0x8D: "lea",
            0x31: "xor",
            0x33: "xor",
            0x01: "add",
            0x03: "add",
            0x29: "sub",
            0x2B: "sub",
            0x39: "cmp",
            0x3B: "cmp",
            0x85: "test",
        }
        reverse = opcode in {0x8B, 0x8D, 0x33, 0x03, 0x2B, 0x3B}
        instruction = f"{names[opcode]} {reg if reverse else rm}, {rm if reverse else reg}"
    elif opcode == 0x0F and position < len(data) and 0x80 <= data[position] <= 0x8F:
        second = data[position]
        position += 1
        conditions = (
            "jo",
            "jno",
            "jb",
            "jae",
            "je",
            "jne",
            "jbe",
            "ja",
            "js",
            "jns",
            "jp",
            "jnp",
            "jl",
            "jge",
            "jle",
            "jg",
        )
        displacement = _signed(data[position : position + 4])
        position += 4
        instruction = f"{conditions[second & 15]} 0x{address + position - start + displacement:x}"
    else:
        instruction = f"db 0x{opcode:02x}"
    return " ".join([*prefixes, instruction]), position


@implementation("Disassemble x86", category="Shellcode")
def disassemble_x86(value: Data, args: Args) -> str:
    data = _machine_bytes(value)
    mode_text = str(arg(args, 0, "64"))
    if mode_text not in {"16", "32", "64"}:
        raise ValueError("Invalid mode value")
    mode = int(mode_text)

    # Validate Compatibility argument
    compatibility = str(arg(args, 1, "Full x86 architecture"))
    if compatibility != "Full x86 architecture":
        raise ValueError(
            f"Unsupported Compatibility mode: {compatibility!r}. "
            "PyChef x86 disassembler only supports 'Full x86 architecture'. "
            "Other compatibility modes (Knights Corner, Larrabee, etc.) are not implemented."
        )

    code_segment = require_int(arg(args, 2, 16), name="code segment")
    offset = require_int(arg(args, 3, 0), name="offset")
    show_hex, show_position = bool(arg(args, 4, True)), bool(arg(args, 5, True))
    output: list[str] = []
    position = 0
    while position < len(data):
        start = position
        instruction, position = _x86_instruction(data, start, offset + start, mode)
        raw = data[start:position]
        line = ""
        if show_position:
            if mode == 16:
                line += f"{code_segment:04x}:{(offset + start) & 0xFFFF:04x} "
            else:
                line += f"{offset + start:0{16 if mode == 64 else 8}x} "
        if show_hex:
            line += raw.hex().upper().ljust(32)
        output.append(line + instruction)
    return "\r\n".join(output) + ("\r\n" if output else "")
