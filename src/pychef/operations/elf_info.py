"""Dependency-free readelf-style ELF header, section, and symbol analysis."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

from ..registry import operation
from ..types import Args, Data, to_bytes

_ALIGNMENT = 30
_ABI_NAMES = {
    0x00: "System V",
    0x01: "HP-UX",
    0x02: "NetBSD",
    0x03: "Linux",
    0x04: "GNU Hurd",
    0x06: "Solaris",
    0x07: "AIX",
    0x08: "IRIX",
    0x09: "FreeBSD",
    0x0A: "Tru64",
    0x0B: "Novell Modesto",
    0x0C: "OpenBSD",
    0x0D: "OpenVMS",
    0x0E: "NonStop Kernel",
    0x0F: "AROS",
    0x10: "Fenix OS",
    0x11: "CloudABI",
    0x12: "Stratus Technologies OpenVOS",
}
_FILE_TYPES = {
    0x0000: "Unknown",
    0x0001: "Relocatable File",
    0x0002: "Executable File",
    0x0003: "Shared Object",
    0x0004: "Core File",
    0xFE00: "LOOS",
    0xFEFF: "HIOS",
    0xFF00: "LOPROC",
    0xFFFF: "HIPROC",
}
_MACHINES = {
    0x0000: "No specific instruction set",
    0x0001: "AT&T WE 32100",
    0x0002: "SPARC",
    0x0003: "x86",
    0x0004: "Motorola 68000 (M68k)",
    0x0005: "Motorola 88000 (M88k)",
    0x0006: "Intel MCU",
    0x0007: "Intel 80860",
    0x0008: "MIPS",
    0x0009: "IBM System/370",
    0x000A: "MIPS RS3000 Little-endian",
    0x000F: "Hewlett-Packard PA-RISC",
    0x0014: "PowerPC",
    0x0015: "PowerPC (64-bit)",
    0x0028: "ARM (up to ARMv7/Aarch32)",
    0x002A: "SuperH",
    0x002B: "SPARC Version 9",
    0x0032: "IA-64",
    0x003E: "AMD x86-64",
    0x0053: "Atmel AVR 8-bit microcontroller",
    0x005C: "OpenRISC 32-bit embedded processor",
    0x005E: "Tensilica Xtensa Architecture",
    0x00B7: "ARM 64-bits (ARMv8/Aarch64)",
    0x00F3: "RISC-V",
    0x00F7: "Berkeley Packet Filter",
    0x0101: "WDC 65C816",
}
_PROGRAM_TYPES = {
    0: "Unused",
    1: "Loadable Segment",
    2: "Dynamic linking information",
    3: "Interpreter Information",
    4: "Auxiliary Information",
    5: "Reserved",
    6: "Program Header Table",
    7: "Thread-Local Storage Template",
}
_SECTION_TYPES = {
    0: "Unused",
    1: "Program Data",
    2: "Symbol Table",
    3: "String Table",
    4: "Relocation Entries with Addens",
    5: "Symbol Hash Table",
    6: "Dynamic Linking Information",
    7: "Notes",
    8: "Program Space with No Data",
    9: "Relocation Entries with no Addens",
    10: "Reserved",
    11: "Dynamic Linker Symbol Table",
    14: "Array of Constructors",
    15: "Array of Destructors",
    16: "Array of pre-constructors",
    17: "Section group",
    18: "Extended section indices",
    19: "Number of defined types",
}


def _line(label: str, value: object) -> str:
    return label.ljust(_ALIGNMENT) + str(value)


class _Reader:
    def __init__(self, data: bytes, byteorder: Literal["little", "big"]) -> None:
        self.data = data
        self.byteorder = byteorder
        self.position = 0

    def move(self, position: int) -> None:
        self.position = position

    def read(self, length: int) -> bytes:
        if self.position + length > len(self.data):
            raise ValueError("Invalid ELF")
        value = self.data[self.position : self.position + length]
        self.position += length
        return value

    def integer(self, length: int) -> int:
        return int.from_bytes(self.read(length), self.byteorder)


@dataclass(slots=True)
class _ELFHeader:
    file_class: int
    byteorder: Literal["little", "big"]
    program_offset: int
    section_offset: int
    program_entry_size: int
    program_entries: int
    section_entry_size: int
    section_entries: int
    section_names_index: int


@dataclass(slots=True)
class _Section:
    name: str
    kind: int
    offset: int
    size: int
    entry_size: int


def _header(data: bytes) -> tuple[_ELFHeader, str]:
    if len(data) < 16 or data[:4] != b"\x7fELF" or data[4] not in {1, 2} or data[5] not in {1, 2}:
        raise ValueError("Invalid ELF")
    file_class = data[4]
    byteorder = "little" if data[5] == 1 else "big"
    reader = _Reader(data, byteorder)
    reader.move(16)
    file_type = reader.integer(2)
    machine = reader.integer(2)
    elf_version = reader.integer(4)
    width = 4 if file_class == 1 else 8
    entry_point = reader.integer(width)
    program_offset = reader.integer(width)
    section_offset = reader.integer(width)
    flags = reader.integer(4)
    header_size = reader.integer(2)
    program_entry_size = reader.integer(2)
    program_entries = reader.integer(2)
    section_entry_size = reader.integer(2)
    section_entries = reader.integer(2)
    section_names_index = reader.integer(2)
    abi = _ABI_NAMES.get(data[7], "")
    lines = [
        _line("Magic:", data[:4].decode("latin-1")),
        _line("Format:", "32-bit" if file_class == 1 else "64-bit"),
        _line("Endianness:", "Little" if byteorder == "little" else "Big"),
        _line("Version:", data[6]),
        _line("ABI:", abi),
    ]
    if abi != "Linux":
        lines.append(_line("ABI Version:", data[8]))
    lines.extend(
        (
            _line("Type:", _FILE_TYPES.get(file_type, "")),
            _line("Instruction Set Architecture:", _MACHINES.get(machine, "Unimplemented")),
            _line("ELF Version:", elf_version),
            _line("Entry Point:", f"0x{entry_point:x}"),
            _line("Entry PHOFF:", f"0x{program_offset:x}"),
            _line("Entry SHOFF:", f"0x{section_offset:x}"),
            _line("Flags:", f"{flags:08b}"),
            _line("ELF Header Size:", f"{header_size} bytes"),
            _line("Program Header Size:", f"{program_entry_size} bytes"),
            _line("Program Header Entries:", program_entries),
            _line("Section Header Size:", f"{section_entry_size} bytes"),
            _line("Section Header Entries:", section_entries),
            _line("Section Header Names:", section_names_index),
        )
    )
    header = _ELFHeader(
        file_class,
        byteorder,
        program_offset,
        section_offset,
        program_entry_size,
        program_entries,
        section_entry_size,
        section_entries,
        section_names_index,
    )
    return header, "\n".join(lines)


def _flags(value: int) -> str:
    labels = []
    if value & 1:
        labels.append("Execute")
    if value & 2:
        labels.append("Write")
    if value & 4:
        labels.append("Read")
    if value & 0xF0000000:
        labels.append("Unspecified")
    return ",".join(labels)


def _program_headers(data: bytes, header: _ELFHeader) -> list[str]:
    reader = _Reader(data, header.byteorder)
    width = 4 if header.file_class == 1 else 8
    output = []
    for index in range(header.program_entries):
        reader.move(header.program_offset + index * header.program_entry_size)
        kind = reader.integer(4)
        if 0x60000000 <= kind <= 0x6FFFFFFF:
            type_name = "Reserved Inclusive Range. OS Specific"
        elif 0x70000000 <= kind <= 0x7FFFFFFF:
            type_name = "Reserved Inclusive Range. Processor Specific"
        else:
            type_name = _PROGRAM_TYPES.get(kind, "")
        lines = [_line("Program Header Type:", type_name)]
        if header.file_class == 2:
            lines.append(_line("Flags:", _flags(reader.integer(4))))
        offset = reader.integer(width)
        virtual_address = reader.integer(width)
        physical_address = reader.integer(width)
        file_size = reader.integer(width)
        memory_size = reader.integer(width)
        lines.extend(
            (
                _line("Offset Of Segment:", offset),
                _line("Virtual Address of Segment:", virtual_address),
                _line("Physical Address of Segment:", physical_address),
                _line("Size of Segment:", f"{file_size} bytes"),
                _line("Size of Segment in Memory:", f"{memory_size} bytes"),
            )
        )
        if header.file_class == 1:
            lines.append(_line("Flags:", _flags(reader.integer(4))))
        output.append("\n".join(lines))
    return output


def _string(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def _section_kind(kind: int) -> str:
    if 0x60000000 <= kind <= 0x6FFFFFFF:
        return "OS-specific"
    if 0x70000000 <= kind <= 0x7FFFFFFF:
        return "Processor-specific"
    if 0x80000000 <= kind <= 0x8FFFFFFF:
        return "Application-specific"
    return _SECTION_TYPES.get(kind, "Unused")


def _section_flags(value: int) -> str:
    masks = (
        (0x00000001, "Writable"),
        (0x00000002, "Alloc"),
        (0x00000004, "Executable"),
        (0x00000010, "Merge"),
        (0x00000020, "Strings"),
        (0x00000040, "SHT Info Link"),
        (0x00000080, "Link Order"),
        (0x00000100, "OS Specific Handling"),
        (0x00000200, "Group"),
        (0x00000400, "Thread Local Data"),
        (0x0FF00000, "OS-Specific"),
        (0xF0000000, "Processor Specific"),
        (0x04000000, "Special Ordering (Solaris)"),
        (0x08000000, "Excluded (Solaris)"),
    )
    return ",".join(label for mask, label in masks if value & mask)


def _section_names_offset(data: bytes, header: _ELFHeader) -> int:
    if not header.section_entries or header.section_names_index >= header.section_entries:
        return 0
    reader = _Reader(data, header.byteorder)
    position = header.section_offset + header.section_names_index * header.section_entry_size
    position += 16 if header.file_class == 1 else 24
    reader.move(position)
    return reader.integer(4 if header.file_class == 1 else 8)


def _sections(data: bytes, header: _ELFHeader) -> tuple[list[_Section], list[str]]:
    reader = _Reader(data, header.byteorder)
    names_offset = _section_names_offset(data, header)
    width = 4 if header.file_class == 1 else 8
    sections = []
    output = []
    for index in range(header.section_entries):
        reader.move(header.section_offset + index * header.section_entry_size)
        name_offset = reader.integer(4)
        kind = reader.integer(4)
        flags = reader.integer(width)
        virtual_address = reader.integer(width)
        section_offset = reader.integer(width)
        section_size = reader.integer(width)
        associated = reader.integer(4)
        extra = reader.integer(4)
        reader.integer(width)
        entry_size = reader.integer(width)
        type_name = _section_kind(kind)
        name = _string(data, names_offset + name_offset) if type_name != "Unused" else ""
        lines = [_line("Type:", type_name)]
        if name:
            lines.append(_line("Section Name: ", name))
        lines.extend(
            (
                _line("Flags:", _section_flags(flags)),
                _line("Section Vaddr in memory:", virtual_address),
                _line("Offset of the section:", section_offset),
                _line("Section Size:", section_size),
                _line("Associated Section:", associated),
                _line("Section Extra Information:", extra),
            )
        )
        sections.append(_Section(name, kind, section_offset, section_size, entry_size))
        output.append("\n".join(lines))
    return sections, output


def _symbols(data: bytes, header: _ELFHeader, sections: list[_Section]) -> list[str]:
    symbol_table = next((section for section in sections if section.name == ".symtab"), None)
    string_table = next((section for section in sections if section.name == ".strtab"), None)
    if symbol_table is None or string_table is None or not symbol_table.entry_size:
        return []
    reader = _Reader(data, header.byteorder)
    output = []
    count = math.ceil(symbol_table.size / symbol_table.entry_size)
    for index in range(count):
        reader.move(symbol_table.offset + index * symbol_table.entry_size)
        name_offset = reader.integer(4)
        name = _string(data, string_table.offset + name_offset)
        if name:
            output.append(_line("Symbol Name:", name))
    return output


@operation("ELF Info", category="Analysis")
def elf_info(value: Data, _args: Args) -> str:
    data = to_bytes(value)
    header, header_output = _header(data)
    sections, section_output = _sections(data, header)
    result = ["=" * _ALIGNMENT + " ELF Header " + "=" * _ALIGNMENT, header_output + "\n"]
    result.append("=" * _ALIGNMENT + " Program Header " + "=" * _ALIGNMENT)
    result.extend(output + "\n" for output in _program_headers(data, header))
    result.append("=" * _ALIGNMENT + " Section Header " + "=" * _ALIGNMENT)
    result.extend(output + "\n" for output in section_output)
    result.append("=" * _ALIGNMENT + " Symbol Table " + "=" * _ALIGNMENT)
    result.extend(_symbols(data, header, sections))
    return "\n".join(result)
