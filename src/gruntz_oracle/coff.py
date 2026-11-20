"""Read i386 COFF objects and link named fragments into a common address space."""

import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM


@dataclass
class Symbol:
    name: str
    value: int
    section: int
    kind: int
    storage: int


@dataclass
class Section:
    name: str
    data: bytes
    flags: int
    relocs: list[tuple[int, int, int]]


@dataclass
class Fragment:
    name: str
    section: int
    offset: int
    data: bytes
    code: bool
    readonly: bool
    relocated: tuple[int, ...] = ()


class Object:
    def __init__(self, path: Path):
        self.path = path
        data = path.read_bytes()
        if len(data) < 20 or struct.unpack_from("<H", data)[0] != 0x14C:
            raise ValueError(f"{path}: expected i386 COFF")
        _, count, _, table, nsyms, optional, _ = struct.unpack_from("<HHIIIHH", data)
        strings = table + 18 * nsyms

        def name(raw):
            if raw[:4] == bytes(4):
                start = strings + struct.unpack_from("<I", raw, 4)[0]
                return data[start : data.index(b"\0", start)].decode("latin1")
            return raw.rstrip(b"\0").decode("latin1")

        self.sections = {}
        for i in range(1, count + 1):
            at = 20 + optional + (i - 1) * 40
            raw, _, _, size, body, relocs, _, nr, _, flags = struct.unpack_from(
                "<8sIIIIIIHHI", data, at
            )
            label = name(raw)
            if label.startswith("/"):
                start = strings + int(label[1:])
                label = data[start : data.index(b"\0", start)].decode("latin1")
            if flags & 0x1000000:
                raise ValueError("extended relocation counts are unsupported")
            content = data[body : body + size] if body else bytes(size)
            if len(content) != size:
                raise ValueError("truncated section")
            entries = [
                struct.unpack_from("<IIH", data, relocs + j * 10) for j in range(nr)
            ]
            self.sections[i] = Section(label, content, flags, entries)
        self.symbols = {}
        i = 0
        while i < nsyms:
            at = table + i * 18
            raw, value, section, kind, storage, aux = struct.unpack_from(
                "<8sIhHBB", data, at
            )
            self.symbols[i] = Symbol(name(raw), value, section, kind, storage)
            i += aux + 1
        self.fragments = []
        for index, sec in self.sections.items():
            if sec.flags & (0x2000000 | 0x200 | 0x800) or sec.name.startswith(".debug"):
                continue
            code = bool(sec.flags & 0x20)
            definitions = [
                s
                for s in self.symbols.values()
                if s.section == index
                and s.storage in (2, 3)
                and s.name != sec.name
                and (not code or s.kind & 0x20)
            ]
            starts = sorted({s.value for s in definitions})
            if not starts:
                if not sec.data:
                    continue
                starts = [0]
            elif starts[0] != 0:
                starts.insert(0, 0)
            for j, start in enumerate(starts):
                end = starts[j + 1] if j + 1 < len(starts) else len(sec.data)
                names = sorted(s.name for s in definitions if s.value == start)
                label = names[0] if names else f"{sec.name}#{index}+{start}"
                self.fragments.append(
                    Fragment(
                        label,
                        index,
                        start,
                        sec.data[start:end],
                        code,
                        not bool(sec.flags & 0x80000000),
                    )
                )
        self.functions = {
            s.name for s in self.symbols.values() if s.section > 0 and s.kind & 0x20
        }

    def fragment_at(self, section, offset):
        for frag in self.fragments:
            if frag.section == section and frag.offset <= offset < frag.offset + len(
                frag.data
            ):
                return frag
        raise ValueError(f"no allocated fragment for section {section} offset {offset}")


class Link:
    def __init__(self, objects):
        self.addresses = {}
        kinds = {}
        aliases = {}

        def root(name):
            aliases.setdefault(name, name)
            while aliases[name] != name:
                name = aliases[name]
            return name

        for obj in objects:
            for frag in obj.fragments:
                kinds[frag.name] = "code" if frag.code else "data"
                for sym in obj.symbols.values():
                    if (
                        sym.section == frag.section
                        and sym.value == frag.offset
                        and sym.storage in (2, 3)
                        and sym.name != obj.sections[frag.section].name
                    ):
                        kinds[sym.name] = kinds[frag.name]
                        left, right = sorted((root(sym.name), root(frag.name)))
                        aliases[right] = left
            for sym in obj.symbols.values():
                if sym.section == 0 and sym.storage == 2:
                    kinds.setdefault(sym.name, "external")
        groups = {}
        for name, kind in kinds.items():
            canonical = root(name)
            if kind != "external" or canonical not in groups:
                groups[canonical] = kind
        counters = {"code": 0x10000000, "data": 0x30000000, "external": 0x50000000}
        allocation = {}
        for canonical in sorted(groups):
            kind = groups[canonical]
            allocation[canonical] = counters[kind]
            counters[kind] += 0x10000
            if (
                counters[kind]
                >= {"code": 0x30000000, "data": 0x50000000, "external": 0x60000000}[
                    kind
                ]
            ):
                raise ValueError("object exceeds address-space allocation")
        self.addresses = {name: allocation[root(name)] for name in kinds}
        self.names = {address: name for name, address in allocation.items()}

    def load(self, obj):
        def address(section, offset):
            frag = obj.fragment_at(section, offset)
            return self.addresses[frag.name] + offset - frag.offset

        def target(sym, addend):
            if sym.section == -1:
                return sym.value + addend
            if sym.section > 0:
                if sym.name == obj.sections[sym.section].name:
                    return address(sym.section, sym.value + addend)
                return address(sym.section, sym.value) + addend
            return self.addresses[sym.name] + addend

        loaded = []
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        for frag in obj.fragments:
            if len(frag.data) > 0x10000:
                raise ValueError(f"{frag.name}: fragment exceeds 64 KiB")
            base = self.addresses[frag.name]
            body = bytearray(frag.data)
            reloc_fields = set()
            for offset, index, kind in obj.sections[frag.section].relocs:
                if not frag.offset <= offset < frag.offset + len(body):
                    continue
                rel = offset - frag.offset
                if kind == 0:
                    continue
                if kind not in (6, 7, 20):
                    raise ValueError(f"{frag.name}: unsupported relocation {kind}")
                addend = struct.unpack_from("<i", body, rel)[0]
                value = target(obj.symbols[index], addend)
                if kind == 20:
                    value -= base + rel + 4
                struct.pack_into("<I", body, rel, value & 0xFFFFFFFF)
                reloc_fields.add(rel)
            if frag.code:
                for ins in md.disasm(frag.data, frag.offset):
                    if (
                        not (ins.group(1) or ins.group(2))
                        or not ins.operands
                        or ins.operands[0].type != X86_OP_IMM
                    ):
                        continue
                    field = ins.address - frag.offset + ins.imm_offset
                    if field in reloc_fields:
                        continue
                    old_dest = ins.operands[0].imm & 0xFFFFFFFF
                    try:
                        dest = address(frag.section, old_dest)
                    except ValueError:
                        raise ValueError(
                            f"{frag.name}: unrelocated branch outside section"
                        ) from None
                    displacement = dest - (base + ins.address - frag.offset + ins.size)
                    try:
                        body[field : field + ins.imm_size] = displacement.to_bytes(
                            ins.imm_size, "little", signed=True
                        )
                    except OverflowError:
                        raise ValueError(
                            f"{frag.name}: short branch crosses allocated functions"
                        ) from None
            frag.relocated = tuple(sorted(reloc_fields))
            loaded.append((base, bytes(body), frag))
        entries = {
            s.name: address(s.section, s.value)
            for s in obj.symbols.values()
            if s.section > 0 and s.kind & 0x20
        }
        return loaded, entries
