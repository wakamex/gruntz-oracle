"""Read i386 COFF objects and link named fragments into a common address space."""

import hashlib
import re
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


# Names a build or the delinker gives data and code with no source name of its own: counters, section
# numbers, content hashes and exception-table labels. They differ between two builds of one unit, so such a
# fragment is identified by its contents instead.
ANONYMOUS = re.compile(r"^(\$|\.|_\$S\d+\$S|__eh(funcinfo|handler|unwind|reg)\$|__unwindfunclet\$|\?\?_C@_)|#")


def stable(name):
    return not ANONYMOUS.search(name)


class Link:
    """One address space for two or more objects. A fragment with a source name (a function, a global) is
    placed by that name; one without is placed by its bytes, relocation fields masked, and its order among
    equal fragments of its object, so the same datum gets the same address in every object whatever each
    build called it."""

    def __init__(self, objects):
        parent = {}

        def root(name):
            parent.setdefault(name, name)
            while parent[name] != name:
                parent[name] = parent[parent[name]]
                name = parent[name]
            return name

        defined = []  # (object, fragment, the names that define it)
        for obj in objects:
            for frag in obj.fragments:
                names = {frag.name} | {
                    sym.name for sym in obj.symbols.values()
                    if sym.section == frag.section and sym.value == frag.offset and sym.storage in (2, 3)
                    and sym.name != obj.sections[frag.section].name
                }
                defined.append((obj, frag, names))
                kept = sorted(n for n in names if stable(n))
                for name in kept[1:]:
                    parent[root(name)] = root(kept[0])
        self.local = {}  # id(object) -> name -> key
        kinds, sizes = {}, {}
        for obj in objects:
            local = self.local.setdefault(id(obj), {})
            seen = {}
            for owner, frag, names in defined:
                if owner is not obj:
                    continue
                kept = sorted(n for n in names if stable(n))
                if kept:
                    key = root(kept[0])
                else:
                    body = bytearray(frag.data)
                    for offset, _, _ in obj.sections[frag.section].relocs:
                        if frag.offset <= offset < frag.offset + len(body):
                            body[offset - frag.offset : offset - frag.offset + 4] = bytes(4)
                    digest = hashlib.sha256(bytes(body)).hexdigest()[:16]
                    seen[digest] = seen.get(digest, -1) + 1
                    key = f"$content_{'code' if frag.code else 'data'}_{digest}_{seen[digest]}"
                kinds[key] = "code" if frag.code else "data"
                sizes[key] = max(sizes.get(key, 0), len(frag.data))
                for name in names:
                    local[name] = key
        # a symbol one object only references resolves to the other object's definition when there is one, so
        # a string literal or helper retail keeps elsewhere and our build defines lands at one address
        defined_keys = {}
        for obj in objects:
            for name, key in self.local[id(obj)].items():
                defined_keys.setdefault(name, key)
        for obj in objects:
            local = self.local[id(obj)]
            for sym in obj.symbols.values():
                if sym.section == 0 and sym.storage == 2 and sym.name not in local:
                    local[sym.name] = defined_keys.get(sym.name, root(sym.name))
                    kinds.setdefault(local[sym.name], "external")
        counters = {"code": 0x10000000, "data": 0x30000000, "external": 0x50000000}
        ends = {"code": 0x30000000, "data": 0x50000000, "external": 0x60000000}
        self.addresses = {}
        for key in sorted(kinds):
            kind = kinds[key]
            self.addresses[key] = counters[kind]
            counters[kind] += max(0x10000, -(-sizes.get(key, 0) // 0x10000) * 0x10000)
            if counters[kind] >= ends[kind]:
                raise ValueError("object exceeds address-space allocation")
        self.names = {address: key for key, address in self.addresses.items()}
        self.unlinked = []  # (start, end, reason) of fragments load could not place

    def address(self, obj, name):
        return self.addresses[self.local[id(obj)][name]]

    def load(self, obj):
        def address(section, offset):
            frag = obj.fragment_at(section, offset)
            return self.address(obj, frag.name) + offset - frag.offset

        def target(sym, addend):
            if sym.section == -1:
                return sym.value + addend
            if sym.section > 0:
                if sym.name == obj.sections[sym.section].name:
                    return address(sym.section, sym.value + addend)
                return address(sym.section, sym.value) + addend
            return self.address(obj, sym.name) + addend

        def link_fragment(frag):
            base = self.address(obj, frag.name)
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
            return base, bytes(body), frag

        loaded = []
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        for frag in obj.fragments:
            try:
                loaded.append(link_fragment(frag))
            except ValueError as error:
                # a fragment whose code cannot be placed on its own (a short branch into a neighbour retail
                # shares code with) is left unloaded; a run that reaches it ends there, unjudged
                base = self.address(obj, frag.name)
                self.unlinked.append((base, base + len(frag.data), str(error)))
        entries = {
            s.name: address(s.section, s.value)
            for s in obj.symbols.values()
            if s.section > 0 and s.kind & 0x20
        }
        return loaded, entries
