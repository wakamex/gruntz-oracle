"""Deterministic generated-input execution of linked i386 functions."""

import bisect
import hashlib
import math
import struct
import zlib
from collections import Counter, deque
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MEM_FETCH_UNMAPPED,
    UC_MODE_32,
    UC_PROT_EXEC,
    UC_PROT_READ,
    Uc,
    UcError,
)
from unicorn import x86_const as x86

from .coff import Fragment, Link, Object, stable
from .retail import image
from .signature import record_result, signature, void_result

PAGE = 4096
ENTRY_SP = 0x68010000
STACK = ENTRY_SP - 0x100000  # 1 MiB below the entry stack pointer: room for frames __chkstk allocates
STOP = 0x61000000
GDT = 0x62000000
TIB = GDT + 0x800
MASK = 0xFFFFFFFF
# Instructions that end a backward scan for a call's pushed arguments: control transfers and stack moves.
STOPS = {"call", "ret", "jmp", "pop", "pushal", "popal", "leave", "enter"}
REGISTERS = {
    name: getattr(x86, "UC_X86_REG_" + name.upper())
    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")
}


def moves_esp(ins):
    """Whether the instruction changes esp itself, as opposed to reading or writing memory through it."""
    if ins.mnemonic in ("push", "pop", "pushal", "popal", "pushfd", "popfd", "leave", "enter", "call", "ret"):
        return True
    return bool(ins.operands) and ins.operands[0].type == X86_OP_REG and ins.reg_name(ins.operands[0].reg) == "esp"


def mix(value):
    value = (value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return value ^ (value >> 31)


def word(seed, address, constants=()):
    value = mix((seed << 32) ^ address)
    lane = seed % 8
    if lane == 0:
        return (0, 1, 2, 3, MASK)[value % 5]
    if lane in (2, 3):
        # mostly empty memory: arguments, registers and call results are small, and memory reads as zero
        # except an occasional arena pointer, so loops over clear cells or empty lists run to their bounds
        if address >= 0xE0000000 or ENTRY_SP <= address < ENTRY_SP + 0x400:
            return (0, 1, 2, 3, MASK)[value % 5]
        # each page is either a page of pointers (arrays of rows, objects' pointer fields) or sparse data,
        # mostly zero with an occasional small value, so a pointer chain can reach a run of clear cells
        if mix((seed << 32) ^ (address & -PAGE) ^ 0x5BD1E995) % 2 == 0:
            return 0x70000000 + ((value >> 8) % 256) * PAGE
        return sparse(seed, address)
    if lane == 1 and constants:
        return constants[value % len(constants)] & MASK
    selector = value % 8
    if selector < 4:
        return 0x70000000 + ((value >> 8) % 256) * PAGE
    if selector < 6:
        return (0, 1, 2, 3, 4, 7, 15, 31, 63, 127, 255, MASK)[(value >> 8) % 12]
    return (value >> 16) & MASK


def sparse(seed, address):
    """A data word of mostly empty memory: zero, or now and then a small value."""
    value = mix((seed << 32) ^ address)
    return 0 if value % 4 else (1, 2, 3)[value % 3]


# Memory laid out by type: each record type, and each array of pointers to one, has its own span of the
# arena, so the type of any address follows from the address alone and generated memory does not depend on
# the order a build touches it. A pointer to a type points at one of its span's slots, chosen from the
# pointer's own address, so two builds reach the same objects.
TYPED, TYPED_END = 0x80000000, 0xE0000000
SPAN, SLOT = 0x40000, 0x10000
# A virtual function's stand-in address, never mapped: a typed vtable's entries point here, so a call through
# one is a boundary that knows the function it reached.
METHODS = 0xE1000000


class Layouts:
    """The record layouts of the unit: for each record, its size and pointer fields with their targets."""

    def __init__(self, records):
        self.sizes = {name: row["size"] for name, row in records.items()}
        self.vtables = {name: tuple(row["vtable"]) for name, row in records.items() if row.get("vtable")}
        self.globals = records.get("$globals", {}).get("globals", {})  # decorated name -> pointee type
        self.records = {
            name: (row["size"], tuple((offset, target) for offset, target in row["pointers"]))
            for name, row in records.items()
            if 0 < row["size"] <= SLOT
        }
        kinds = set(self.records)
        for _, pointers in self.records.values():
            kinds.update(target for _, target in pointers if target.lstrip("*") in self.records)
        kinds.update("#" + name for name in self.vtables)  # each polymorphic class's vtable
        kinds = sorted(kinds)[: (TYPED_END - TYPED) // SPAN]
        self.ids = {kind: index for index, kind in enumerate(kinds)}
        self.kinds = kinds
        # the stand-in address of each virtual function, by vtable and slot
        self.methods = {
            METHODS + 0x400 * self.ids["#" + name] + 4 * slot: decorated
            for name, table in self.vtables.items() if "#" + name in self.ids
            for slot, decorated in enumerate(table[:256])
        }

    def layout(self, kind):
        """The element size and pointer fields of one slot type: a record, or an array of pointers."""
        if kind.startswith("*"):
            return 4, ((0, kind[1:]),)
        return self.records[kind]

    def pointer(self, seed, address, kind):
        """The generated value of a pointer stored at `address` whose target has type `kind`."""
        value = mix((seed << 32) ^ address ^ 0x7F4A7C15)
        if kind.startswith("?vtable"):
            # a polymorphic object's vtable pointer is never null: the class's typed vtable when its functions
            # are known, else generated memory
            table = "#" + kind.partition(":")[2]
            if table in self.ids:
                return TYPED + self.ids[table] * SPAN
            return 0x70000000 + ((value >> 8) % 256) * PAGE
        if seed % 8 not in (2, 3) and value % 8 == 0:
            return 0
        if kind not in self.ids:
            return 0x70000000 + ((value >> 8) % 256) * PAGE
        size, _ = self.layout(kind)
        per_slot = SLOT // size
        return TYPED + self.ids[kind] * SPAN + ((value >> 8) % (SPAN // SLOT)) * per_slot * size

    def page(self, seed, page, constants):
        """The bytes of one page of the typed arena: scalar words as generated data, pointer fields typed."""
        kind = self.kinds[(page - TYPED) // SPAN] if (page - TYPED) // SPAN < len(self.kinds) else None
        if seed % 8 in (2, 3):
            body = bytearray(b"".join(struct.pack("<I", sparse(seed, at)) for at in range(page, page + PAGE, 4)))
        else:
            body = bytearray(page_bytes(seed, page, constants))
        if kind is None:
            return bytes(body)
        if kind.startswith("#"):  # a vtable: each slot holds its function's stand-in address
            start = TYPED + self.ids[kind] * SPAN
            for slot in range(len(self.vtables[kind[1:]][:256])):
                at = start + 4 * slot
                if page <= at < page + PAGE:
                    body[at - page : at - page + 4] = struct.pack("<I", METHODS + 0x400 * self.ids[kind] + 4 * slot)
            return bytes(body)
        size, pointers = self.layout(kind)
        start = TYPED + self.ids[kind] * SPAN
        first = (page - start) // size
        for element in range(first, (page + PAGE - 1 - start) // size + 1):
            for offset, target in pointers:
                at = start + element * size + offset
                if page - 3 <= at < page + PAGE:
                    data = struct.pack("<I", self.pointer(seed, at, target))
                    for k in range(4):
                        if page <= at + k < page + PAGE:
                            body[at + k - page] = data[k]
        return bytes(body)


def owner(symbol):
    """The class a member function's decorated name belongs to, as libclang spells it, or None."""
    if not symbol.startswith("?") or "?$" in symbol:
        return None
    if symbol.startswith("??"):
        rest = symbol[4:] if symbol[2] == "_" else symbol[3:]
        scopes = rest.split("@@")[0].split("@")
    else:
        scopes = symbol[1:].split("@@")[0].split("@")[1:]
    return "::".join(reversed(scopes)) if scopes and all(scopes) else None


@lru_cache(maxsize=2048)
def page_bytes(seed, page, constants=()):
    return b"".join(
        struct.pack("<I", word(seed, at, constants))
        for at in range(page, page + PAGE, 4)
    )


class CaseStopped(Exception):
    """End an emulated access on the same rules as a native access."""


@dataclass
class Limits:
    instructions: int = 20000
    pages: int = 128


class Runner:
    def __init__(self, link, obj, symbol, constants, limits, loaded, layouts=None):
        self.link = link
        self.layouts = layouts
        self.loaded, self.entries = loaded
        if symbol not in self.entries:
            raise ValueError(f"{obj.path}: missing function {symbol}")
        for start, end, reason in link.unlinked:
            if start <= self.entries[symbol] < end:
                raise ValueError(reason)
        self.entry = self.entries[symbol]
        self.symbol = symbol
        self.constants = tuple(constants)
        self.limits = limits
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.instructions = {}
        self.ranges = []
        self.sizes = layouts.sizes if layouts else None
        self.sigs = {
            address: self.signature(name) for name, address in link.addresses.items()
        }
        self.methods = layouts.methods if layouts else {}
        # a global that points to a record starts as a typed pointer, wherever the objects placed it
        local = link.local[id(obj)]
        self.typed_globals = {
            link.addresses[local[name]]: kind
            for name, kind in (layouts.globals.items() if layouts else ())
            if name in local and kind in layouts.ids
        }
        for address, name in self.methods.items():
            self.sigs[address] = self.signature(name)
        for base, data, frag in self.loaded:
            if frag.code:
                self.ranges.append((base, base + len(data)))
                for ins in self.md.disasm(data, base):
                    self.instructions[ins.address] = ins
        self.previous = {i.address + i.size: i for i in self.instructions.values()}
        # unnamed code (exception handlers and unwind funclets) is laid out differently by each build, so a
        # pointer into it is compared as a token, not an address
        self.bases = sorted(link.names)

    def signature(self, name):
        """The call layout of a function, sizing classes passed by value from the unit's layouts."""
        return signature(name, self.sizes)

    def reg(self, name):
        return self.uc.reg_read(REGISTERS[name])

    def setreg(self, name, value):
        self.uc.reg_write(REGISTERS[name], value & MASK)

    def map_page(self, page, *, generated=False):
        if page not in self.mapped:
            self.uc.mem_map(page, PAGE)
            if generated and self.layouts and TYPED <= page < TYPED_END:
                self.uc.mem_write(page, self.layouts.page(self.seed, page, self.constants))
            elif generated:
                self.uc.mem_write(page, page_bytes(self.seed, page, self.constants))
            for at, kind in self.typed_globals.items() if generated else ():
                if page <= at <= page + PAGE - 4:
                    self.uc.mem_write(at, struct.pack("<I", self.layouts.pointer(self.seed, at, kind)))
            self.mapped.add(page)

    def protect(self, base, size):
        """Code and read-only data cannot be written, as in the original process: a store there faults."""
        for page in range(base & -PAGE, (base + size - 1 & -PAGE) + PAGE, PAGE):
            self.uc.mem_protect(page, PAGE, UC_PROT_READ | UC_PROT_EXEC)
        self.protected.append((base & -PAGE, (base + size - 1 & -PAGE) + PAGE))

    def read(self, address, size):
        if not self.ensure_memory(address, size):
            raise CaseStopped
        return bytes(self.uc.mem_read(address, size))

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def install_segments(self):
        self.map_page(GDT)
        descriptors = [
            (0, 0xFFFFF, 0x9A, 0xC),
            (0, 0xFFFFF, 0x92, 0xC),
            (TIB, 0x7FF, 0x92, 0x4),
        ]
        for index, (base, limit, access, flags) in enumerate(descriptors, 1):
            value = (
                (limit & 0xFFFF)
                | ((base & 0xFFFFFF) << 16)
                | (access << 40)
                | ((limit >> 16) << 48)
                | (flags << 52)
                | ((base >> 24) << 56)
            )
            self.uc.mem_write(GDT + index * 8, struct.pack("<Q", value))
        self.uc.reg_write(x86.UC_X86_REG_GDTR, (0, GDT, 31, 0))
        self.uc.reg_write(x86.UC_X86_REG_CS, 8)
        for reg in (x86.UC_X86_REG_DS, x86.UC_X86_REG_ES, x86.UC_X86_REG_SS):
            self.uc.reg_write(reg, 16)
        self.uc.reg_write(x86.UC_X86_REG_FS, 24)
        self.uc.mem_write(TIB, struct.pack("<I", MASK))
        self.uc.mem_write(TIB + 0x18, struct.pack("<I", TIB))

    def stop(self, outcome):
        self.outcome = outcome
        self.uc.emu_stop()

    def bad_memory(self, uc, access, address, size, value, _):
        if access == UC_MEM_FETCH_UNMAPPED:
            if any(start <= address < end for start, end, _ in self.link.unlinked):
                self.stop(["limit", "unlinked"])  # code the linker could not place: the run is not judged
                return False
            self.stop(["fault", "fetch", address & -PAGE])
            return False
        return self.ensure_memory(address, size)

    def ensure_memory(self, address, size):
        if address < PAGE or address + size > 0x100000000:
            self.stop(["fault", "memory", address & -PAGE])
            return False
        for page in range(address & -PAGE, (address + size - 1 & -PAGE) + PAGE, PAGE):
            if page in self.mapped:
                continue
            if page in self.lazy:  # a writable data fragment's page: seeded bytes with its relocated words
                self.map_page(page, generated=True)
                for at, word_bytes in self.lazy[page]:
                    self.uc.mem_write(at, word_bytes)
                self.apply(page, page + PAGE)
                continue
            if self.generated >= self.limits.pages:
                self.stop(["limit", "pages"])
                return False
            self.map_page(page, generated=True)
            self.apply(page, page + PAGE)
            self.generated += 1
        return True

    def write_hook(self, uc, access, address, size, value, _):
        # the frame, and the function's own parameters, which it may reuse as scratch, are dead at return
        if STACK <= address and address + size <= self.frame_end:
            return
        if any(start <= address < end for start, end in self.protected):
            return  # the store faults before it writes; the fault is the outcome compared
        self.writes.update(range(address, address + size))
        ins = self.instructions.get(self.reg("eip"))
        at, width = None, 0
        if ins and ins.mnemonic in ("fst", "fstp") and ins.operands[0].type == X86_OP_MEM:
            # a floating-point store, compared as a number within rounding; the operand gives its extent, since
            # the emulator may write a 10-byte value in parts
            at, width = self.address_of(ins, ins.operands[0]), ins.operands[0].size
        elif ins and ins.mnemonic.split()[-1] in ("movsd", "movsw", "movsb"):
            # a string copy carries a float's marking along: the source of this element is as far past esi as
            # the destination is past edi
            source = self.reg("esi") + address - self.reg("edi") & MASK
            for start, extent in list(self.float_stores.items()):
                if start <= source < start + extent:
                    at, width = address - (source - start), extent
                    break
        for other in [o for o, extent in self.float_stores.items() if o < address + size and address < o + extent and o != at]:
            del self.float_stores[other]  # a value this write overlaps is no longer that float
        if at is not None and width in (4, 8, 10):
            self.float_stores[at] = width

    def address_of(self, ins, op):
        mem = op.mem
        address = mem.disp
        if mem.base:
            address += self.uc.reg_read(getattr(x86, "UC_X86_REG_" + ins.reg_name(mem.base).upper()))
        if mem.index:
            address += mem.scale * self.uc.reg_read(getattr(x86, "UC_X86_REG_" + ins.reg_name(mem.index).upper()))
        if mem.segment and ins.reg_name(mem.segment) == "fs":
            address += TIB
        return address & MASK

    def operand(self, ins, op):
        if op.type == X86_OP_IMM:
            return op.imm & MASK
        if op.type == X86_OP_REG:
            return self.uc.reg_read(
                getattr(x86, "UC_X86_REG_" + ins.reg_name(op.reg).upper())
            )
        if op.type == X86_OP_MEM:
            return self.u32(self.address_of(ins, op))
        raise ValueError("unsupported call operand")

    def input(self, key, value):
        """An input word generated for `key` (a memory address, or the key of a register or call result),
        with the case's overrides applied."""
        if self.overrides:
            data = bytearray(struct.pack("<I", value))
            for k in range(4):
                if key + k in self.overrides:
                    data[k] = self.overrides[key + k]
            value = struct.unpack("<I", data)[0]
        self.sources[key] = value
        return value

    def apply(self, start, end):
        """Write the case's overrides that fall in [start, end) over generated memory."""
        for at, byte in self.overrides.items():
            if start <= at < end:
                self.uc.mem_write(at, bytes((byte,)))

    def compared(self, ins):
        """Log a comparison: each operand's value, size and the input it came from, if one can be named. A sub,
        dec, inc or and that sets the flags a branch tests (MSVC's switch tests are sub and dec) is logged as
        a cmp or test of its operands before it runs: dec x compares x with 1, inc x with -1."""
        operands = list(ins.operands)
        if operands and operands[0].type == X86_OP_REG and ins.reg_name(operands[0].reg) in ("esp", "ebp"):
            return  # frame arithmetic, not a comparison
        sides = []
        for op in operands:
            size = op.size or 4
            if op.type == X86_OP_IMM:
                sides.append((None, op.imm & ((1 << 8 * size) - 1), size, "imm"))
            elif op.type == X86_OP_REG:
                value = self.uc.reg_read(getattr(x86, "UC_X86_REG_" + ins.reg_name(op.reg).upper()))
                value &= (1 << 8 * size) - 1
                sides.append((None, value, size, "reg"))
            elif op.type == X86_OP_MEM:
                at = self.address_of(ins, op)
                if at < PAGE or not all((page & -PAGE) in self.mapped for page in (at, at + size - 1)):
                    return
                value = int.from_bytes(self.uc.mem_read(at, size), "little")
                # memory the function read before writing it, outside code and constants, is an input
                generated = not (STACK <= at < ENTRY_SP + 4) and not any(lo <= at < hi for lo, hi in self.protected)
                fresh = not any(at + k in self.writes for k in range(size))
                sides.append((at if generated and fresh else None, value, size, "mem"))
        if ins.mnemonic in ("dec", "inc") and len(sides) == 1:
            size = sides[0][2]
            sides.append((None, 1 if ins.mnemonic == "dec" else (1 << 8 * size) - 1, size, "imm"))
        if len(sides) == 2:
            kind = "test" if ins.mnemonic in ("test", "and") else "cmp"
            self.log.append((ins.address, kind, sides))

    def traced(self, value):
        """Inputs a register's value was computed from, each with the word that would give the register another
        value: an input word, or an 8- or 16-bit field of one (after a shift or mask, such as a message's high
        word), equal to the value or off by a small constant (msg - 0x110 in a switch); closest first, with each
        input's best whole-word and best field reading."""
        found = []
        for k, v in self.sources.items():
            best = {}
            for shift, mask in ((0, MASK), (16, 0xFFFF), (0, 0xFFFF), (24, 0xFF), (16, 0xFF), (8, 0xFF), (0, 0xFF)):
                field = (v >> shift) & mask
                offset = (field - value + 0x80000000 & MASK) - 0x80000000  # signed: msg - 0x110 may wrap
                whole = mask == MASK
                if abs(offset) <= 0x10000 and (whole not in best or abs(offset) < best[whole][0]):
                    best[whole] = (abs(offset), lambda t, v=v, s=shift, m=mask, d=offset:
                                   v & ~(m << s) & MASK | ((t + d) & m) << s)
            found.extend((distance, not whole, k, word_for) for whole, (distance, word_for) in best.items())
        found.sort(key=lambda row: row[:2])
        return [(k, 4, word_for) for _, _, k, word_for in found[:8]]

    def proposals(self):
        """Overrides that would take the other side of the comparisons this run made, latest first: an
        operand read from an input is set to the other operand, its neighbours, or (for test) with the
        mask's bits set or cleared; a register operand is traced to an input word holding the same value."""
        found, sites = [], set()
        for address, mnemonic, sides in reversed(self.log):
            for index in (0, 1):
                key, value, size, kind = sides[index]
                other = sides[1 - index][1]
                width = (1 << 8 * size) - 1
                if mnemonic == "switch":
                    targets = set(range(16)) if index == 0 else set()  # a jump table's index: its first cases
                elif mnemonic == "cmp":
                    targets = {other, other + 1 & width, other - 1 & width}
                elif sides[0][3] == "reg" and sides[1][3] == "reg" and sides[0][1] == sides[1][1]:
                    targets = {0, 1, width}  # test r, r: zero, positive and negative
                else:
                    targets = {value | other, value & ~other & width}
                targets.discard(value)
                # each change: (input key, its byte width, the word that gives the operand a target value)
                if key is not None:
                    changes = [(key, size, lambda target: target)]
                elif kind == "reg":
                    changes = self.traced(value)
                else:
                    changes = []
                for k, width_bytes, word_for in changes:
                    for target in sorted(targets):
                        site = (address, index, k, target)
                        if site not in sites:
                            sites.add(site)
                            new = word_for(target) & ((1 << 8 * width_bytes) - 1)
                            found.append({k + i: b for i, b in enumerate(new.to_bytes(width_bytes, "little"))})
        return found

    def call_site_words(self, ins):
        """The stack words a call without a readable signature passes, and how many bytes the callee pops.
        A caller that removes the arguments itself follows the call with `add esp, N` (cdecl); otherwise
        the callee pops what the caller pushed (stdcall, thiscall). The pushes are counted back from the
        call over instructions that neither move esp nor transfer control, since MSVC sets ecx or loads
        an operand between an argument's push and the call."""
        # the cleanup may follow other work the scheduler placed first, such as a lea reading the arguments
        after = self.instructions.get(ins.address + ins.size)
        while (
            after
            and after.mnemonic not in STOPS | {"push"}
            and not (after.group(1) or after.group(3))
            and not moves_esp(after)
        ):
            after = self.instructions.get(after.address + after.size)
        if (
            after
            and after.mnemonic == "add"
            and len(after.operands) == 2
            and after.op_str.startswith("esp, ")
            and after.operands[1].type == X86_OP_IMM
        ):
            return after.operands[1].imm // 4, 0
        cursor, count = ins.address, 0
        while True:
            previous = self.previous.get(cursor)
            if previous is None or previous.mnemonic in STOPS or previous.group(1) or previous.group(3):
                break
            if previous.mnemonic == "push":
                count += 1
            elif moves_esp(previous):  # a store into the stack, such as mov [esp+4], x, does not move it
                break
            cursor = previous.address
        return count, 4 * count

    def virtual(self, ins):
        """Whether a call without a signature is a virtual member call, whose this is in ecx: the call reads its
        target through a vtable pointer equal to the word at [ecx]. Judged by values, so builds that load the
        vtable through different registers agree; a COM call pushes its object instead, and in any other call
        ecx is scratch, holding whatever each build left there."""
        op = ins.operands[0] if ins.operands else None
        if op is None or op.type != X86_OP_MEM or not op.mem.base:
            return False
        table = self.uc.reg_read(getattr(x86, "UC_X86_REG_" + ins.reg_name(op.mem.base).upper()))
        ecx = self.reg("ecx")
        if ecx < PAGE or not all(page in self.mapped for page in (ecx & -PAGE, ecx + 3 & -PAGE)):
            return False  # reading an unmapped [ecx] would generate memory one build never touched
        return struct.unpack("<I", self.uc.mem_read(ecx, 4))[0] == table

    def token(self, value):
        """A pointer into unnamed code (an exception stub or funclet, anywhere in its allocated slot) as a token."""
        index = bisect.bisect_right(self.bases, value) - 1
        unnamed = index >= 0 and 0x10000000 <= value < 0x30000000
        if unnamed and str(self.link.names[self.bases[index]]).startswith("$content_code"):
            return "unnamed-code"
        return value

    def arguments(self, values, sig):
        widths = dict(sig.pointees) if sig else {}
        normalized = []
        for index, value in enumerate(values):
            if not STACK <= value < ENTRY_SP + 4:
                normalized.append(self.token(value))
                continue
            size = widths.get(index)
            if size is None:
                # A pointer into the caller's frame whose pointee size is unknown: its address differs
                # between correct builds, so compare the word it points at, the part both must agree on.
                normalized.append({"stack": self.token(self.u32(value))})
                continue
            aliases = [
                (other, pointer - value)
                for other, pointer in enumerate(values)
                if other in widths
                and pointer < value + size
                and value < pointer + widths[other]
            ]
            normalized.append(
                {"pointee": self.read(value, size).hex(), "aliases": aliases}
            )
        return normalized

    def boundary(self, ins, destination, tail):
        if self.link.names.get(destination) == "__chkstk":
            # The runtime's stack probe: it takes the frame size in eax, no stack arguments, and returns
            # with esp lowered by that size, which is how a large frame is allocated.
            size, sp = self.reg("eax"), self.reg("esp")
            self.calls.append({"callee": "__chkstk", "eax": size})
            if tail:
                self.setreg("esp", sp + 4 - size)
                self.setreg("eip", self.u32(sp))
            else:
                self.setreg("esp", sp - size)
                self.setreg("eip", ins.address + ins.size)
            return
        sig = self.sigs.get(destination)
        if sig:
            words, pop = sig.words, sig.pop
        else:
            words, pop = self.call_site_words(ins)
        if words > 128:
            raise ValueError("boundary signature exceeds 128 words")
        sp = self.reg("esp")
        args_sp = sp + 4 if tail else sp
        arguments = [self.u32(args_sp + 4 * i) for i in range(words)]
        callee = self.link.names.get(destination) or self.methods.get(destination, destination)
        call = {"callee": callee, "stack": self.arguments(arguments, sig)}
        if (sig.thiscall if sig else self.virtual(ins)):
            ecx = self.reg("ecx")
            # this in the caller's frame: compare the object's first word (its vtable for a class with
            # one), since the frame address itself differs between correct builds
            call["ecx"] = {"stack": self.token(self.u32(ecx))} if STACK <= ecx < ENTRY_SP + 4 else self.token(ecx)
        self.calls.append(call)
        # keyed by the callee and how many times it has been called, so a call added or removed elsewhere does
        # not shift the results of the others
        callee = str(call["callee"])
        self.call_counts[callee] += 1
        slot = (zlib.crc32(callee.encode()) % 0x100000) * 64 + self.call_counts[callee] % 64
        result = self.input(0xF0000000 + 4 * slot, word(self.seed, 0xF0000000 + 4 * slot, self.constants))
        self.setreg("eax", result)
        if sig and sig.floating:
            status = self.uc.reg_read(x86.UC_X86_REG_FPSW)
            top = (((status >> 11) & 7) - 1) & 7
            value = float(struct.unpack("<i", struct.pack("<I", result))[0])
            bits = struct.unpack("<Q", struct.pack("<d", value))[0]
            exponent = (bits >> 52) & 0x7FF
            mantissa = ((bits & ((1 << 52) - 1)) | (1 << 52)) << 11 if exponent else 0
            extended_exp = ((bits >> 63) << 15) | (
                exponent - 1023 + 16383 if exponent else 0
            )
            self.uc.reg_write(
                getattr(x86, f"UC_X86_REG_FP{top}"), (mantissa, extended_exp)
            )
            self.uc.reg_write(x86.UC_X86_REG_FPSW, (status & ~(7 << 11)) | top << 11)
            tags = self.uc.reg_read(x86.UC_X86_REG_FPTAG)
            self.uc.reg_write(x86.UC_X86_REG_FPTAG, tags & ~(3 << (2 * top)))
        if tail:
            target = self.u32(sp)
            self.setreg("esp", sp + 4 + pop)
        else:
            target = ins.address + ins.size
            self.setreg("esp", sp + pop)
        self.setreg("eip", target)

    def code_hook(self, uc, address, size, _):
        if address == STOP:
            self.stop(["return"])
            return
        if self.reg("esp") < STACK or self.reg("esp") >= ENTRY_SP + PAGE:
            self.stop(["fault", "stack", self.reg("esp") & -PAGE])
            return
        self.steps += 1
        self.executed[address] = self.executed.get(address, 0) + 1
        if self.steps > self.limits.instructions:
            self.stop(["limit", "instructions"])
            return
        ins = self.instructions.get(address)
        if ins is None:
            self.stop(["fault", "instruction", address & -PAGE])
            return
        if ins.mnemonic in ("cmp", "test", "sub", "dec", "inc", "and") and len(self.log) < 512:
            self.compared(ins)
            return
        if ins.mnemonic not in ("call", "jmp"):
            return
        op = ins.operands[0]
        if ins.mnemonic == "jmp" and op.type == X86_OP_MEM and op.mem.index and op.mem.scale == 4 and len(self.log) < 512:
            # a switch's jump table: its index is compared with every case
            index = self.uc.reg_read(getattr(x86, "UC_X86_REG_" + ins.reg_name(op.mem.index).upper()))
            self.log.append((ins.address, "switch", [(None, index, 4, "reg"), (None, 0, 4, "imm")]))
        destination = self.operand(ins, ins.operands[0])
        direct = ins.operands[0].type == X86_OP_IMM
        inside = any(lo <= destination < hi for lo, hi in self.ranges)
        same_function = any(
            lo <= address < hi and lo <= destination < hi for lo, hi in self.ranges
        )
        if ((direct and inside and destination not in self.stubbed)
                or (ins.mnemonic == "jmp" and same_function)):
            return
        self.boundary(ins, destination, ins.mnemonic == "jmp")

    def run(self, seed, overrides=None, stubbed=frozenset()):
        self.seed = seed
        self.stubbed = stubbed  # entries of callees run as boundaries, like functions outside the objects
        self.overrides = overrides or {}
        self.sources = {}  # input key -> value of the register-like inputs: registers, arguments, call results
        self.log = []
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mapped = set()
        self.generated = 0
        self.calls = []
        self.writes = set()
        self.executed = {}
        self.float_stores = {}
        self.call_counts = Counter()
        self.protected = []
        self.steps = 0
        self.outcome = None
        self.lazy = {}  # page -> relocated words of writable data fragments, written when the page is first touched
        for base, data, frag in self.loaded:
            if frag.code or frag.readonly:
                for page in range(base & -PAGE, (base + len(data) - 1 & -PAGE) + PAGE, PAGE):
                    self.map_page(page)
                self.uc.mem_write(base, data)
                self.protect(base, len(data))
                continue
            if not stable(frag.name):
                # compiler-generated data (a floating-point constant or other temporary the compiler keeps in
                # writable data) is part of the program, not an input: it starts with its own bytes
                for page in range(base & -PAGE, (base + len(data) - 1 & -PAGE) + PAGE, PAGE):
                    self.map_page(page)
                self.uc.mem_write(base, data)
                continue
            for page in range(base & -PAGE, (base + len(data) - 1 & -PAGE) + PAGE, PAGE):
                self.lazy.setdefault(page, [])
            for offset in frag.relocated:
                self.lazy[(base + offset) & -PAGE].append((base + offset, data[offset : offset + 4]))
        self.uc.mem_map(STACK, ENTRY_SP + PAGE - STACK)
        self.mapped.update(range(STACK, ENTRY_SP + PAGE, PAGE))
        self.map_page(STOP)
        self.uc.mem_write(STOP, b"\x90")
        self.install_segments()
        for name in REGISTERS:
            self.setreg(
                name,
                word(
                    seed, 0xE0000000 + 4 * list(REGISTERS).index(name), self.constants
                ),
            )
        self.setreg("ecx", 0x70000000 + (mix(seed) % 256) * PAGE)
        self.setreg("esp", ENTRY_SP)
        self.uc.mem_write(ENTRY_SP, struct.pack("<I", STOP))
        self.uc.mem_write(
            ENTRY_SP + 4,
            b"".join(
                struct.pack("<I", word(seed, ENTRY_SP + 4 + 4 * i, self.constants))
                for i in range(128)
            ),
        )
        sig = self.signature(self.symbol)
        self.frame_end = ENTRY_SP + 4 + 4 * (sig.words if sig else 0)
        if sig:
            records = dict(sig.records) if self.layouts else {}
            for index in sig.pointers:
                at = ENTRY_SP + 4 + index * 4
                if index in records and records[index] in self.layouts.ids:
                    value = self.layouts.pointer(seed, at, records[index])
                else:
                    value = 0x70000000 + (mix(seed + index + 1) % 256) * PAGE
                self.uc.mem_write(at, struct.pack("<I", value))
        # a member function's object is laid out by its class when the unit's layouts know it
        cls = owner(self.symbol) if self.layouts and (sig is None or sig.thiscall) else None
        if cls in (self.layouts.ids if self.layouts else ()):
            self.setreg("ecx", self.layouts.pointer(seed, 0xE0000000 + 0x100, cls) or TYPED + self.layouts.ids[cls] * SPAN)
        for index, name in enumerate(REGISTERS):
            if name not in ("esp", "eip"):
                self.setreg(name, self.input(0xE0000000 + 4 * index, self.reg(name)))
                if name != "ecx":
                    # under Microsoft's conventions only ecx (this) carries an input; the others are scratch or
                    # saved, so a compared value is not traced to them
                    del self.sources[0xE0000000 + 4 * index]
        self.apply(ENTRY_SP + 4, ENTRY_SP + 4 + 4 * 128)
        for index in range(sig.words if sig else 16):
            self.sources[ENTRY_SP + 4 + 4 * index] = self.u32(ENTRY_SP + 4 + 4 * index)
        self.uc.reg_write(x86.UC_X86_REG_EFLAGS, 0x202)
        self.uc.reg_write(x86.UC_X86_REG_FPCW, 0x37F)
        self.uc.reg_write(x86.UC_X86_REG_FPSW, 0)
        self.uc.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        for index in range(8):
            self.uc.reg_write(getattr(x86, f"UC_X86_REG_FP{index}"), (0, 0))
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self.bad_memory)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write_hook)
        self.uc.hook_add(UC_HOOK_CODE, self.code_hook)
        self.uc.hook_add(
            UC_HOOK_INTR,
            lambda uc, number, _: self.stop(
                ["fault", f"interrupt-{number}", self.reg("eip") & -PAGE]
            ),
        )
        try:
            self.uc.emu_start(self.entry, 0)
        except CaseStopped:
            pass
        except UcError as error:
            if self.outcome is None:
                self.outcome = ["fault", str(error), self.reg("eip") & -PAGE]
        if self.outcome is None and self.reg("eip") == 0:
            # emu_start's end address is 0, so a jump to address 0 ends emulation quietly; in the
            # original process it faults on the instruction fetch
            self.outcome = ["fault", "fetch", 0]
        if self.outcome is None:
            raise ValueError("execution stopped without an outcome")
        record = {
            "outcome": self.outcome,
            "calls": self.calls,
            "writes": {
                str(at): self.uc.mem_read(at, 1)[0]
                for at in sorted(self.writes)
                if at & -PAGE in self.mapped
            },
        }
        # the exception-handler chain head, left pointing into the frame or at a handler stub by a run that ended
        # before restoring it, is compared as a frame address or a token: both differ between correct builds
        if any(str(TIB + k) in record["writes"] for k in range(4)):
            head = self.u32(TIB)
            for k in range(4):
                record["writes"].pop(str(TIB + k), None)
            record["handler_chain"] = "frame" if STACK <= head < ENTRY_SP + 4 else self.token(head)
        if self.outcome == ["return"]:
            # edx is scratch under Microsoft's conventions unless the result fills edx:eax; with no
            # readable signature it is compared, so an unknown result type cannot hide a difference
            own = self.signature(self.symbol)
            void = void_result(self.symbol)
            if void or (own and own.floating):
                kept = ()  # nothing, or a float or double on the x87 stack: eax and edx are scratch
            elif record_result(self.symbol):
                kept = ("eax",)  # a class returned by value: eax holds the caller's result address, edx is scratch
            else:
                kept = ("eax", "edx") if own is None or own.wide else ("eax",)
            record["registers"] = {
                r: self.reg(r) for r in (*kept, "esp", "ebx", "esi", "edi", "ebp")
            }
            if not void:  # the x87 stack holds a floating result, or, with no signature, may
                tags = self.uc.reg_read(x86.UC_X86_REG_FPTAG)
                top = (self.uc.reg_read(x86.UC_X86_REG_FPSW) >> 11) & 7
                stack = [
                    extended(self.uc.reg_read(getattr(x86, f"UC_X86_REG_FP{(top + i) & 7}")))
                    for i in range(8)
                    if (tags >> (2 * ((top + i) & 7))) & 3 != 3
                ]
                record["x87"] = stack[:1] if own and own.floating else stack
                record["x87_depth"] = len(stack)
        record["floats"] = {str(at): size for at, size in sorted(self.float_stores.items())}
        return record


def followed(loaded, entry):
    """The fragments the function can reach through relocations and branches, transitively: the code it can
    run and the data it can name. Others are left out, so an access through a generated value that happens to
    land where an unrelated global was placed reads generated memory, as it would in both builds."""
    if entry is None:
        return loaded
    items = sorted(loaded, key=lambda item: item[0])
    starts = [base for base, _, _ in items]

    def owner(address):
        index = bisect.bisect_right(starts, address) - 1
        if index >= 0 and address < starts[index] + max(len(items[index][1]), 1):
            return index
        return None

    seen, todo = set(), [owner(entry)]
    while todo:
        index = todo.pop()
        if index is None or index in seen:
            continue
        seen.add(index)
        todo.extend(owner(target) for target in items[index][2].targets)
    # data read from the original executable has no relocations and is kept with whatever names it
    return [item for index, item in enumerate(items) if index in seen or not item[2].targets and item[2].section == 0]


def kinds_of(link, key):
    address = link.addresses[key]
    return "external" if 0x50000000 <= address < 0x60000000 else "defined"


def extended(value):
    """An x87 register's 80-bit value as a float."""
    mantissa, exponent = value
    sign = -1.0 if exponent & 0x8000 else 1.0
    exponent &= 0x7FFF
    if exponent == 0x7FFF:
        return math.nan if mantissa & ((1 << 63) - 1) else sign * math.inf
    try:
        return sign * math.ldexp(mantissa, exponent - 16383 - 63)
    except OverflowError:
        return sign * math.inf


def close(a, b):
    """Floating-point results within rounding: a build that keeps a value in an 80-bit register and one that
    rounds it to memory are both correct. Within a millionth relative, or a billionth absolute for results that
    cancel to near zero."""
    if math.isnan(a) or math.isnan(b):
        return math.isnan(a) and math.isnan(b)
    return math.isclose(a, b, rel_tol=1e-6, abs_tol=1e-9)  # absolute: cancellation leaves 0 against ~1e-17


def stored(writes, at, size):
    data = bytes(writes.get(str(at + k), 0) for k in range(size))
    if size == 10:
        mantissa, exponent = struct.unpack("<QH", data)
        return extended((mantissa, exponent))
    return struct.unpack("<f" if size == 4 else "<d", data)[0]


def same(a, b):
    """Whether two runs behaved the same, with floating-point values compared within rounding."""
    keys = (a.keys() | b.keys()) - {"x87", "writes", "floats"}
    if any(a.get(k) != b.get(k) for k in keys):
        return False
    if len(a.get("x87", [])) != len(b.get("x87", [])) or not all(map(close, a.get("x87", []), b.get("x87", []))):
        return False
    # a value either build stored with fst is a number in both, though the other may have copied it with mov
    floats = {**b["floats"], **a["floats"]}
    if any(floats[at] != size for at, size in b["floats"].items()):
        return False  # stored with different widths
    numbers = {str(int(at) + k) for at, size in floats.items() for k in range(size)}
    if {k: v for k, v in a["writes"].items() if k not in numbers} != {k: v for k, v in b["writes"].items() if k not in numbers}:
        return False
    if a["writes"].keys() & numbers != b["writes"].keys() & numbers:
        return False
    return all(close(stored(a["writes"], int(at), size), stored(b["writes"], int(at), size)) for at, size in floats.items())


def bucket(count):
    """A hit count's class, as coverage-guided fuzzers count loop iterations: 1, 2, 3, 4-7, 8-15, ..."""
    return count if count < 4 else count.bit_length() + 1


def shape(ins, runner=None):
    """An instruction with branch targets left out, for aligning two builds' code; a constant that points into
    unnamed code (an exception handler stub, laid out differently by each build) is the token the runs compare."""
    if ins.group(1) or ins.group(2) or ins.mnemonic.startswith("j"):
        return ins.mnemonic
    parts = [ins.mnemonic]
    for op in ins.operands:
        if op.type == X86_OP_IMM and runner is not None and runner.token(op.imm & MASK) == "unnamed-code":
            parts.append("unnamed-code")
        elif op.type == X86_OP_MEM and runner is not None and runner.token(op.mem.disp & MASK) == "unnamed-code":
            parts.append("[unnamed-code]")
        else:
            parts.append(ins.op_str)
    return " ".join(parts)


def reachable(runner, code):
    """The code fragments a run can follow from the function's entry: direct calls and jumps into code the
    objects define, which the oracle executes rather than stubbing."""
    starts = sorted(code)

    def fragment(address):
        index = bisect.bisect_right(starts, address) - 1
        if index >= 0 and address < starts[index] + len(code[starts[index]]):
            return starts[index]
        return None

    seen, todo = set(), [fragment(runner.entry)]
    while todo:
        base = todo.pop()
        if base is None or base in seen:
            continue
        seen.add(base)
        for address in range(base, base + len(code[base])):
            ins = runner.instructions.get(address)
            if ins and (ins.group(1) or ins.group(2)) and ins.operands and ins.operands[0].type == X86_OP_IMM:
                todo.append(fragment(ins.operands[0].imm & MASK))
    return seen


def shared_code(runners, symbol):
    """The entries of the functions, other than the one checked, whose code is the same in both builds."""
    codes = [{base: data for base, data, frag in r.loaded if frag.code} for r in runners]
    own = {r.entries.get(symbol) for r in runners}
    return frozenset(base for base in codes[0].keys() & codes[1].keys()
                     if base not in own and codes[0][base].rstrip(b"\x90\xcc") == codes[1][base].rstrip(b"\x90\xcc"))


def differing(runners):
    """For each runner, the addresses of its instructions that differ from the other build's code at the same
    fragment: every function both builds define is aligned instruction by instruction."""
    found = [set(), set()]
    codes = [{base: data for base, data, frag in r.loaded if frag.code} for r in runners]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    followed = set.union(*(reachable(r, code) for r, code in zip(runners, codes)))
    for base in codes[0].keys() & codes[1].keys() & followed:
        if codes[0][base].rstrip(b"\x90\xcc") == codes[1][base].rstrip(b"\x90\xcc"):
            continue
        # alignment padding after a function (nop or int3, which one object keeps and the other trims) never runs
        sides = [list(md.disasm(codes[i][base].rstrip(b"\x90\xcc"), base)) for i in (0, 1)]
        shapes = [[shape(i, runner) for i in side] for side, runner in zip(sides, runners)]
        for tag, i1, i2, j1, j2 in SequenceMatcher(None, *shapes, autojunk=False).get_opcodes():
            if tag != "equal":
                found[0].update(i.address for i in sides[0][i1:i2])
                found[1].update(i.address for i in sides[1][j1:j2])
    return found


def check(
    before: Path,
    after: Path,
    symbol: str,
    unit=None,
    cases=5000,
    *,
    seed=0,
    limits=None,
    layouts=None,
    guided=True,
    retail=None,
):
    if cases < 1 or seed < 0:
        raise ValueError("cases must be positive and seed nonnegative")
    objects = [Object(Path(before)), Object(Path(after))]
    link = Link(objects)
    constants = {0, 1, 2, 3, MASK}
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for obj in objects:
        for frag in obj.fragments:
            if frag.code:
                for ins in md.disasm(frag.data, 0):
                    if ins.mnemonic in ("cmp", "test"):
                        for op in ins.operands:
                            if op.type == X86_OP_IMM:
                                constants.update(
                                    (
                                        op.imm - 1 & MASK,
                                        op.imm & MASK,
                                        op.imm + 1 & MASK,
                                    )
                                )
    limits = limits or Limits()
    loads = [link.load(obj) for obj in objects]
    if retail is not None:
        # a compiler-generated datum an object only references, under a name no other object defines, is
        # read from the original executable when its bytes hold no pointers
        source = image(Path(retail))
        for obj, (loaded, _) in zip(objects, loads):
            defined = {base for base, _, _ in loaded}
            for name, key in link.local[id(obj)].items():
                base = link.addresses[key]
                if stable(name) or base in defined or kinds_of(link, key) != "external" or source is None:
                    continue
                data = source.bytes(name)
                if data:
                    loaded.append((base, data, Fragment(name, 0, 0, data, False, True)))
                    defined.add(base)
    shared = []
    for index, (loaded, entries) in enumerate(loads):
        # A function or datum only one object defines (an inline copy one build emitted, or a body the
        # retail object keeps elsewhere) runs from that copy in both, so the two builds see the same callee.
        other_loaded, other_entries = loads[1 - index]
        bases = {base for base, _, _ in loaded}
        shared.append((
            [*loaded, *(item for item in other_loaded if item[0] not in bases)],
            {**other_entries, **entries},
        ))
    # each build keeps the fragments either reaches, so both runs see the same memory at every address
    reached = {base for loaded, entries in shared for base, _, _ in followed(loaded, entries.get(symbol))}
    shared = [([item for item in loaded if item[0] in reached], entries) for loaded, entries in shared]
    runners = [
        Runner(link, obj, symbol, sorted(constants), limits, shared[index], Layouts(layouts) if layouts else None)
        for index, obj in enumerate(objects)
    ]
    differ = 0
    first = None
    outcomes = [Counter(), Counter()]
    targets = differing(runners)
    same_callees = shared_code(runners, symbol)
    reaching = exercised = inconclusive = 0
    missed = Counter()
    covered = set()
    queue = deque()
    tried = set()
    seeds = iter(range(seed, seed + 10 * cases + 1))
    guided_cases = 0
    for number in range(cases):
        # half the cases are seeds; the rest take the other side of comparisons in cases that reached new
        # code or ran a loop a new number of times, and more seeds when there is nothing left to flip
        if guided and number >= cases // 2 and queue:
            case, overrides = queue.popleft()
            guided_cases += 1
        else:
            case, overrides = next(seeds), {}
        records = [runner.run(case, overrides) for runner in runners]
        if any(record["outcome"][0] == "limit" for record in records) and same_callees:
            # a callee whose code both builds share, such as a long decoding loop, can use up the limit without
            # showing anything about the difference: the case runs again with such callees as boundaries
            records = [runner.run(case, overrides, same_callees) for runner in runners]
        if guided:
            new = {(index, address, bucket(count)) for index, runner in enumerate(runners)
                   for address, count in runner.executed.items()} - covered
            if new:
                covered |= new
                for runner in runners:
                    for proposal in runner.proposals()[:24]:
                        candidate = {**overrides, **proposal}
                        identity = (case, tuple(sorted(candidate.items())))
                        if identity not in tried:
                            tried.add(identity)
                            queue.append((case, candidate))
        for index, record in enumerate(records):
            outcomes[index].update([record["outcome"][0]])
        if any(runner.executed.keys() & target for runner, target in zip(runners, targets)):
            reaching += 1
            if all(record["outcome"][0] != "limit" for record in records):
                exercised += 1
        else:  # how a case that missed the difference ended, for finding what keeps inputs away from it
            outcome = records[0]["outcome"]
            if outcome[0] == "fault":
                kind = "fault-null" if outcome[-1] == 0 else f"fault-{outcome[1] if outcome[1] in ('memory', 'fetch', 'stack') else 'other'}"
            else:
                kind = outcome[0] if outcome[0] != "limit" else f"limit-{outcome[1]}"
            missed[kind] += 1
        if any(record["outcome"][0] == "limit" for record in records):
            # a run cut off by a limit stopped at a point that depends on how the build orders its work, so
            # the two are not compared: the case shows neither agreement nor a difference
            inconclusive += 1
            continue
        if not same(*records):
            differ += 1
            if first is None:
                categories = [
                    k
                    for k in records[0].keys() | records[1].keys()
                    if records[0].get(k) != records[1].get(k)
                ]
                first = {
                    "seed": case,
                    "overrides": {hex(at): byte for at, byte in sorted(overrides.items())},
                    "categories": sorted(categories),
                    "before": records[0],
                    "after": records[1],
                }
    # agreement means something only where a case ran the code that differs and both builds finished
    if differ:
        verdict = "differ"
    elif (targets[0] or targets[1]) and not exercised:
        verdict = "under-exercised"
    else:
        verdict = "agree"
    return {
        "symbol": symbol,
        "unit": unit,
        "verdict": verdict,
        "differing_instructions": [len(targets[0]), len(targets[1])],
        "cases_reaching_difference": reaching,
        "cases_exercising_difference": exercised,
        "cases_missing_difference": dict(missed),
        "cases_inconclusive": inconclusive,
        "guided_cases": guided_cases,
        "cases": cases,
        "agree": cases - differ,
        "differ": differ,
        "first_difference": first,
        "outcomes": {"before": dict(outcomes[0]), "after": dict(outcomes[1])},
        "execution_limits": asdict(limits),
        "input_guidance": {"comparison_constants": sorted(constants)},
        "objects": [
            hashlib.sha256(obj.path.read_bytes()).hexdigest() for obj in objects
        ],
    }
