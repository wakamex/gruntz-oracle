"""Deterministic generated-input execution of linked i386 functions."""

import bisect
import hashlib
import struct
import zlib
from collections import Counter
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

from .coff import Link, Object
from .signature import signature

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
        return 0 if value % 4 else (1, 2, 3)[value % 3]
    if lane == 1 and constants:
        return constants[value % len(constants)] & MASK
    selector = value % 8
    if selector < 4:
        return 0x70000000 + ((value >> 8) % 256) * PAGE
    if selector < 6:
        return (0, 1, 2, 3, 4, 7, 15, 31, 63, 127, 255, MASK)[(value >> 8) % 12]
    return (value >> 16) & MASK


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
    def __init__(self, link, obj, symbol, constants, limits, loaded):
        self.link = link
        self.loaded, self.entries = loaded
        if symbol not in self.entries:
            raise ValueError(f"{obj.path}: missing function {symbol}")
        self.entry = self.entries[symbol]
        self.symbol = symbol
        self.constants = tuple(constants)
        self.limits = limits
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.instructions = {}
        self.ranges = []
        self.sigs = {
            address: signature(name) for name, address in link.addresses.items()
        }
        for base, data, frag in self.loaded:
            if frag.code:
                self.ranges.append((base, base + len(data)))
                for ins in self.md.disasm(data, base):
                    self.instructions[ins.address] = ins
        self.previous = {i.address + i.size: i for i in self.instructions.values()}
        # unnamed code (exception handlers and unwind funclets) is laid out differently by each build, so a
        # pointer into it is compared as a token, not an address
        self.bases = sorted(link.names)

    def reg(self, name):
        return self.uc.reg_read(REGISTERS[name])

    def setreg(self, name, value):
        self.uc.reg_write(REGISTERS[name], value & MASK)

    def map_page(self, page, *, generated=False):
        if page not in self.mapped:
            self.uc.mem_map(page, PAGE)
            if generated:
                self.uc.mem_write(page, page_bytes(self.seed, page, self.constants))
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
                continue
            if self.generated >= self.limits.pages:
                self.stop(["limit", "pages"])
                return False
            self.map_page(page, generated=True)
            self.generated += 1
        return True

    def write_hook(self, uc, access, address, size, value, _):
        if STACK <= address and address + size <= ENTRY_SP + 4:
            return
        if any(start <= address < end for start, end in self.protected):
            return  # the store faults before it writes; the fault is the outcome compared
        self.writes.update(range(address, address + size))

    def operand(self, ins, op):
        if op.type == X86_OP_IMM:
            return op.imm & MASK
        if op.type == X86_OP_REG:
            return self.uc.reg_read(
                getattr(x86, "UC_X86_REG_" + ins.reg_name(op.reg).upper())
            )
        if op.type == X86_OP_MEM:
            mem = op.mem
            address = mem.disp
            if mem.base:
                address += self.uc.reg_read(
                    getattr(x86, "UC_X86_REG_" + ins.reg_name(mem.base).upper())
                )
            if mem.index:
                address += mem.scale * self.uc.reg_read(
                    getattr(x86, "UC_X86_REG_" + ins.reg_name(mem.index).upper())
                )
            if mem.segment and ins.reg_name(mem.segment) == "fs":
                address += TIB
            return self.u32(address & MASK)
        raise ValueError("unsupported call operand")

    def call_site_words(self, ins):
        """The stack words a call without a readable signature passes, and how many bytes the callee pops.
        A caller that removes the arguments itself follows the call with `add esp, N` (cdecl); otherwise
        the callee pops what the caller pushed (stdcall, thiscall). The pushes are counted back from the
        call over instructions that neither move esp nor transfer control, since MSVC sets ecx or loads
        an operand between an argument's push and the call."""
        after = self.instructions.get(ins.address + ins.size)
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
            elif "esp" in previous.op_str.split(",")[0]:
                break
            cursor = previous.address
        return count, 4 * count

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
        call = {"callee": self.link.names.get(destination, destination), "stack": self.arguments(arguments, sig)}
        if sig is None or sig.thiscall:
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
        result = word(self.seed, 0xF0000000 + 4 * slot, self.constants)
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
        self.executed.add(address)
        if self.steps > self.limits.instructions:
            self.stop(["limit", "instructions"])
            return
        ins = self.instructions.get(address)
        if ins is None:
            self.stop(["fault", "instruction", address & -PAGE])
            return
        if ins.mnemonic not in ("call", "jmp"):
            return
        destination = self.operand(ins, ins.operands[0])
        direct = ins.operands[0].type == X86_OP_IMM
        inside = any(lo <= destination < hi for lo, hi in self.ranges)
        same_function = any(
            lo <= address < hi and lo <= destination < hi for lo, hi in self.ranges
        )
        if (direct and inside) or (ins.mnemonic == "jmp" and same_function):
            return
        self.boundary(ins, destination, ins.mnemonic == "jmp")

    def run(self, seed):
        self.seed = seed
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mapped = set()
        self.generated = 0
        self.calls = []
        self.writes = set()
        self.executed = set()
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
        sig = signature(self.symbol)
        if sig:
            for index in sig.pointers:
                self.uc.mem_write(
                    ENTRY_SP + 4 + index * 4,
                    struct.pack(
                        "<I", 0x70000000 + (mix(seed + index + 1) % 256) * PAGE
                    ),
                )
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
        if self.outcome == ["return"]:
            # edx is scratch under Microsoft's conventions unless the result fills edx:eax; with no
            # readable signature it is compared, so an unknown result type cannot hide a difference
            own = signature(self.symbol)
            kept = ("eax", "edx") if own is None or own.wide else ("eax",)
            record["registers"] = {
                r: self.reg(r) for r in (*kept, "esp", "ebx", "esi", "edi", "ebp")
            }
            tags = self.uc.reg_read(x86.UC_X86_REG_FPTAG)
            top = (self.uc.reg_read(x86.UC_X86_REG_FPSW) >> 11) & 7
            record["x87"] = [
                self.uc.reg_read(getattr(x86, f"UC_X86_REG_FP{(top + i) & 7}"))
                for i in range(8)
                if (tags >> (2 * ((top + i) & 7))) & 3 != 3
            ]
            record["x87_depth"] = len(record["x87"])
        return record


def shape(ins):
    """An instruction with branch targets left out, for aligning two builds' code."""
    if ins.group(1) or ins.group(2) or ins.mnemonic.startswith("j"):
        return ins.mnemonic
    return f"{ins.mnemonic} {ins.op_str}"


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


def differing(runners):
    """For each runner, the addresses of its instructions that differ from the other build's code at the same
    fragment: every function both builds define is aligned instruction by instruction."""
    found = [set(), set()]
    codes = [{base: data for base, data, frag in r.loaded if frag.code} for r in runners]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    followed = set.union(*(reachable(r, code) for r, code in zip(runners, codes)))
    for base in codes[0].keys() & codes[1].keys() & followed:
        if codes[0][base] == codes[1][base]:
            continue
        sides = [list(md.disasm(codes[i][base], base)) for i in (0, 1)]
        shapes = [[shape(i) for i in side] for side in sides]
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
    runners = [
        Runner(link, obj, symbol, sorted(constants), limits, shared[index])
        for index, obj in enumerate(objects)
    ]
    differ = 0
    first = None
    outcomes = [Counter(), Counter()]
    targets = differing(runners)
    reaching = exercised = 0
    missed = Counter()
    for case in range(seed, seed + cases):
        records = [runner.run(case) for runner in runners]
        for index, record in enumerate(records):
            outcomes[index].update([record["outcome"][0]])
        if any(runner.executed & target for runner, target in zip(runners, targets)):
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
        if records[0] != records[1]:
            differ += 1
            if first is None:
                categories = [
                    k
                    for k in records[0].keys() | records[1].keys()
                    if records[0].get(k) != records[1].get(k)
                ]
                first = {
                    "seed": case,
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
