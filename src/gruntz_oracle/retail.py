"""Retail data an extracted object only references: the original executable's bytes for a compiler-generated
datum, such as a floating-point constant, which an object compiled from source keeps under another name."""

import csv
import struct
from functools import cache
from pathlib import Path

EXE = "build/exe/GRUNTZ.EXE"
MANIFEST = "build/gen/delink_data_manifest.tsv"


class Image:
    def __init__(self, root: Path):
        data = (root / EXE).read_bytes()
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        count, optional = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        self.data = data
        self.sections = []
        for i in range(count):
            at = pe + 24 + optional + 40 * i
            size, rva, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
            self.sections.append((rva, max(size, raw_size), raw, raw_size))
        # base relocations: every address whose word the loader adjusts, which holds a pointer
        reloc_rva, reloc_size = struct.unpack_from("<II", data, pe + 24 + 96 + 5 * 8)
        self.pointers = set()
        at, end = self.offset(reloc_rva), self.offset(reloc_rva) + reloc_size
        while at < end:
            page, block = struct.unpack_from("<II", data, at)
            if block < 8:
                break
            for k in range(8, block, 2):
                entry = struct.unpack_from("<H", data, at + k)[0]
                if entry >> 12 == 3:
                    self.pointers.add(page + (entry & 0xFFF))
            at += block
        with (root / MANIFEST).open(newline="") as stream:
            self.symbols = {row["name"]: (int(row["rva"], 16), int(row["size"], 16))
                            for row in csv.DictReader(stream, delimiter="\t")}

    def offset(self, rva):
        for start, size, raw, _ in self.sections:
            if start <= rva < start + size:
                return raw + rva - start
        raise ValueError(f"rva {rva:#x} outside the image")

    def bytes(self, name):
        """The datum's bytes when the image has it and they hold no pointer, else None."""
        if name not in self.symbols:
            return None
        rva, size = self.symbols[name]
        if size <= 0 or any(rva - 3 <= p < rva + size for p in self.pointers):
            return None
        for start, extent, raw, raw_size in self.sections:
            if start <= rva and rva + size <= start + extent:
                body = self.data[raw + rva - start : raw + min(rva - start + size, raw_size)]
                return body + bytes(size - len(body))  # past the raw data a section is zero-filled
        return None


@cache
def image(root: Path):
    return Image(root) if (root / EXE).exists() and (root / MANIFEST).exists() else None
