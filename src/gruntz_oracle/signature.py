"""Calling conventions and stack widths from Microsoft's symbol decoration."""

import re
import subprocess
from dataclasses import dataclass
from functools import cache


@dataclass(frozen=True)
class Signature:
    words: int
    pop: int
    floating: bool = False
    pointers: tuple[int, ...] = ()
    pointees: tuple[tuple[int, int], ...] = ()
    wide: bool = False  # the result fills edx:eax, so edx is part of it
    thiscall: bool = False  # ecx carries this; for any other convention ecx is scratch at the call
    records: tuple[tuple[int, str], ...] = ()  # stack word and record name of each pointer-to-record argument


C_SIGNATURES = {
    "_memcpy": 3,
    "_memmove": 3,
    "_memset": 3,
    "_memcmp": 3,
    "_strlen": 1,
    "_strcpy": 2,
    "_strncpy": 3,
    "_strcmp": 2,
    "_strncmp": 3,
    "_malloc": 1,
    "_calloc": 2,
    "_realloc": 2,
    "_free": 1,
    "__ftol": 0,
    "__allmul": 4,
    "__alldiv": 4,
    "__aulldiv": 4,
}


def split_arguments(text):
    depth = 0
    start = 0
    args = []
    for i, char in enumerate(text):
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    args.append(text[start:].strip())
    return args


@cache
def result_type(name):
    """The result type a decorated function name declares, or None; readable even where the arguments are
    not, such as a class passed by value."""
    if not name.startswith("?"):
        return None
    result = subprocess.run(["llvm-undname", name], capture_output=True, text=True, check=False)
    lines = result.stdout.strip().splitlines()
    if result.returncode or len(lines) < 2:
        return None
    match = re.search(r"__(cdecl|stdcall|thiscall|fastcall) ", lines[1])
    if not match:
        return None
    return re.sub(r"^(public|private|protected): |\b(static|virtual) ", "", lines[1][: match.start()]).strip()


def void_result(name):
    """Whether the function returns nothing, so no register holds a result."""
    return result_type(name) == "void"


def record_result(name):
    """Whether the function returns a class by value, through a result address the caller passes."""
    kind = result_type(name) or ""
    return bool(re.match(r"(const )?(class|struct|union) ", kind)) and not any(c in kind for c in "*&")


@cache
def signature(name):
    name = name.removeprefix("__imp_")
    if name in C_SIGNATURES:
        return Signature(C_SIGNATURES[name], 0)
    stdcall = re.fullmatch(r"_[^@]+@(\d+)", name)
    if stdcall:
        size = int(stdcall[1])
        return Signature(size // 4, size)
    if not name.startswith("?"):
        return None
    result = subprocess.run(
        ["llvm-undname", name], capture_output=True, text=True, check=False
    )
    lines = result.stdout.strip().splitlines()
    if result.returncode or len(lines) < 2:
        return None
    declaration = lines[1]
    match = re.search(r"__(cdecl|stdcall|thiscall|fastcall) ", declaration)
    if not match or match[1] == "fastcall":
        return None
    returns = declaration[: match.start()]
    if re.search(r"\b(class|struct|union)\b", returns) and not any(
        c in returns for c in "*&"
    ):
        return None
    open_paren = declaration.find("(", match.end())
    if open_paren < 0:
        return None
    args = split_arguments(declaration[open_paren + 1 : declaration.rfind(")")])
    if args == ["void"] or args == [""]:
        args = []
    words = 0
    pointers = []
    pointees = []
    records = []
    for arg in args:
        if arg == "...":
            return None
        pointer = "*" in arg or "&" in arg
        if pointer:
            pointers.append(words)
            named = re.fullmatch(r"(?:const |volatile )*(?:class|struct|union) ([\w:<>, ]+?) *[*&]", arg.strip())
            if named:
                records.append((words, named[1].strip()))
            primitive = re.sub(r"\b(const|volatile|signed|unsigned)\b", "", arg)
            primitive = primitive.replace("*", "").replace("&", "").strip()
            widths = {
                "char": 1,
                "bool": 1,
                "short": 2,
                "int": 4,
                "long": 4,
                "float": 4,
                "double": 8,
                "__int64": 8,
            }
            if arg.count("*") + arg.count("&") == 1 and primitive in widths:
                pointees.append((words, widths[primitive]))
        elif arg.startswith(("class ", "struct ", "union ")):
            return None
        words += 2 if not pointer and ("double" in arg or "__int64" in arg) else 1
    floating = bool(re.search(r"\b(float|double)\s*$", returns))
    wide = bool(re.search(r"\b__int64\s*$", returns))
    return Signature(
        words,
        4 * words if match[1] in ("stdcall", "thiscall") else 0,
        floating,
        tuple(pointers),
        tuple(pointees),
        wide,
        match[1] == "thiscall",
        tuple(records),
    )
