"""Synthetic assembly assembled as COFF by LLVM's real assembler."""

import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gruntz_oracle.engine import (
    PAGE,
    SPAN,
    TYPED,
    Layouts,
    Limits,
    check,
    owner,
    page_bytes,
)
from gruntz_oracle.signature import signature


@unittest.skipUnless(
    shutil.which("clang") and shutil.which("llvm-undname"), "requires LLVM tools"
)
class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def obj(self, body, extra="", symbol="_entry"):
        self.counter += 1
        source = self.root / f"{self.counter}.s"
        name = f'"{symbol}"'
        source.write_text(
            f".text\n.globl {name}\n.def {name}; .scl 2; .type 32; .endef\n{name}:\n"
            + body
            + "\n"
            + extra
        )
        output = source.with_suffix(".obj")
        subprocess.run(
            [
                "clang",
                "--target=i686-pc-windows-msvc",
                "-c",
                str(source),
                "-o",
                str(output),
            ],
            check=True,
            capture_output=True,
        )
        return output

    def compare(self, before, after, **kwargs):
        return check(before, after, "_entry", cases=4, **kwargs)

    def test_return_and_changed_constant(self):
        before = self.obj("movl $7, %eax\nret")
        same = self.obj("nop\nmovl $7, %eax\nret")
        after = self.obj("movl $8, %eax\nret")
        self.assertEqual(self.compare(before, same)["verdict"], "agree")
        self.assertEqual(self.compare(before, after)["differ"], 4)

    def test_difference_never_reached_is_under_exercised(self):
        # the differing instruction sits after a loop no case leaves within the instruction limit
        before = self.obj("1:\njmp 1b\nmovl $7, %eax\nret")
        after = self.obj("1:\njmp 1b\nmovl $8, %eax\nret")
        result = self.compare(before, after)
        self.assertEqual(result["verdict"], "under-exercised")
        self.assertEqual(result["cases_exercising_difference"], 0)

    def test_runs_cut_off_by_a_limit_are_not_compared(self):
        # the same work in another order: stores cut off at a fixed instruction count differ, results would not
        before = self.obj("1:\nmovl $1, 0x70000000\nmovl $2, 0x70000004\njmp 1b")
        after = self.obj("1:\nmovl $2, 0x70000004\nmovl $1, 0x70000000\njmp 1b")
        result = self.compare(before, after, limits=Limits(instructions=101))
        self.assertEqual(result["verdict"], "under-exercised")
        self.assertEqual(result["cases_inconclusive"], 4)

    def test_parameter_slots_are_scratch(self):
        # ?f@@YAHH@Z takes one int: a store into its slot is dead at return, a store past it is not
        before = self.obj("movl $1, 4(%esp)\nmovl $0, %eax\nret", symbol="?f@@YAHH@Z")
        after = self.obj("movl $2, 4(%esp)\nmovl $0, %eax\nret", symbol="?f@@YAHH@Z")
        self.assertEqual(check(before, after, "?f@@YAHH@Z", cases=4)["verdict"], "agree")
        beyond = self.obj("movl $2, 8(%esp)\nmovl $0, %eax\nret", symbol="?f@@YAHH@Z")
        self.assertEqual(check(before, beyond, "?f@@YAHH@Z", cases=4)["verdict"], "differ")

    def test_void_result_registers_are_not_compared(self):
        before = self.obj("movl $1, %eax\nret", symbol="?f@@YAXH@Z")
        after = self.obj("movl $2, %eax\nret", symbol="?f@@YAXH@Z")
        self.assertEqual(check(before, after, "?f@@YAXH@Z", cases=4)["verdict"], "agree")

    def test_class_result_compares_only_eax(self):
        name = "?f@@YA?AVC@@XZ"
        before = self.obj("movl $1, %eax\nmovl $1, %edx\nret", symbol=name)
        after = self.obj("movl $1, %eax\nmovl $2, %edx\nret", symbol=name)
        self.assertEqual(check(before, after, name, cases=4)["verdict"], "agree")

    def test_handler_chain_left_in_the_frame_is_a_frame_address(self):
        # each build registers a handler record at another frame offset, then faults before unregistering it
        before = self.obj("subl $16, %esp\nmovl %esp, %fs:0\nmovl 0, %eax")
        after = self.obj("subl $32, %esp\nmovl %esp, %fs:0\nmovl 0, %eax")
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_compiler_constants_keep_their_bytes(self):
        # the same constant under two compiler-chosen names reads the same; a changed one does not
        def build(name, value):
            return self.obj(f'movl "{name}", %eax\nret',
                            f'.data\n"{name}":\n.long {value}')
        before, renamed, changed = build("$T100", 7), build("$T200", 7), build("$T200", 8)
        self.assertEqual(self.compare(before, renamed)["verdict"], "agree")
        self.assertEqual(self.compare(before, changed)["verdict"], "differ")

    def test_identical_code_agrees_without_coverage(self):
        obj = self.obj("1:\njmp 1b")
        self.assertEqual(self.compare(obj, obj)["verdict"], "agree")

    def test_reached_equivalent_difference_agrees(self):
        before = self.obj("movl $7, %eax\nret")
        after = self.obj("xorl %eax, %eax\naddl $7, %eax\nret")
        result = self.compare(before, after)
        self.assertEqual(result["verdict"], "agree")
        self.assertEqual(result["cases_exercising_difference"], 4)

    def test_followed_helper_and_inline(self):
        before = self.obj(
            "call _helper\nret",
            ".globl _helper\n.def _helper; .scl 2; .type 32; .endef\n_helper:\nmovl $7, %eax\nret",
        )
        after = self.obj("movl $7, %eax\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_followed_write_is_observed(self):
        before = self.obj(
            "call _helper\nret",
            ".globl _helper\n.def _helper; .scl 2; .type 32; .endef\n_helper:\nmovl $7, (%ecx)\nret",
        )
        after = self.obj("movl $8, (%ecx)\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "differ")

    def test_independent_stores(self):
        before = self.obj("movl $7, (%ecx)\nmovl $8, 4(%ecx)\nret")
        after = self.obj("movl $8, 4(%ecx)\nmovl $7, (%ecx)\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_stack_pop_and_saved_register(self):
        before = self.obj("ret")
        for code in ("ret $4", "xorl %ebx, %ebx\nret"):
            with self.subTest(code=code):
                self.assertEqual(
                    self.compare(before, self.obj(code))["verdict"], "differ"
                )

    def test_x87_values_and_depth(self):
        before = self.obj("fld1\nret")
        for code in ("fldz\nret", "ret"):
            with self.subTest(code=code):
                self.assertEqual(
                    self.compare(before, self.obj(code))["verdict"], "differ"
                )

    def test_external_stdcall_arguments(self):
        before = self.obj('pushl $1\ncall "_outside@4"\nret')
        after = self.obj('pushl $2\ncall "_outside@4"\nret')
        result = self.compare(before, after)
        self.assertEqual(result["verdict"], "differ")
        self.assertEqual(result["outcomes"]["before"], {"return": 4})

    def test_instruction_limit(self):
        obj = self.obj("loop_here:\njmp loop_here")
        report = self.compare(obj, obj, limits=Limits(20, 4))
        self.assertEqual(report["verdict"], "agree")
        self.assertEqual(report["outcomes"]["before"], {"limit": 4})

    def test_fs_thread_block(self):
        before = self.obj("movl %fs:0, %eax\nret")
        after = self.obj("movl $-1, %eax\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_caller_stack_write_is_observed(self):
        before = self.obj("movl $1, 4(%esp)\nret")
        after = self.obj("movl $2, 4(%esp)\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "differ")

    def test_entrypoints(self):
        for command in ([sys.executable, "-m", "gruntz_oracle"], ["gruntz-oracle"]):
            result = subprocess.run(
                [*command, "--help"], capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("check", result.stdout)


class GenerationTests(unittest.TestCase):
    def test_memory_is_address_deterministic(self):
        first = page_bytes(13, 0x70000000)
        page_bytes(13, 0x70001000)
        self.assertEqual(first, page_bytes(13, 0x70000000))
        self.assertNotEqual(first, page_bytes(14, 0x70000000))

    def test_typed_memory_follows_pointer_fields(self):
        layouts = Layouts({
            "Map": {"size": 12, "pointers": [[8, "*Cell"]]},
            "Cell": {"size": 28, "pointers": [[24, "Node"]]},
            "Node": {"size": 8, "pointers": []},
        })
        seed = 2  # an empty-memory lane, whose typed pointers are never null

        def at(address):  # a word of typed memory, which may cross a page
            page = address & -PAGE
            both = layouts.page(seed, page, ()) + layouts.page(seed, page + PAGE, ())
            return struct.unpack_from("<I", both, address - page)[0]

        start = layouts.pointer(seed, 0x1000, "Map")
        rows = at(start + 8)
        self.assertEqual((rows - TYPED) // SPAN, layouts.ids["*Cell"])
        row = at(rows)
        self.assertEqual((row - TYPED) // SPAN, layouts.ids["Cell"])
        self.assertEqual((row - TYPED) % SPAN % 28, 0)  # at an element boundary
        self.assertEqual((at(row + 24) - TYPED) // SPAN, layouts.ids["Node"])

    def test_member_function_owner(self):
        self.assertEqual(owner("?LineIsClear@CMapMgr@@QAEHHHHH@Z"), "CMapMgr")
        self.assertEqual(owner("??_GCMapMgr@@UAEPAXI@Z"), "CMapMgr")
        self.assertEqual(owner("?A@In@Out@@QAEXXZ"), "Out::In")
        self.assertIsNone(owner("?f@@YAHH@Z"))

    def test_demangled_widths(self):
        self.assertEqual(signature("?SetNames@CGameInfo@@QAEHPAD0H@Z").words, 3)
        self.assertEqual(signature("?SetNames@CGameInfo@@QAEHPAD0H@Z").pop, 12)
        self.assertEqual(signature("_outside@8").pop, 8)


@unittest.skipUnless(
    shutil.which("clang") and shutil.which("llvm-undname"), "requires LLVM tools"
)
class BoundaryTests(EngineTests):
    def test_indirect_defined_function_is_boundary(self):
        before = self.obj(
            'movl $"_helper@0", %eax\ncall *%eax\nret',
            '.globl "_helper@0"\n.def "_helper@0"; .scl 2; .type 32; .endef\n"_helper@0":\nmovl $7, %eax\nret',
        )
        after = self.obj(
            'movl $"_helper@0", %eax\ncall *%eax\nret',
            '.globl "_helper@0"\n.def "_helper@0"; .scl 2; .type 32; .endef\n"_helper@0":\nmovl $8, %eax\nret',
        )
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_generated_memory_call_is_boundary(self):
        obj = self.obj(
            "pushl $1\nmovl $0x70000000, %eax\ncall *%eax\naddl $4, %esp\nret"
        )
        result = self.compare(obj, obj)
        self.assertEqual(result["outcomes"]["before"], {"return": 4})

    def test_float_boundary_pushes_x87(self):
        before = self.obj('call "?outside@@YAMXZ"\nret')
        after = self.obj('call "?outside@@YAMXZ"\nfstp %st(0)\nret')
        result = self.compare(before, after)
        self.assertEqual(result["verdict"], "differ")
        self.assertEqual(result["first_difference"]["before"]["x87_depth"], 1)

    def test_tail_followed_helper(self):
        before = self.obj(
            "jmp _helper",
            ".globl _helper\n.def _helper; .scl 2; .type 32; .endef\n_helper:\nmovl $7, %eax\nret",
        )
        after = self.obj("movl $7, %eax\nret")
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_mixed_width_signature(self):
        sig = signature("?outside@@YANHN@Z")
        self.assertEqual(sig.words, 3)
        self.assertTrue(sig.floating)

    def test_inlining_local_pointer_boundary(self):
        body = 'subl $4, %esp\nmovl $7, (%esp)\nleal (%esp), %eax\npushl %eax\ncall "?outside@@YAXPAH@Z"\naddl $8, %esp\nret'
        before = self.obj(
            "call _helper\nret",
            ".globl _helper\n.def _helper; .scl 2; .type 32; .endef\n_helper:\n" + body,
        )
        after = self.obj(body)
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_stack_pointer_aliasing(self):
        prefix = "subl $8, %esp\nmovl $7, (%esp)\nmovl $7, 4(%esp)\nleal (%esp), %eax\n"
        suffix = 'pushl %eax\ncall "?outside@@YAXPAH0@Z"\naddl $16, %esp\nret'
        before = self.obj(prefix + "pushl %eax\n" + suffix)
        after = self.obj(prefix + "leal 4(%esp), %edx\npushl %edx\n" + suffix)
        self.assertEqual(self.compare(before, after)["verdict"], "differ")

    def test_hook_side_read_page_limit(self):
        obj = self.obj("movl 0x70000000, %eax\ncall *0x70001000\naddl $4, %esp\nret")
        result = self.compare(obj, obj, limits=Limits(100, 1))
        self.assertEqual(result["outcomes"]["before"], {"limit": 4})

    def test_named_mutable_data_relocation(self):
        data = ".data\n.globl _value\n_value:\n.long 0\n.globl _pointer\n_pointer:\n.long _value"
        before = self.obj("movl _pointer, %eax\nmovl (%eax), %eax\nret", data)
        after = self.obj("movl _value, %eax\nret", data)
        self.assertEqual(self.compare(before, after)["verdict"], "agree")

    def test_linker_directives_are_not_runtime_memory(self):
        body = "movl 0x3000002c, %eax\nret"
        before = self.obj(body)
        after = self.obj(
            body,
            '.section .drectve,"yn"\n.ascii " /defaultlib:example-library-that-must-never-be-mapped "',
        )
        self.assertEqual(self.compare(before, after)["verdict"], "agree")
