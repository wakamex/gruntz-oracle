# gruntz-oracle

gruntz-oracle checks whether two builds of one function from [gruntz-decomp](https://github.com/sushi-shi/gruntz-decomp) behave the same. A source rewrite can raise a function's byte-match score without reaching an exact match; [concord](https://github.com/wakamex/concord) keeps such a rewrite only when this oracle shows the function's behavior unchanged. It runs both builds' 32-bit x86 machine code with [Unicorn](https://www.unicorn-engine.org/) on the same generated inputs and compares what each does.

It has no false differences on 421 byte-exact functions, catches all 5 seeded bugs in a mutation benchmark, and agrees on 290 of 293 functions whose code differs between two correct builds. The 3 exceptions are floating-point rasterization functions whose results really differ between those builds, described under [limits](#limits).

| Check | What it tests | Result |
| --- | --- | --- |
| Exact functions | Every byte-exact function in 35 units, retail object against reconstructed object, 1,000 cases each | 421 of 421 agree, 0 errors |
| Mutations | 5 behavior changes (changed constant, flipped comparison, dropped store, swapped arguments, off-by-one loop bound) and 3 behavior-preserving rewrites (reordered independent stores, renamed local, named temporary), 5,000 cases each | 5 of 5 changes differ, in 36 to 4,952 cases; 3 of 3 rewrites agree |
| Equivalent builds | Every function whose code differs between the unit compiled for two processors (`-G5` and `-G6`) from one front-end output, 35 units, 500 cases each | 290 of 293 agree; 3 differ |

The tests are chosen to expose the two ways an oracle fails. Byte-exact functions and equivalent builds must agree, so any difference there is a false difference; the equivalent builds also check code that differs, which identical code cannot. The mutations must differ, so a mutation reported as agreeing is a missed difference. Results for this version are in [the evidence](evidence/v-2d977fa).

## Use

Requires Python 3.11 or newer, [uv](https://docs.astral.sh/uv/), and `llvm-undname` from [LLVM](https://llvm.org/), which reads Microsoft symbol decorations.

```sh
uv tool install .
```

From the gruntz-decomp checkout:

```sh
gruntz-oracle check BEFORE.obj AFTER.obj --symbol SYMBOL --unit UNIT --cases 5000 --layouts LAYOUTS.json
```

Each input is an i386 [Common Object File Format (COFF)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) object defining the symbol. The oracle prints one [JavaScript Object Notation (JSON)](https://www.json.org/) line and exits with:

- 0, `"verdict": "agree"`: every case that ran the differing code to completion behaved the same.
- 1, `"verdict": "differ"`: some case behaved differently; `first_difference` gives its seed, input overrides and observations.
- 3, `"verdict": "under-exercised"`: no case ran the differing code to completion, so equivalence is not shown.
- 2: an error, such as a malformed object or a function the linker cannot place.

Only exit 0 shows equivalence. `--layouts` takes the unit's record layouts, which concord produces from the checkout's headers; without it, memory is untyped and fewer cases reach deep code. `--retail CHECKOUT` reads data that a retail object only references, such as a floating-point constant, from the original executable. `--unguided` runs seeds only, `--instructions` (default 20,000) and `--pages` (default 128) set the per-case limits, and `--seed` the first seed.

Concord runs `gruntz-oracle` from `PATH` for a Gruntz target, passing the unit's layouts, and treats exit 1 and 3 alike as a reason to reject a rewrite. `CONCORD_ORACLE` overrides the command; an empty value disables it.

## Inputs

A case starts from a seed. One seed in eight each favors small values, comparison constants from both builds' code, and mostly empty memory, where pages hold either pointers or mostly zero data; the rest are general random words. Generated memory depends only on the seed and the address, so both builds read the same bytes wherever they read.

With layouts, memory is laid out by type. `this` and arguments that point to records point to typed objects whose pointer fields point to typed objects, so a chain such as `this->m_rows[y][x]` is valid without luck. A polymorphic object's vtable pointer points to a typed vtable whose slots stand for its virtual functions, so a call through it knows its callee and signature. Globals that point to records start as typed pointers. Each type has its own range of addresses, so the type of any address follows from the address alone.

Half of each check's cases are guided. Every comparison the two builds make (`cmp`, `test`, and the `sub`, `dec`, `inc` and `and` that switch statements test, and jump-table indexes) is logged with the input word each operand came from: a memory word the function read before writing it, an argument, `ecx`, or a call result. A value computed from an input, such as a message's high word or `msg - 0x110`, is traced to the input field it came from. Cases that reach new code or run a loop a new number of times give rise to cases that set those inputs to take the other side of their comparisons. Inputs are logged in both builds, so code only one build has is reached too.

## Execution

Both objects share one address space: named functions and data by name, unnamed fragments by their contents and relocation positions. A fragment only one object defines is loaded in both. Only fragments the function can reach through its relocations and branches are loaded, the same set in both runs. Code and read-only data cannot be written. Calls to functions the objects define run their bodies; calls elsewhere are boundaries, as is a callee both builds share when a case would otherwise end at the instruction limit inside it.

A boundary records the callee and its stack arguments, and `ecx` when the call takes `this` in it: a `thiscall` callee, or a call through the vtable that `[ecx]` points to. Its stack layout comes from the callee's decorated name, sizing classes passed by value from the layouts, or else from the pushes before the call and the caller's cleanup after it. Its result is generated from the seed, the callee and how many times it has been called.

## Comparison

Each case compares:

- The outcome: return, or fault and the faulting page.
- The result registers the function's declared result uses: `eax` for most, `eax` and `edx` for 64-bit integers and unknown results, the top of the x87 stack for `float` and `double`, `eax` alone for a class returned by value, nothing for `void`. Also `esp` and the callee-saved `ebx`, `esi`, `edi` and `ebp`.
- The ordered boundary calls and their arguments.
- The final value of every byte written outside the function's stack frame and its own parameter slots, which it may use as scratch.

Floating-point values are compared within one millionth, relative, or one billionth, absolute: x87 values on return and values stored with `fst`, `fstp`, or copied from them with string moves. A build that keeps a value in an 80-bit register and one that rounds it to memory are both correct. A pointer into an exception handler stub, which each build lays out differently, is compared as a token, and so is the exception chain head a faulting run leaves pointing into its frame.

A case either build ends at a limit is inconclusive and not compared, since where a cutoff lands depends on how each build orders its work.

## Limits

Agreement on generated cases is evidence, not proof. Boundaries return generated values: they do not allocate, perform operating-system calls, or write through output arguments. Windows exception dispatch is not modeled.

The three equivalent-build differences are in `imagepolyclip`, which rasterizes polygons. In `ProjectWallQuad`, a value that cancels to near zero is -0.00050 in one build and -0.00063 in the other, because the builds spill different intermediates to 32-bit floats; the difference is real, and no tolerance that still catches changed constants covers it. In `ImageRotateBlit`, a float copied through an integer register loses its floating-point marking and is compared exactly. In such cases the oracle errs toward rejecting a rewrite.

## Reproduction

The benchmarks need concord, for compiling and for layouts, and this project, run from `benchmarks/`:

```sh
cd benchmarks
uv run --project ../../concord --with-editable .. python mutations.py --gruntz ../../gruntz-decomp --concord ../../concord --output ../evidence/mutations --cases 5000
uv run --project ../../concord --with-editable .. python exact.py --gruntz ../../gruntz-decomp --concord ../../concord --output ../evidence/exact --cases 1000 --attempt 1 --units $(cat units.txt)
uv run --project ../../concord --with-editable .. python equivalent.py --gruntz ../../gruntz-decomp --concord ../../concord --output ../evidence/equivalent --units $(cat units.txt)
```

`mutations.py --build-only` compiles the mutated sources with the checkout's pinned compiler and records their hashes; `--run-only` measures saved objects after checking those hashes. `exact.py` takes every function with a 100% score in the checkout's `build/objdiff/compare-new/report.json` whose followed callees are exact too. Each benchmark exits nonzero when its gate fails.

## Development checks

```sh
uv run --locked ruff check src tests benchmarks
uv run --locked python -m unittest discover -s tests
```

## License

The oracle code is under the [MIT License](LICENSE). Retained gruntz-decomp source fragments and toolchain-definition excerpts are under upstream's [Creative Commons CC0 1.0 dedication](https://creativecommons.org/publicdomain/zero/1.0/). Generated source files and objects stay local and are not committed.
