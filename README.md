# gruntz-oracle

gruntz-oracle compares the behavior of two builds of one function from [gruntz-decomp](https://github.com/sushi-shi/gruntz-decomp). It executes 32-bit x86 machine code with [Unicorn](https://www.unicorn-engine.org/) on identical generated inputs. Its purpose is to check source rewrites that improve a byte match without reaching an exact match.

This is an unvalidated prototype. Two false-difference gates failed, and work stopped at the required limit. Do not use its agreement verdicts to authorize partial source improvements. The implemented concord adapter and tests do not establish the oracle's reliability.

The real-object checks compare every report-exact function in five selected units with its retail counterpart. The mutation checks compare builds of real functions after deliberately changing or preserving their behavior. These tests expose whether the harness invents differences or misses known changes.

| Validation | Completed checks | Result |
| --- | --- | --- |
| First exact-function gate | All 14 functions across 5 units, 256 cases per function | 1 false difference in 1 function, 0 setup errors |
| Second exact-function gate, stopped | 2 of 14 functions across 2 of 5 units, 5,000 cases per completed function | 1 false difference in 1 function, 0 setup errors; full sweep incomplete |
| Mutation screen | 5 changing mutations and 3 preserving rewrites, 128 cases per pair | 4 of 5 detected (80%); 1 off-by-one mutation missed; 0 of 3 preserving false differences (0%) |
| Larger mutation run, stopped | 2 of 5 changing mutations, 5,000 cases per completed pair; no preserving checks completed | Changed constant detected in 4,987 cases; flipped comparison detected in 4,416 cases; remaining checks incomplete |

The first gate's false difference came from loading linker directives as runtime memory. The second came from an identical store into writable code pages whose surrounding bytes differ between builds. These are harness defects, not established behavior changes in the checked functions. The first defect is repaired; the second remains open under the stop limit. Detailed records and diagnoses are in [first-gate evidence](evidence/exact-attempt-1/diagnosis.md), [second-gate evidence](evidence/exact-attempt-2/diagnosis.md), [mutation-screen evidence](evidence/mutation-screen.json), and [partial larger-run evidence](evidence/mutation-partial.json).

Across the first gate's 3,584 cases per build, 2,607 returned and 977 faulted; none reached a limit. In the second gate, `SetCell` returned in 3,693 of 5,000 cases and faulted in 1,307, with one write difference. Its check took 60.88 seconds, exceeding concord's default 60-second process timeout. The timeout is configurable through `CONCORD_ORACLE_TIMEOUT`, but increasing it does not resolve the failed correctness gate.

## Development installation and interface

Requires Python 3.11 or newer, [uv](https://docs.astral.sh/uv/), and `llvm-undname` from [LLVM](https://llvm.org/) for Microsoft symbol signatures.

```sh
uv tool install .
```

From the gruntz-decomp checkout:

```sh
gruntz-oracle check BEFORE.obj AFTER.obj --symbol SYMBOL --unit UNIT --cases 5000
```

Each input is a [Common Object File Format (COFF)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) i386 object. Both objects must define the requested symbol. For supported input it prints one [JavaScript Object Notation (JSON)](https://www.json.org/) line. Exit status 0 means `"verdict": "agree"`, 1 means `"verdict": "differ"`, and another status indicates an error. Malformed or truncated object files can currently raise an uncaught `struct.error` and exit 1 instead of the required error status; this is an unresolved interface defect. An error cannot authorize a rewrite.

Retail and reconstructed objects can be compared directly:

```sh
gruntz-oracle check build/objdiff/compare-new/target/namerecord.c.obj build/objdiff/compare-new/base/namerecord.obj --symbol '?UpdateBestScore@CGameInfo@@QAEHHHH@Z' --unit namerecord --cases 5000
```

[concord](https://github.com/wakamex/concord) selects `gruntz-oracle` from `PATH` for a Gruntz target. `CONCORD_ORACLE` overrides the command; an empty value disables the oracle. Concord invokes the same `check BEFORE.obj AFTER.obj --symbol SYMBOL --unit UNIT --cases N` interface from the target checkout. This interface is implemented for `permute --apply-improved`, but this prototype must remain outside production rewrite approval until its validation gate passes.

## Execution and comparison

The loader gives named code and data symbols common addresses across both objects, applies i386 relocations, and excludes linker-only metadata. Direct calls and tail jumps to functions defined in the same object execute their bodies, including recursive calls. Their calls and writes contribute to the entry function's result, so an outlined helper can agree with its inlined form. Indirect calls remain boundaries even when their destination is a loaded function; indirect jumps within a function can execute switch tables.

A fake thread information block selected by `fs` supports exception-handler prologues. The function receives `this` in `ecx` and arguments on a 32-bit stack. Each case initializes integer registers and the complete x87 register stack. Pointer and scalar inputs depend on the case seed. Generated memory pages depend only on that seed and their address. Writable data receives seeded contents with its relocations preserved; read-only data retains the object's bytes. One input lane favors small integers, and another draws from pooled comparison constants and their neighbors from both objects.

A boundary records the callee, `ecx`, and stack arguments inferred from its decorated name or a recognized call-site cleanup. Its generated return depends on the seed and the boundary call's position. The return goes in `eax`; a known floating return also pushes an x87 value. The stub removes stack arguments for known `stdcall` and `thiscall` callees. Supported primitive pointers into the function's stack compare their pointee bytes and alias relationships, allowing a compiler to move a local without changing its call argument.

Each case compares:

- Return, fault or limit outcome, including the fault address's page.
- `eax`, `edx`, `esp`, and callee-saved `ebx`, `esi`, `edi`, and `ebp` when returning.
- The x87 stack depth and occupied values when returning.
- Ordered boundary calls and their arguments.
- Final values of every aligned four-byte word written outside the function's stack frame, including writes before a fault or limit. Independent stores can change order without changing this result.

The default limits are 20,000 executed instructions and 128 generated memory pages per case. `--instructions` and `--pages` override them. These limits are deterministic; the engine has no wall-clock case timeout. Code pages are currently writable, which causes the second gate failure documented above. Reports include the effective limits, pooled comparison constants, object hashes, each version's outcome counts, and the first differing seed and observations.

## Coverage limits

The environment supplies generated bytes rather than valid game objects, so cases can fault before reaching deeper code. External functions have opaque generated-return stubs: they do not perform allocation, operating-system operations, or writes through output arguments. The fake thread information block supports prologues but does not implement Windows exception dispatch or multithreading. Generated floating boundary returns are finite values derived from signed 32-bit integers; there is no dedicated not-a-number or infinity return lane.

Signature support covers known C routines and supported Microsoft-decorated `cdecl`, `stdcall`, and `thiscall` functions. Unknown calling conventions, unrecognized indirect-call argument layouts, aggregate arguments or returns, variadic signatures, and stack pointers without a supported pointee extent can produce an error. Primitive stack pointee comparisons cover the declared scalar's width; they do not model arbitrarily sized arrays, strings, or object graphs. Linker features outside the supported i386 relocation set and fragments over 64 KiB also produce errors.

Return-register comparison is deliberately strict: `eax` and `edx` are both compared even when the source return type does not use both. Instruction limits can stop differently compiled versions after different amounts of semantic work. The harness reports those observations without discarding call or write differences.

## Benchmark method and reproduction

`benchmarks/exact.py` selects every function with a 100% score in the current `build/objdiff/compare-new/report.json` for five fixed units: `brickzcellflags`, `rezlist`, `namerecord`, `chainforward`, and `brickz`. These include pointer stores, same-object calls, external calls, comparisons, and loops. It compares each retail object with the reconstructed object used by that report. It does not select functions by the oracle's result.

`benchmarks/mutations.py` compiles candidates with `concord.gruntz.Gruntz.evaluate`, using the checkout's pinned Microsoft Visual C++ 5.0 compiler and each unit's configured flags. Compilation uses four workers and source overlays under concord's build directory. It does not edit the target's source. Five behavior-changing mutations cover a changed constant, flipped comparison, dropped store, swapped arguments, and an off-by-one loop bound. Three preserving controls swap independent stores, rename a local, and introduce a named temporary. Expected labels come from the source operations.

Both scripts retain object hashes and detailed results. The mutation build also retains the source hashes, effective flags, toolchain definition and target revision; portable copies are in [build provenance](evidence/build-provenance.json). `--run-only` verifies the saved object hashes before measurement. A benchmark exits nonzero when an error, false difference or missed mutation prevents its gate from passing.

Compile the fixed mutation inputs with concord's dependencies available, then measure them with this project's environment:

```sh
uv run --project ../concord --locked python "$PWD/benchmarks/mutations.py" --gruntz ../gruntz-decomp --concord ../concord --output "$PWD/evidence/mutations" --build-only
uv run --locked python benchmarks/mutations.py --gruntz ../gruntz-decomp --output evidence/mutations --run-only --oracle "$PWD/.venv/bin/gruntz-oracle" --cases 5000
uv run --locked python benchmarks/exact.py --gruntz ../gruntz-decomp --output evidence/exact --oracle "$PWD/.venv/bin/gruntz-oracle" --cases 5000 --attempt 1
```

The fixed mutation collection measures these particular changes; agreement on generated cases is not a proof of equivalence for every possible game state.

## Development checks

```sh
uv run --locked ruff check src tests
uv run --locked python -m unittest discover -s tests
```

## License

The oracle code is under the [MIT License](LICENSE). Retained gruntz-decomp source fragments and toolchain-definition excerpts are under upstream's [Creative Commons CC0 1.0 dedication](https://creativecommons.org/publicdomain/zero/1.0/). Generated source files and objects stay local and are not committed.
