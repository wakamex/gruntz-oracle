# Writable code pages caused a second false difference

The second gate found one differing seed among 5,000 cases for report-exact `CLevelPlane::SetCell` in `brickzcellflags`. The next completed function, `CVirtBaseList::InsertFirst` in `rezlist`, agreed on all 5,000 cases. The gate was stopped after the second failure, with two of fourteen requested functions completed. No further repair or validation run was attempted.

At seed 841, both identical `SetCell` bodies write the same four-byte value `0x98` to the unaligned address `0x1000025e`, inside the loaded `ComputeCellFlags` function. Their outcomes, return registers and calls agree. The loader maps every page with read, write and execute permissions, so this write to code succeeds instead of faulting.

The surrounding bytes belong to another function whose bodies differ between the two objects:

| Version | Eight bytes at `0x1000025c` before the store | Eight bytes after the identical store |
| --- | --- | --- |
| Retail | `24 10 8b 52 0c 8b da c1` | `24 10 98 00 00 00 da c1` |
| Reconstructed | `0c 8b da c1 e3 03 2b da` | `0c 8b 98 00 00 00 2b da` |

The required final four-byte-word comparison therefore reports different surrounding bytes. This is an emulator memory-permission defect, not an established behavior difference in `SetCell`. The comparison remains intact, and the prototype is not validated for banking partial improvements.

[results.json](results.json) retains both completed results, including the differing records. [summary.json](summary.json) identifies the partial run, stopped function, object report hash and engine source hashes. The simultaneous 5,000-case mutation run was stopped too; its two completed results are in [mutation-partial.json](../mutation-partial.json).
