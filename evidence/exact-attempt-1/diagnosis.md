# Linker directives caused a spurious call argument difference

The 256-case check of 14 report-exact functions found one differing case, seed 246 in `SaveBackBufferShot` from `chainforward`. Its retail and reconstructed function bytes and relocation target are identical. Both executions return with identical checked registers, but the first `SaveScreenshot` stack argument differs.

The pointer chain starts with the generated owner argument at `0x70011000`:

| Read address | Generated value |
| --- | --- |
| `0x70011030` | `0x700e7000` |
| `0x700e7004` | `0xbc59d2ee` |
| `0xbc59d302` | `0x30000000` |
| `0x3000002c` | `0x70006000` |

The reconstructed object's `.drectve` section was mapped at `0x30000000`; the retail object has no corresponding section. Its linker directive bytes replace the generated value at `0x3000002c` with `0x642d2062`. This is loader behavior, not a change to the function. Sections with `IMAGE_SCN_LNK_INFO` or `IMAGE_SCN_LNK_REMOVE` describe linker input and must not occupy runtime memory.

The full records and engine source hashes are in [results.json](results.json) and [summary.json](summary.json). No comparison fields were removed to diagnose this difference.
