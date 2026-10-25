# TILE-Gx processor

This module loads TILE-Gx ELF files and disassembles the processor's 64-bit bundles.

| Language | Data byte order | ABI |
|---|---|---|
| `TILE:LE:64:default` | little | 64-bit pointers and `long` |
| `TILE:BE:64:default` | big | 64-bit pointers and `long` |
| `TILE:LE:32:default` | little | 32-bit pointers and `long` |
| `TILE:BE:32:default` | big | 32-bit pointers and `long` |

Instruction bundles retain their little-endian byte layout in all four languages. The ELF
machine number is 191 (`EM_TILEGX`).

Each 64-bit bundle decodes as either two X-pipeline operations or three
Y-pipeline operations. P-code reads all source registers before committing any
slot's destination and defers control flow until the complete bundle executes.
Scalar, memory, control-flow, atomic, multiplication, CRC, and selected SIMD
operations have native p-code. Instructions whose hardware behavior is not yet
modeled use mnemonic-specific user-ops.

The language specifications are generated from instruction fields in Tilera's ISA manual
(UG401) by `support/generate_tilegx_sleigh.py`. `GHIDRA-RARE.md` gives the decode, emulator,
and real-binary results and remaining limits. `CREDITS.md` records the original Ghidra pull
request and the changes made here.

Build with Ghidra's `buildExtension` after compiling all four `.slaspec` files, or use
Ghidra-Rare's `tools/build-module.sh --standard --name TILE`. The `test/` directory holds the
slot comparator, emulator checks, constructor coverage check, and real-binary inspection script.
