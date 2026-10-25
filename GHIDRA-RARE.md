# Ghidra-Rare verification: TILE-Gx

This is the standalone fork of Ghidra [PR #9426](https://github.com/NationalSecurityAgency/ghidra/pull/9426).
Tests used Ghidra 12.1.4, GNU binutils 2.45, cross-GCC 6.5.0, and zlib 1.3.1.

## Results

| Check | Result |
|---|---|
| Decode corpus | 318,760 bundles checked against GNU libopcodes: 316,258 exact, 2,502 equivalent after normalizing branch targets that binutils truncates to 32 bits, 133,205 rejected by both, zero unexplained differences |
| Constructor coverage | 1,521/1,521 reached by the generated corpus |
| Emulator | 29/29 hand-computed cases in each of four languages; parallel register reads, arithmetic, memory, branches, atomics, SIMD, SPRs and CRC checked |
| Floating-point helper model | 1,000 random GCC helper sequences matched IEEE results in the independent Python model; hardware behavior remains unverified |
| Extension build | Ghidra 12.1.4 extension zip builds with four compiled language files |

Nine zlib 1.3.1 source files (Adler-32, CRC-32, deflate, infback, inffast, inflate,
inftrees, trees and zutil) were cross-compiled with `-DZ_SOLO -ffreestanding -nostdinc -O2 -g`
and linked without unresolved symbols or relocations. Ghidra imported the complete linked ELF,
analysed it, decompiled every function with a 30-second limit, and compared every analysed
bundle with GNU's TILE-Gx slot decoder at the same address.

| ELF variant | Functions decompiled | Analysed bundles | Slot agreement | Bad-instruction / error bookmarks |
|---|---:|---:|---:|---:|
| LE64 | 81/81 | 8,947 | 100% | 0 / 0 |
| BE64 | 81/81 | 8,954 | 100% | 0 / 0 |
| LE32 | 81/81 | 8,758 | 100% | 0 / 0 |
| BE32 | 81/81 | 8,754 | 100% | 0 / 0 |

The 32-bit decompilations sometimes name saved registers `unaff_r*`; one zlib switch produces
an indirect-jump recovery warning. All functions still produce C output. Relocatable objects
import with relocation errors because Ghidra has no TILE-Gx ELF relocation handler; the linked
ELFs above have no relocations.

## Remaining limits

- Several hardware-specific instructions (cache, TLB, network, breakpoints and floating-point
  helper stages) use named user operations. Their effects are not proved against a TILE-Gx
  processor or a full-system simulator.
- The Python floating-point model derives intermediate formats from GCC sequences and the
  public manual; bit-exact results for exceptional values and hardware flags remain unverified.
- `-m32` pointer recovery and switch analysis need more work, despite all functions decompiling.
- TILE-Gx ELF relocations in object files are not applied. Linked executables without remaining
  relocations import and analyse correctly.

## Reproduce

Compile the four `.slaspec` files with Ghidra's `support/sleigh` and link the module into
`Ghidra/Processors/TILE`. `test/tgxslots.c` decodes raw bundles with GNU libopcodes;
`test/compare.py` classifies a Ghidra listing against that output. `test/CoverageCheck.java`
checks constructors; `test/emu_tests.py` and `test/EmuCheck.java` run the emulator cases;
`test/RealCheck.java` produces the real-binary summaries and listings. The zlib source and
cross-toolchain are external test inputs, not part of the extension.
