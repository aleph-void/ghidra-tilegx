# Credits and provenance

The original TILE-Gx processor module was contributed to Ghidra as
[PR #9426](https://github.com/NationalSecurityAgency/ghidra/pull/9426) by Idan Freiberg
(@speidy), at PR head `6f84e513bf1f135ec7762aba9db5e02d70e7da54`. The contribution is
Apache-2.0 under Ghidra's contribution terms. Its SLEIGH generator originally used the GNU
binutils 2.35.1 TILE-Gx opcode table. The original files and their attribution remain in this
repository's history.

Ghidra-Rare changes on top of the PR:

- Read opcode names, masks and operands from Tilera's public ISA manual (UG401) into a
  tab-separated table and regenerate the language specification. The manual text is not
  redistributed. GNU binutils 2.45 is a test oracle, not a copied source of the generated
  specification.
- Add big-endian data and the `-m32` ABI, ELF opinions, signed `char` and GCC's DWARF register
  map.
- Add the slot decoder comparison, constructor-coverage check, emulator tests and real-binary
  inspection script. `support/tilegx_fp_model.py` explores GCC's floating-point helper sequences;
  its inferences are not hardware validation.
- Add this documentation and release packaging.

The zlib 1.3.1 source used for the real-binary check is by Jean-loup Gailly and Mark Adler;
the resulting test ELFs and that source are not distributed in the extension. GNU binutils and
GCC were used as external reference and compilation tools.
