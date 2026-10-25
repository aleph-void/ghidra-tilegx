#!/usr/bin/env python3
"""P-code semantic tests for the TILE-Gx module, run in Ghidra's emulator by EmuCheck.java.

  emu_tests.py <outdir> [--break NAME]  -> emu.s, emu.bin (tilegx-linux-gnu-as / ld), emu.txt

Each test is a short sequence of bundles at its own label, assembled at address 0. emu.txt has one
line per test:
  <name> <start-hex> <stop-hex> <init: key=val,...|-> <expect: key=val,...>
Keys are register names (r0-r52, tp, sp, lr) or m1:/m2:/m4:/m8:<addr> for memory (the language's
byte order). Values are hex. Before every test r0-r52, lr and tp are 0 and sp is 0x8000.
Expected values were worked out by hand from Tilera UG401 (TILE-Gx Instruction Set Architecture).
A line in braces is one bundle; any other line is assembled as a bundle on its own. An optional
fifth element overrides expectations for the big-endian languages (--big-endian writes emu.txt for
those; bundles are little-endian in both, so emu.bin is the same).
--break NAME makes that test's first expectation wrong, to show the harness can fail.
Environment: TILEGX_AS, TILEGX_LD, TILEGX_OBJCOPY (default tilegx-linux-gnu-as/-ld/-objcopy).
"""
import os
import subprocess
import sys

M = 0xffffffffffffffff

TESTS = [
    # constants: moveli sign-extends Imm16, shl16insli shifts in 16 more bits
    ("move_imm", ["moveli r1, 0x1234", "shl16insli r1, r1, 0x5678", "movei r2, -1",
                  "moveli r3, -2", "shl16insli r4, zero, -32768"], {},
     {"r1": 0x12345678, "r2": M, "r3": 0xfffffffffffffffe, "r4": 0x8000}),
    ("add_sub", ["add r3, r1, r2", "sub r4, r1, r2", "addi r5, r1, -6", "addli r6, r1, 0x7ff0"],
     {"r1": 5, "r2": 7}, {"r3": 12, "r4": 0xfffffffffffffffe, "r5": M, "r6": 0x7ff5}),
    # 32-bit ops sign-extend their 32-bit result; addxsc saturates
    ("addx_32bit", ["addx r3, r1, r2", "addxsc r4, r1, r2", "subx r5, r6, r2", "addxi r7, r1, 1"],
     {"r1": 0x7fffffff, "r2": 1, "r6": 0x100000000},
     {"r3": 0xffffffff80000000, "r4": 0x7fffffff, "r5": M, "r7": 0xffffffff80000000}),
    ("logic", ["and r3, r1, r2", "or r4, r1, r2", "xor r5, r1, r2", "nor r6, r1, r2", "andi r7, r1, -16"],
     {"r1": 0xff00ff00ff00ff0f, "r2": 0x0ff00ff00ff00ff0},
     {"r3": 0x0f000f000f000f00, "r4": 0xfff0fff0fff0ffff, "r5": 0xf0f0f0f0f0f0f0ff,
      "r6": 0x000f000f000f0000, "r7": 0xff00ff00ff00ff00}),
    # every slot reads its sources before any slot writes: one bundle swaps two registers
    ("bundle_swap", ["{ move r1, r2 ; move r2, r1 }"], {"r1": 1, "r2": 2}, {"r1": 2, "r2": 1}),
    ("ybundle_three_slots", ["{ add r1, r2, r3 ; addi r4, r1, 1 ; ld r5, r6 }"],
     {"r1": 100, "r2": 1, "r3": 2, "r6": 0x1000, "m8:1000": 0x55},
     {"r1": 3, "r4": 101, "r5": 0x55}),
    # r63 reads as zero and writes to it are discarded
    ("zero_register", ["add zero, r1, r1", "add r3, zero, r1", "move r4, zero"],
     {"r1": 9, "r4": 7}, {"r3": 9, "r4": 0}),
    ("compare", ["cmpltu r3, r1, r2", "cmplts r4, r1, r2", "cmpeqi r5, r1, -1", "cmpne r6, r1, r2",
                 "cmpleu r7, r2, r2"], {"r1": M, "r2": 1},
     {"r3": 0, "r4": 1, "r5": 1, "r6": 1, "r7": 1}),
    ("shifts", ["shli r3, r1, 4", "shrui r4, r1, 60", "shrsi r5, r1, 60", "shl r6, r2, r7",
                "rotli r8, r1, 4", "shlxi r9, r2, 31"],
     {"r1": 0xf000000000000001, "r2": 1, "r7": 65},
     {"r3": 0x10, "r4": 0xf, "r5": M, "r6": 2, "r8": 0x000000000000001f, "r9": 0xffffffff80000000}),
    ("multiply", ["mul_ls_ls r3, r1, r2", "mulx r4, r1, r2", "mula_lu_lu r5, r1, r2",
                  "mul_hu_lu r6, r7, r2"],
     {"r1": 0xffffffff, "r2": 3, "r5": 10, "r7": 0x500000000},
     {"r3": 0xfffffffffffffffd, "r4": 0xfffffffffffffffd, "r5": 0x300000007, "r6": 15}),
    ("bitfield", ["bfextu r3, r1, 4, 11", "bfexts r4, r2, 8, 15", "bfins r5, r6, 8, 15"],
     {"r1": 0x1234, "r2": 0x8000, "r5": 0xffff, "r6": 0xab},
     {"r3": 0x23, "r4": 0xffffffffffffff80, "r5": 0xabff}),
    ("count_bits", ["clz r3, r1", "ctz r4, r1", "pcnt r5, r1", "revbytes r6, r2"],
     {"r1": 0x0000100000000100, "r2": 0x0102030405060708},
     {"r3": 19, "r4": 8, "r5": 2, "r6": 0x0807060504030201}),
    ("loads", ["ld r2, r1", "ld1s r3, r1", "addi r4, r1, 7", "ld1s r5, r4", "ld1u r6, r4",
               "addi r9, r1, 6", "ld2s r7, r9", "ld4u r8, r1", "ld4s r10, r11"],
     {"r1": 0x1000, "m8:1000": 0x8877665544332211, "r11": 0x1004},
     {"r2": 0x8877665544332211, "r3": 0x11, "r5": 0xffffffffffffff88, "r6": 0x88,
      "r7": 0xffffffffffff8877, "r8": 0x44332211, "r10": 0xffffffff88776655},
     {"r3": 0xffffffffffffff88, "r5": 0x11, "r6": 0x11, "r7": 0x2211, "r8": 0x88776655, "r10": 0x44332211}),
    ("stores", ["st4 r1, r2", "addi r3, r1, 4", "st1 r3, r2", "addi r4, r1, 6", "st2 r4, r5"],
     {"r1": 0x2000, "r2": 0x1122334455667788, "r5": 0xabcd},
     {"m8:2000": 0xabcd008855667788}, {"m8:2000": 0x556677888800abcd}),
    # post-increment forms update the address register after the access
    ("post_increment", ["st_add r1, r2, 8", "st_add r1, r3, 8", "ld_add r4, r5, -8", "ld4u_add r6, r5, 4"],
     {"r1": 0x3000, "r2": 0x1111, "r3": 0x2222, "r5": 0x3008},
     {"r1": 0x3010, "m8:3000": 0x1111, "m8:3008": 0x2222, "r4": 0x2222, "r5": 0x3004, "r6": 0x1111},
     {"r6": 0}),
    ("ldna_aligns", ["ldna r2, r1"], {"r1": 0x3005, "m8:3000": 0x0123456789abcdef},
     {"r2": 0x0123456789abcdef}),
    ("branch_taken", ["movei r2, 1", "beqz r1, 1f", "movei r2, 2", "1:"], {"r1": 0}, {"r2": 1}),
    ("branch_not_taken", ["movei r2, 1", "bnez r1, 1f", "movei r2, 2", "1:"], {"r1": 0}, {"r2": 2}),
    ("branch_signed", ["movei r2, 1", "bgtz r1, 1f", "movei r2, 2", "1:", "blbs r3, 2f", "movei r4, 5", "2:"],
     {"r1": 0x8000000000000000, "r3": 3}, {"r2": 2, "r4": 0}),
    # the other slots of a bundle execute before its branch
    ("branch_with_slot", ["{ addi r2, r2, 1 ; bnez r1, 1f }", "movei r2, 9", "1:"],
     {"r1": 1, "r2": 4}, {"r2": 5}),
    ("call_return", ["jal 9f", "addi r3, r3, 1", "j 8f", "9:", "movei r3, 10", "jr lr", "8:"], {},
     {"r3": 11, "lr": "@+8"}),
    ("jalr_lnk", ["moveli r5, hw0_last(9f)", "jalr r5", "lnk r6", "j 8f", "9:", "move r7, lr", "jrp lr", "8:"], {},
     {"r7": "@+8", "r6": "@+16"}),
    ("cmpexch", ["mtspr CMPEXCH_VALUE, r2", "cmpexch r3, r1, r4", "cmpexch r5, r6, r4"],
     {"r1": 0x4000, "m8:4000": 7, "r2": 7, "r4": 99, "r6": 0x4008, "m8:4008": 8},
     {"r3": 7, "m8:4000": 99, "r5": 8, "m8:4008": 8}),
    ("fetch_ops", ["fetchadd4 r3, r1, r2", "fetchor r4, r5, r6", "exch r7, r8, r9", "fetchaddgez r10, r11, r12"],
     {"r1": 0x4000, "m4:4000": 0x7fffffff, "r2": 1, "r5": 0x4008, "m8:4008": 0xf0, "r6": 0x0f,
      "r8": 0x4010, "m8:4010": 0x55, "r9": 0x66, "r11": 0x4018, "m8:4018": 3, "r12": 0xfffffffffffffffc},
     {"r3": 0x7fffffff, "m4:4000": 0x80000000, "r4": 0xf0, "m8:4008": 0xff, "r7": 0x55, "m8:4010": 0x66,
      "r10": 3, "m8:4018": 3}),
    ("simd", ["v1add r3, r1, r2", "v1adduc r4, r5, r6", "v4int_l r7, r1, r2", "v1cmpeqi r8, r9, 7"],
     {"r1": 0x0102030405060708, "r2": 0xff01ff01ff01ff01, "r5": 0xfff0000180007fff,
      "r6": 0x0020000180000001, "r9": 0x0700070007000700},
     {"r3": 0x0003020504070609, "r4": 0xffff0002ff007fff, "r7": 0x05060708ff01ff01,
      "r8": 0x0100010001000100}),
    ("conditional_move", ["cmovnez r3, r1, r2", "cmoveqz r4, r1, r2", "mnz r5, r6, r2"],
     {"r1": 0, "r2": 0x77, "r3": 5, "r4": 6, "r6": 1}, {"r3": 5, "r4": 0x77, "r5": 0x77}),
    ("spr", ["mtspr SYSTEM_SAVE_0_0, r1", "mfspr r2, SYSTEM_SAVE_0_0"], {"r1": 0xdeadbeef}, {"r2": 0xdeadbeef}),
    ("crc32", ["crc32_8 r3, r1, r2"], {"r1": 0xffffffff, "r2": 0x61}, {"r3": 0x174841bc}),
    ("dblalign", ["dblalign r3, r1, r2"],
     {"r3": 0x0807060504030201, "r1": 0x100f0e0d0c0b0a09, "r2": 0x1003},
     {"r3": 0x0b0a090807060504}, {"r3": 0x0504030201100f0e}),
]


def main():
    out = sys.argv[1]
    brk = sys.argv[sys.argv.index("--break") + 1] if "--break" in sys.argv else None
    big = "--big-endian" in sys.argv
    asm = ["\t.text", "\t.globl _start", "_start:"]
    for name, code, init, expect, *_ in TESTS:
        asm.append(f"t_{name}:")
        for line in code:
            if line.endswith(":"):
                asm.append(line)
            elif line.startswith("{"):
                asm.append("\t" + line)
            else:
                asm.append("\t{ " + line + " }")
        asm.append(f"e_{name}:")
        asm.append("\t{ nop }")
    asm.append("")
    s = os.path.join(out, "emu.s")
    open(s, "w").write("\n".join(asm))
    tool = lambda n, d: os.environ.get(n, d)
    subprocess.run([tool("TILEGX_AS", "tilegx-linux-gnu-as"), "-o", os.path.join(out, "emu.o"), s], check=True)
    subprocess.run([tool("TILEGX_LD", "tilegx-linux-gnu-ld"), "-Ttext=0", "-e", "0", "-o",
                    os.path.join(out, "emu.elf"), os.path.join(out, "emu.o")], check=True)
    subprocess.run([tool("TILEGX_OBJCOPY", "tilegx-linux-gnu-objcopy"), "-O", "binary", "-j", ".text",
                    os.path.join(out, "emu.elf"), os.path.join(out, "emu.bin")], check=True)
    nm = subprocess.run([tool("TILEGX_NM", "tilegx-linux-gnu-nm"), os.path.join(out, "emu.elf")],
                        check=True, capture_output=True, text=True).stdout
    sym = {}
    for line in nm.splitlines():
        p = line.split()
        if len(p) == 3:
            sym[p[2]] = int(p[0], 16)
    lines = []
    for name, code, init, expect, *be in TESTS:
        if big and be:
            expect = {**expect, **be[0]}
        start, stop = sym[f"t_{name}"], sym[f"e_{name}"]
        exp = {}
        for k, v in expect.items():
            if isinstance(v, str):          # "@+n": the address of the test's first jal/jalr bundle + n
                first_call = start + 8 * next(i for i, c in enumerate(x for x in code if not x.endswith(":"))
                                              if c.split()[0] in ("jal", "jalr"))
                v = first_call + int(v[2:])
            exp[k] = v
        if name == brk:
            k = next(iter(exp))
            exp[k] ^= 1
        ini = ",".join(f"{k}={v:x}" for k, v in init.items()) or "-"
        lines.append(f"{name} {start:x} {stop:x} {ini} " + ",".join(f"{k}={v:x}" for k, v in exp.items()))
    open(os.path.join(out, "emu_be.txt" if big else "emu.txt"), "w").write("\n".join(lines) + "\n")
    print(f"{len(TESTS)} tests")


if __name__ == "__main__":
    main()
