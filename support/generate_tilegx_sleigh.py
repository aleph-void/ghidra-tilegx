#!/usr/bin/env python3
# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Generate the TILE-Gx SLEIGH specifications.

    generate_tilegx_sleigh.py [languages-dir]

Reads tilegx_isa.tsv and tilegx_sprs.tsv (next to this script; ug401_extract.py makes them from
Tilera's ISA manual) and writes one .slaspec per variant:

    TILE_le.slaspec    little-endian, 64-bit addresses   TILE:LE:64:default
    TILE_be.slaspec    big-endian data, 64-bit addresses TILE:BE:64:default
    TILE_le32.slaspec  little-endian, -m32 ABI           TILE:LE:32:default
    TILE_be32.slaspec  big-endian data, -m32 ABI         TILE:BE:32:default

Bundles are always stored little-endian; the endianness of a TILE-Gx process applies to data.
A whole 64-bit bundle is one Ghidra instruction: every slot reads its sources before any slot
writes its destination (destinations go to shadow registers that the COMMIT section copies back),
and control flow runs last (FLOW section). Semantics follow the manual's functional descriptions.

The bundle-level design, the shadow-register commit and many semantic helpers come from the
original pull request (NationalSecurityAgency/ghidra#9426, Idan Freiberg); this version reads the
instruction table from the manual instead of GNU binutils and adds the remaining semantics.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ug401_extract import FIELDS  # noqa: E402

HERE = Path(__file__).resolve().parent
PIPES = ("X0", "X1", "Y0", "Y1", "Y2")
REGISTER_NAMES = ([f"r{i}" for i in range(53)] +
                  ["tp", "sp", "lr", "sn", "idn0", "idn1", "udn0", "udn1", "udn2", "udn3", "zero"])
REGISTER_FIELDS = [f for f in FIELDS if f.rsplit("_", 1)[0] in ("Dest", "SrcA", "SrcB", "SrcBDest")]
SIGNED_FIELDS = {"Imm8", "Imm16", "BrOff", "JumpOff", "Dest_Imm8"}
SPR_BASE = 0x10000          # register-space offset of SPR 0; SPR n is at SPR_BASE + 8 * n
VARIANTS = {
    "TILE_le": ("little", 8),
    "TILE_be": ("big", 8),
    "TILE_le32": ("little", 4),
    "TILE_be32": ("big", 4),
}
# Instructions that read their destination register (the manual's functional descriptions).
READS_DEST = {
    "dblalign", "shufflebytes", "fdouble_addsub", "fdouble_pack2", "fsingle_addsub2", "bfins",
    "cmoveqz", "cmovnez", "mm", "tblidxb0", "tblidxb1", "tblidxb2", "tblidxb3", "cmula", "cmulaf",
    "mula_hs_hs", "mula_hs_hu", "mula_hs_ls", "mula_hs_lu", "mula_hu_hu", "mula_hu_ls",
    "mula_hu_lu", "mula_ls_ls", "mula_ls_lu", "mula_lu_lu", "mulax", "v1ddotpua", "v1ddotpusa",
    "v1dotpa", "v1dotpua", "v1dotpusa", "v1sadau", "v2dotpa", "v2sadas", "v2sadau",
}
# The FP helper instructions' internal formats are not documented (UG401 names opaque helper
# functions only) and no reference implementation exists; they stay user-ops with full data flow.
FP_HELPERS = {
    "fdouble_add_flags", "fdouble_addsub", "fdouble_mul_flags", "fdouble_pack1", "fdouble_pack2",
    "fdouble_sub_flags", "fdouble_unpack_max", "fdouble_unpack_min", "fsingle_add1",
    "fsingle_addsub2", "fsingle_mul1", "fsingle_mul2", "fsingle_pack1", "fsingle_pack2",
    "fsingle_sub1",
}
# Cache, TLB, memory-ordering and wait operations: no architectural register or memory effect.
SYSTEM_OPS = {"mf": [], "drain": [], "flushwb": [], "nap": [], "finv": ["SrcA"], "flush": ["SrcA"],
              "inv": ["SrcA"], "icoh": ["SrcA"], "wh64": ["SrcA"], "dtlbpr": ["SrcA"]}


def load_isa():
    rows = []
    for line in open(HERE / "tilegx_isa.tsv"):
        if line.startswith("#"):
            continue
        pipe, mn, mask, value, ops, page = line.rstrip("\n").split("\t")
        operands = [] if ops == "-" else [tuple(o.split("=")) for o in ops.split(",")]
        rows.append((pipe, mn, int(mask, 16), int(value, 16), tuple(operands)))
    return rows


def load_sprs():
    sprs = []
    for line in open(HERE / "tilegx_sprs.tsv"):
        if not line.startswith("#"):
            num, name = line.split()
            sprs.append((int(num, 16), name))
    return sprs


def mask_runs(mask):
    bit = 0
    while bit < 64:
        if not (mask >> bit) & 1:
            bit += 1
            continue
        low = bit
        while bit + 1 < 64 and (mask >> (bit + 1)) & 1:
            bit += 1
        yield low, bit
        bit += 1


def fixed_term(low, high, value, op="="):
    width = high - low + 1
    return f"m_{low:02d}_{high:02d}{op}0x{(value >> low) & ((1 << width) - 1):x}"


def prioritize(rows):
    # Within a pipe, more specific encodings first; a less specific overlapping encoding excludes
    # the more specific one's extra fixed bits (SLEIGH needs disjoint or nested patterns).
    exclusions = {}
    ordered = []
    for pipe in PIPES:
        pipe_rows = sorted((r for r in rows if r[0] == pipe), key=lambda r: (-bin(r[2]).count("1"), r[1]))
        for i, row in enumerate(pipe_rows):
            ex = []
            for hi in pipe_rows[:i]:
                common = row[2] & hi[2]
                if (row[3] & common) != (hi[3] & common):
                    continue
                extra = hi[2] & ~row[2]
                if extra:
                    ex.append((extra, hi[3]))
            exclusions[row] = ex
            ordered.append(row)
    return ordered, exclusions


# ---------------------------------------------------------------------------------------------
# Operand symbols

def lower(field):
    return field.lower()


class Ctx:
    def __init__(self, endian, addr):
        self.endian = endian
        self.addr = addr

    def ea(self, expr, name="addr"):
        if self.addr == 8:
            return f"local {name}:8 = {expr};"
        return f"local {name}_full:8 = {expr}; local {name}:4 = {name}_full:4;"


def operand_symbols(mn, operands):
    """role -> symbol for the constructor body and display, plus the display list."""
    syms, display = {}, []
    for role, field in operands:
        if field.startswith("#"):
            display.append(f'"{field[1:]}"')
            syms[role] = field[1:]
            continue
        f = lower(field)
        if field in REGISTER_FIELDS:
            if role == "Dest":
                kind = "RW" if mn in READS_DEST else "W"
            elif role == "SrcA" and (mn.endswith("_add") or mn.startswith("prefetch_add")):
                kind = "RW"
            else:
                kind = "R"
            sym = f"{kind}_{f}"
        elif field == "BrOff_X1":
            sym = "brtarget_x1"
        elif field == "JumpOff_X1":
            sym = "jtarget_x1"
        elif field == "Dest_Imm8_X1":
            sym = "dimm8_x1"
        elif field == "MF_Imm14_X1":
            sym = "spr_mf_x1"
        elif field == "MT_Imm14_X1":
            sym = "spr_mt_x1"
        else:
            sym = f
        syms[role] = sym
        display.append(sym)
    return syms, display


# ---------------------------------------------------------------------------------------------
# Semantics helpers

def sat_signed(dst, src, size_bits, tmp):
    lo, hi = -(1 << (size_bits - 1)), (1 << (size_bits - 1)) - 1
    return (f"local {tmp}_hi:1 = {src} s> {hi}; local {tmp}_lo:1 = {src} s< {lo}; "
            f"local {tmp}_m:8 = {src}; "
            f"{tmp}_m = ({tmp}_m * zext(({tmp}_hi | {tmp}_lo) == 0)) + ({hi} * zext({tmp}_hi)) + "
            f"(({lo & 0xffffffffffffffff:#x}) * zext({tmp}_lo)); {dst} = {tmp}_m;")


def sat_unsigned(dst, src, size_bits, tmp):
    hi = (1 << size_bits) - 1
    return (f"local {tmp}_hi:1 = {src} s> {hi}; local {tmp}_lo:1 = {src} s< 0; "
            f"local {tmp}_m:8 = {src}; "
            f"{tmp}_m = ({tmp}_m * zext(({tmp}_hi | {tmp}_lo) == 0)) + ({hi} * zext({tmp}_hi)); "
            f"{dst} = {tmp}_m;")


def lanes(dest, bits, count, body):
    """body(i, shift) -> (code, result-expression of 'bits' bits); builds dest from the lanes."""
    n = bits // 8
    code = ["local out:8 = 0;"]
    for i in range(count):
        c, expr = body(i, i * bits)
        code.append(c)
        code.append(f"local res{i}:{n} = {expr};")
        code.append(f"out = out | (zext(res{i}) << {i * bits});")
    code.append(f"{dest} = out;")
    return " ".join(code)


def lane_get(src, name, i, bits, signed=None):
    """local <name><i>: the lane (bits wide); with signed True/False also an 8-byte extension."""
    n = bits // 8
    code = f"local {name}{i}s:8 = {src} >> {i * bits}; local {name}{i}:{n} = {name}{i}s:{n};"
    if signed is True:
        code += f" local {name}{i}x:8 = sext({name}{i});"
    elif signed is False:
        code += f" local {name}{i}x:8 = zext({name}{i});"
    return code


def vec_binary(o, bits, op, b_imm=None):
    """Lane-wise op(a, b) truncated to the lane; op gets lane names a<i>, b<i> (lane size)."""
    d, a = o["Dest"], o["SrcA"]
    n = bits // 8

    def body(i, shift):
        c = lane_get(a, "a", i, bits)
        if b_imm is None:
            c += " " + lane_get(o["SrcB"], "b", i, bits)
            b = f"b{i}"
        else:
            c += f" local b{i}:{n} = {b_imm};"
            b = f"b{i}"
        return c, op(f"a{i}", b, i)
    return lanes(d, bits, 64 // bits, body)


def vec_wide(o, bits, signed_a, signed_b, op, out_bits, count, b_imm=None):
    """Lane-wise op on 8-byte extensions a<i>x, b<i>x; result truncated to out_bits lanes."""
    d, a = o["Dest"], o["SrcA"]

    def body(i, shift):
        c = lane_get(a, "a", i, bits, signed_a)
        if b_imm is None:
            c += " " + lane_get(o["SrcB"], "b", i, bits, signed_b)
        else:
            c += f" local b{i}x:8 = {b_imm};"
        c += f" local w{i}:8 = {op(f'a{i}x', f'b{i}x', i)};"
        return c, f"w{i}:{out_bits // 8}"
    return lanes(d, out_bits, count, body)


def vec_sat(o, bits, signed, op, b_imm=None, out_bits=None, count=None):
    """Lane-wise saturating op on 8-byte extensions."""
    out_bits = out_bits or bits
    count = count or 64 // out_bits
    d, a = o["Dest"], o["SrcA"]

    def body(i, shift):
        c = lane_get(a, "a", i, bits, signed)
        if b_imm is None:
            c += " " + lane_get(o["SrcB"], "b", i, bits, signed)
        else:
            c += f" local b{i}x:8 = {b_imm};"
        c += f" local w{i}:8 = {op(f'a{i}x', f'b{i}x', i)};"
        c += " local s{i}:8 = 0; ".replace("{i}", str(i))
        c += (sat_signed if signed else sat_unsigned)(f"s{i}", f"w{i}", out_bits, f"t{i}")
        return c, f"s{i}:{out_bits // 8}"
    return lanes(d, out_bits, count, body)


def select(cond, yes, no):
    return f"(({yes}) * zext({cond})) + (({no}) * zext(!({cond})))"


def vec_reduce(o, bits, signed_a, signed_b, term, accumulate, halves=False):
    """Sum of term(a<i>x, b<i>x) over lanes; with halves, one 32-bit sum per half."""
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    count = 64 // bits
    code = []
    for i in range(count):
        code.append(lane_get(a, "a", i, bits, signed_a))
        code.append(lane_get(b, "b", i, bits, signed_b))
        code.append(f"local p{i}:8 = {term(f'a{i}x', f'b{i}x')};")
    if not halves:
        code.append("local sum:8 = " + " + ".join(f"p{i}" for i in range(count)) + ";")
        code.append(f"{d} = {d} + sum;" if accumulate else f"{d} = sum;")
        return " ".join(code)
    half = count // 2
    for h in range(2):
        code.append(f"local hs{h}:8 = " + " + ".join(f"p{i}" for i in range(h * half, (h + 1) * half)) + ";")
        code.append(f"local h{h}:4 = hs{h}:4;")
        if accumulate:
            code.append(f"local d{h}s:8 = {d} >> {32 * h}; local d{h}:4 = d{h}s:4; h{h} = h{h} + d{h};")
    code.append(f"{d} = (zext(h1) << 32) | zext(h0);")
    return " ".join(code)


def absdiff(x, y):
    return f"((({x}) - ({y})) * zext(({x}) s>= ({y}))) + ((({y}) - ({x})) * zext(({x}) s< ({y})))"


def vec_interleave(o, bits, high):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    count = 64 // bits
    start = count // 2 if high else 0
    mask = (1 << bits) - 1

    def body(i, shift):
        src = a if i & 1 else b
        return f"local l{i}:8 = {src} >> {(start + i // 2) * bits};", f"l{i}:{bits // 8}"
    return lanes(d, bits, count, body)


def vec_pack(o, high):
    # v2packl/v2packh: low (or high) byte of every 16-bit lane; bytes 0-3 from SrcB, 4-7 from SrcA
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]

    def body(i, shift):
        src = a if i >= 4 else b
        sel = 1 + (i & 3) * 2 if high else (i & 3) * 2
        return f"local l{i}:8 = {src} >> {sel * 8};", f"l{i}:1"
    return lanes(d, 8, 8, body)


def vec_pack_sat(o, in_bits, out_bits, signed):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    count = 64 // out_bits
    half = count // 2

    def body(i, shift):
        src = a if i >= half else b
        sel = i % half
        n = in_bits // 8
        c = (f"local l{i}s:8 = {src} >> {sel * in_bits}; local l{i}:{n} = l{i}s:{n}; "
             f"local l{i}x:8 = sext(l{i}); local s{i}:8 = 0; ")
        c += (sat_signed if signed else sat_unsigned)(f"s{i}", f"l{i}x", out_bits, f"t{i}")
        return c, f"s{i}:{out_bits // 8}"
    return lanes(d, out_bits, count, body)


def vec_shift(o, bits, kind, amount_src):
    d, a = o["Dest"], o["SrcA"]
    n = bits // 8
    code = [f"local amt8:8 = {amount_src} & {bits - 1}; local amt:{n} = amt8:{n};"]

    def body(i, shift):
        c = lane_get(a, "a", i, bits)
        op = {"shl": "<<", "shru": ">>", "shrs": "s>>"}[kind]
        return c, f"a{i} {op} amt"
    return " ".join(code) + " " + lanes(d, bits, 64 // bits, body)


def vec_shift_sat(o, bits):
    # v2shlsc/v4shlsc: signed_saturate(signExtend(lane) << (SrcB % bits))
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    code = f"local amt:8 = {b} & {bits - 1};"

    def body(i, shift):
        c = lane_get(a, "a", i, bits, True)
        c += f" local w{i}:8 = a{i}x << amt; local s{i}:8 = 0; "
        c += sat_signed(f"s{i}", f"w{i}", bits, f"t{i}")
        return c, f"s{i}:{bits // 8}"
    return code + " " + lanes(d, bits, 64 // bits, body)


def complex_mul(o, mn):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    code = []
    for nm, src in (("a", a), ("b", b)):
        code.append(f"local {nm}r:2 = {src}:2; local {nm}is:8 = {src} >> 16; local {nm}i:2 = {nm}is:2;")
        code.append(f"local {nm}rx:4 = sext({nm}r); local {nm}ix:4 = sext({nm}i);")
    rnd = {"cmulfr": " + 0x4000", "cmulhr": " + 0x8000"}.get(mn, "")
    code.append(f"local re:4 = (arx * brx) - (aix * bix){rnd}; local im:4 = (arx * bix) + (aix * brx){rnd};")
    if mn in ("cmul", "cmula"):
        if mn == "cmula":
            code.append(f"local dre:4 = {d}:4; local dims:8 = {d} >> 32; local dim:4 = dims:4; "
                        "re = re + dre; im = im + dim;")
        code.append(f"{d} = (zext(im) << 32) | zext(re);")
        return " ".join(code)
    shift = 16 if mn in ("cmulh", "cmulhr") else 15
    code.append(f"local rsh:4 = re s>> {shift}; local ish:4 = im s>> {shift};")
    code.append("local rr2:2 = rsh:2; local ii2:2 = ish:2;")
    if mn == "cmulaf":
        code.append(f"local dre:2 = {d}:2; local dims:8 = {d} >> 16; local dim:2 = dims:2; "
                    "rr2 = rr2 + dre; ii2 = ii2 + dim;")
    code.append(f"{d} = (zext(ii2) << 16) | zext(rr2);")
    return " ".join(code)


def crc32(o, bits):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    code = [f"local crc:4 = {a}:4;", f"local inp:4 = {b}:4;"]
    for i in range(bits):
        code.append(f"local bit{i}:4 = (crc ^ inp) & 1; crc = (crc >> 1) ^ (0xedb88320 * bit{i}); "
                    "inp = inp >> 1;")
    code.append(f"{d} = zext(crc);")
    return " ".join(code)


def reverse_bytes(dest, source):
    return (f"local v:8 = {source}; "
            "v = ((v & 0x00ff00ff00ff00ff) << 8) | ((v >> 8) & 0x00ff00ff00ff00ff); "
            "v = ((v & 0x0000ffff0000ffff) << 16) | ((v >> 16) & 0x0000ffff0000ffff); "
            f"{dest} = (v << 32) | (v >> 32);")


def reverse_bits(dest, source):
    return (f"local v:8 = {source}; "
            "v = ((v & 0x5555555555555555) << 1) | ((v >> 1) & 0x5555555555555555); "
            "v = ((v & 0x3333333333333333) << 2) | ((v >> 2) & 0x3333333333333333); "
            "v = ((v & 0x0f0f0f0f0f0f0f0f) << 4) | ((v >> 4) & 0x0f0f0f0f0f0f0f0f); "
            "v = ((v & 0x00ff00ff00ff00ff) << 8) | ((v >> 8) & 0x00ff00ff00ff00ff); "
            "v = ((v & 0x0000ffff0000ffff) << 16) | ((v >> 16) & 0x0000ffff0000ffff); "
            f"{dest} = (v << 32) | (v >> 32);")


def shuffle_bytes(o):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    code = [f"local orig:8 = {d};", "local out:8 = 0;"]
    for i in range(8):
        code.append(f"local sel{i}s:8 = {b} >> {i * 8}; local sel{i}:8 = sel{i}s & 0xf;")
        code.append(f"local src{i}:8 = ({a} * zext(sel{i} >= 8)) + (orig * zext(sel{i} < 8));")
        code.append(f"local byte{i}:8 = (src{i} >> ((sel{i} & 7) << 3)) & 0xff;")
        code.append(f"out = out | (byte{i} << {i * 8});")
    code.append(f"{d} = out;")
    return " ".join(code)


def bitfield_mask(start, end):
    # (start <= end) ? ((-1 << start) ^ ((-1 << end) << 1)) : ((-1 << start) | (-1 >> (63 - end)))
    return (f"local bst:8 = {start}; local ben:8 = {end}; " +
            "local lowm:8 = (0xffffffffffffffff << {s}) ^ ((0xffffffffffffffff << {e}) << 1); "
            "local wrapm:8 = (0xffffffffffffffff << {s}) | (0xffffffffffffffff >> (63 - {e})); "
            "local bfm:8 = (lowm * zext({s} <= {e})) + (wrapm * zext({s} > {e}));").format(s="bst", e="ben")


def mul_half(o, mn):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    suffix = mn.removeprefix("mula_").removeprefix("mul_")
    ha, hb = suffix.split("_")

    def ext(v, h, nm):
        return {"lu": f"local {nm}:8 = zext({v}:4);",
                "ls": f"local {nm}:8 = sext({v}:4);",
                "hu": f"local {nm}:8 = {v} >> 32;",
                "hs": f"local {nm}:8 = {v} s>> 32;"}[h]
    code = ext(a, ha, "ma") + " " + ext(b, hb, "mb")
    if mn.startswith("mula_"):
        return code + f" {d} = {d} + (ma * mb);"
    return code + f" {d} = ma * mb;"


def atomic(o, mn, ctx):
    d, a, b = o["Dest"], o["SrcA"], o["SrcB"]
    size = 4 if mn.endswith("4") else 8
    code = [ctx.ea(a), f"local old:{size} = *[ram]:{size} addr;",
            f"{d} = {'sext(old)' if size == 4 else 'old'};"]
    if mn.startswith("cmpexch"):
        code.append(f"if (old != CMPEXCH_VALUE:{size}) goto <done>; *[ram]:{size} addr = {b}:{size}; <done>")
    elif mn.startswith("exch"):
        code.append(f"*[ram]:{size} addr = {b}:{size};")
    else:
        op = {"fetchadd": "+", "fetchaddgez": "+", "fetchand": "&", "fetchor": "|"}[mn.rstrip("4")]
        code.append(f"local upd:{size} = old {op} {b}:{size};")
        if mn.startswith("fetchaddgez"):
            code.append(f"if (upd s< 0) goto <done>; *[ram]:{size} addr = upd; <done>")
        else:
            code.append(f"*[ram]:{size} addr = upd;")
    return " ".join(code)


LOADS = {"ld": (8, None), "ld1s": (1, "sext"), "ld1u": (1, "zext"), "ld2s": (2, "sext"),
         "ld2u": (2, "zext"), "ld4s": (4, "sext"), "ld4u": (4, "zext"), "ldna": (8, None)}
STORES = {"st": 8, "st1": 1, "st2": 2, "st4": 4}
BRANCHES = {"beqz": "{a} == 0", "bnez": "{a} != 0", "bgez": "{a} s>= 0", "bgtz": "{a} s> 0",
            "blez": "{a} s<= 0", "bltz": "{a} s< 0", "blbc": "({a} & 1) == 0", "blbs": "({a} & 1) != 0"}


def semantics(mn, o, ctx, userops):
    """P-code for one slot. o: role -> symbol."""
    D, A, B = o.get("Dest"), o.get("SrcA", o.get("Src")), o.get("SrcB")
    I = o.get("Imm8") or o.get("Imm16")
    S = o.get("ShAmt")
    le = ctx.endian == "little"

    if mn in ("fnop", "nop", "info", "infol"):
        return ""
    if mn in ("prefetch", "prefetch_l1_fault", "prefetch_l2", "prefetch_l2_fault", "prefetch_l3",
              "prefetch_l3_fault"):
        return ""                       # a load to the zero register: a cache hint only
    if mn.startswith("prefetch_add"):
        return f"{A} = {A} + {I};"
    if mn == "move":
        return f"{D} = {A};"
    if mn in ("movei", "moveli"):
        return f"{D} = {I};"
    if mn in ("add", "addi", "addli"):
        return f"{D} = {A} + {B or I};"
    if mn == "sub":
        return f"{D} = {A} - {B};"
    if mn in ("addx", "addxi", "addxli", "subx"):
        op = "-" if mn == "subx" else "+"
        return f"local r:4 = {A}:4 {op} {B or I}; {D} = sext(r);" if B is None else \
            f"local r:4 = {A}:4 {op} {B}:4; {D} = sext(r);"
    if mn in ("addxsc", "subxsc"):
        op = "+" if mn == "addxsc" else "-"
        return f"local w:8 = sext({A}:4) {op} sext({B}:4); local s:8 = 0; " + sat_signed("s", "w", 32, "t") + f" {D} = s;"
    if mn in ("and", "or", "xor"):
        return f"{D} = {A} {dict(zip(('and', 'or', 'xor'), '&|^'))[mn]} {B};"
    if mn in ("andi", "ori", "xori"):
        return f"{D} = {A} {dict(zip(('andi', 'ori', 'xori'), '&|^'))[mn]} {I};"
    if mn == "nor":
        return f"{D} = ~({A} | {B});"
    if mn in ("shl1add", "shl2add", "shl3add"):
        return f"{D} = ({A} << {mn[3]}) + {B};"
    if mn in ("shl1addx", "shl2addx", "shl3addx"):
        return f"local r:4 = ({A}:4 << {mn[3]}) + {B}:4; {D} = sext(r);"
    if mn == "shl16insli":
        return f"{D} = ({A} << 16) | ({I} & 0xffff);"
    if mn == "clz":
        return f"{D} = lzcount({A});"
    if mn == "ctz":
        return f"local iso:8 = {A} & (0 - {A}); {D} = popcount(iso - 1);"
    if mn == "pcnt":
        return f"{D} = popcount({A});"
    if mn == "revbytes":
        return reverse_bytes(D, A)
    if mn == "revbits":
        return reverse_bits(D, A)
    if mn.startswith("tblidxb"):
        return f"{D} = ({D} & 0xfffffffffffffc03) | ((({A} >> {int(mn[-1]) * 8}) & 0xff) << 2);"
    cmps = {"cmpeq": "==", "cmpeqi": "==", "cmpne": "!=", "cmples": "s<=", "cmplts": "s<",
            "cmpltsi": "s<", "cmpleu": "<=", "cmpltu": "<", "cmpltui": "<"}
    if mn in cmps:
        return f"{D} = zext({A} {cmps[mn]} {B or I});"
    if mn in ("cmoveqz", "cmovnez"):
        return f"if ({A} {'!=' if mn == 'cmoveqz' else '=='} 0) goto <skip>; {D} = {B}; <skip>"
    if mn in ("mnz", "mz"):
        return f"{D} = {B} & (0 - zext({A} {'!=' if mn == 'mnz' else '=='} 0));"
    if mn in ("shl", "shrs", "shru"):
        return f"{D} = {A} {dict(shl='<<', shrs='s>>', shru='>>')[mn]} ({B} & 63);"
    if mn in ("shli", "shrsi", "shrui"):
        return f"{D} = {A} {dict(shli='<<', shrsi='s>>', shrui='>>')[mn]} {S};"
    if mn in ("shlx", "shlxi", "shrux", "shruxi"):
        amt = f"({B} & 31)" if B else f"({S} & 31)"
        return f"local r:4 = {A}:4 {'<<' if mn.startswith('shl') else '>>'} {amt}; {D} = sext(r);"
    if mn in ("rotl", "rotli"):
        amt = f"({B} & 63)" if B else S
        return f"local amt:8 = {amt}; {D} = ({A} << amt) | ({A} >> ((64 - amt) & 63));"
    if mn in ("bfextu", "bfexts"):
        st, en = o["BFStart"], o["BFEnd"]
        code = (f"local bfm:8 = ~((0xffffffffffffffff << (({en} - {st}) & 63)) << 1); "
                f"local rot:8 = ({A} >> {st}) | ({A} << ((64 - {st}) & 63)); ")
        if mn == "bfextu":
            return code + f"{D} = rot & bfm;"
        return code + f"local bg:8 = 0 - (({A} >> {en}) & 1); {D} = (rot & bfm) | (bg & ~bfm);"
    if mn == "bfins":
        st, en = o["BFStart"], o["BFEnd"]
        return (bitfield_mask(st, en) + f" local rot:8 = ({A} << {st}) | ({A} >> ((64 - {st}) & 63)); "
                f"{D} = (rot & bfm) | ({D} & ~bfm);")
    if mn == "mm":
        st, en = o["BFStart"], o["BFEnd"]
        return bitfield_mask(st, en) + f" {D} = ({D} & bfm) | ({A} & ~bfm);"
    if mn == "mulx":
        return f"local r:4 = {A}:4 * {B}:4; {D} = sext(r);"
    if mn == "mulax":
        return f"local r:4 = {D}:4 + ({A}:4 * {B}:4); {D} = sext(r);"
    if mn.startswith(("mul_", "mula_")):
        return mul_half(o, mn)
    if mn in ("cmul", "cmula", "cmulf", "cmulaf", "cmulfr", "cmulh", "cmulhr"):
        return complex_mul(o, mn)
    if mn in ("crc32_8", "crc32_32"):
        return crc32(o, 8 if mn == "crc32_8" else 32)
    if mn == "dblalign":
        if le:
            return (f"local sh:8 = ({B} & 7) << 3; "
                    f"{D} = ({D} >> sh) | (({A} << (sh ^ 63)) << 1);")
        return f"local sh:8 = ({B} & 7) << 3; {D} = ({D} << sh) | (({A} >> (sh ^ 63)) >> 1);"
    if mn in ("dblalign2", "dblalign4", "dblalign6"):
        n = int(mn[-1]) * 8
        if le:
            return f"{D} = ({A} << {64 - n}) | ({B} >> {n});"
        return f"{D} = ({B} << {n}) | ({A} >> {64 - n});"
    if mn == "shufflebytes":
        return shuffle_bytes(o)
    if mn in ("cmpexch", "cmpexch4", "exch", "exch4", "fetchadd", "fetchadd4", "fetchaddgez",
              "fetchaddgez4", "fetchand", "fetchand4", "fetchor", "fetchor4"):
        return atomic(o, mn, ctx)

    # SIMD ------------------------------------------------------------------------------------
    if mn[:2] in ("v1", "v2", "v4"):
        return simd(mn, o)

    # memory -----------------------------------------------------------------------------------
    base = mn.removesuffix("_add").removesuffix("_tls")
    base = base.replace("ldnt", "ld", 1).replace("stnt", "st", 1)
    if base == "ldna":
        size, ext = 8, None
    elif base in LOADS:
        size, ext = LOADS[base]
    else:
        size, ext = None, None
    if size:
        addr = f"{A} & 0xfffffffffffffff8" if base == "ldna" else A
        load = f"*[ram]:{size} addr"
        code = f"{ctx.ea(addr)} {D} = {ext + '(' + load + ')' if ext else load};"
        if mn.endswith("_add"):
            code += f" {A} = {A} + {I};"
        return code
    if base in STORES:
        size = STORES[base]
        code = f"{ctx.ea(A)} *[ram]:{size} addr = {B}:{size};"
        if mn.endswith("_add"):
            code += f" {A} = {A} + {o['Imm8']};"
        return code

    # control flow -------------------------------------------------------------------------------
    if mn == "j":
        return f"<<FLOW>> goto {o['JumpOff']};"
    if mn == "jal":
        return f"lr_new = inst_next; <<COMMIT>> lr = lr_new; <<FLOW>> call {o['JumpOff']};"
    if mn in ("jr", "jrp"):
        return f"branch_target = {A} & 0xfffffffffffffff8;"   # flow: the JR operand (render)
    if mn in ("jalr", "jalrp"):
        return (f"lr_new = inst_next; branch_target = {A} & 0xfffffffffffffff8; "
                "<<COMMIT>> lr = lr_new; <<FLOW>> call [branch_target];")
    if mn == "lnk":
        return f"{D} = inst_next;"
    br = mn[:-1] if mn.endswith("t") and mn[:-1] in BRANCHES else mn
    if br in BRANCHES:
        return (f"branch_taken = {BRANCHES[br].format(a=A)}; "
                f"<<FLOW>> if (branch_taken != 0) goto {o['BrOff']};")
    if mn == "iret":
        return ("local ctx0:8 = 0; local ctx1:8 = 0; "
                "if (pl != 0) goto <pl1>; ctx0 = EX_CONTEXT_0_0; ctx1 = EX_CONTEXT_0_1; goto <got>; "
                "<pl1> if (pl != 1) goto <pl2>; ctx0 = EX_CONTEXT_1_0; ctx1 = EX_CONTEXT_1_1; goto <got>; "
                "<pl2> if (pl != 2) goto <pl3>; ctx0 = EX_CONTEXT_2_0; ctx1 = EX_CONTEXT_2_1; goto <got>; "
                "<pl3> ctx0 = EX_CONTEXT_3_0; ctx1 = EX_CONTEXT_3_1; <got> "
                "branch_target = ctx0 & 0xfffffffffffffff8; "
                "<<COMMIT>> pl = ctx1:1 & 3; INTERRUPT_CRITICAL_SECTION = (ctx1 >> 2) & 1; "
                "<<FLOW>> return [branch_target];")
    if mn == "mfspr":
        return f"{D} = {o['Imm14']};"
    if mn == "mtspr":
        return f"{o['Imm14']} = {A};"
    if mn.startswith("swint"):
        userops.add("tilegx_swint")
        return f"tilegx_swint({mn[-1]}:1);"
    if mn == "ill":
        userops.add("tilegx_ill")
        return "tilegx_ill(); <<FLOW>> goto inst_start;"
    if mn in ("bpt", "raise"):
        userops.add(f"tilegx_{mn}")
        return f"tilegx_{mn}();"
    if mn in SYSTEM_OPS:
        userops.add(f"tilegx_{mn}")
        return f"tilegx_{mn}({', '.join(o[r] for r in SYSTEM_OPS[mn])});"
    if mn in FP_HELPERS:
        userops.add(f"tilegx_{mn}")
        args = ([D] if mn in READS_DEST else []) + [x for x in (A, B) if x]
        return f"{D} = tilegx_{mn}({', '.join(args)});"
    raise SystemExit(f"no semantics for {mn}")


def simd(mn, o):
    D, A, B, I, S = o["Dest"], o["SrcA"], o.get("SrcB"), o.get("Imm8"), o.get("ShAmt")
    bits = {"v1": 8, "v2": 16, "v4": 32}[mn[:2]]
    op = mn[2:]
    n = bits // 8
    imm_lane = I
    if op in ("add", "sub"):
        return vec_binary(o, bits, lambda a, b, i: f"{a} {'+' if op == 'add' else '-'} {b}")
    if op == "addi":
        return vec_binary(o, bits, lambda a, b, i: f"{a} + {b}", b_imm=imm_lane)
    if op in ("adduc", "subuc"):
        return vec_sat(o, bits, False, lambda a, b, i: f"{a} {'+' if op == 'adduc' else '-'} {b}")
    if op in ("addsc", "subsc"):
        return vec_sat(o, bits, True, lambda a, b, i: f"{a} {'+' if op == 'addsc' else '-'} {b}")
    if op in ("adiffu", "adiffs"):
        signed = op == "adiffs"
        return vec_wide(o, bits, signed, signed, lambda a, b, i: absdiff(a, b), bits, 64 // bits)
    if op in ("avgu", "avgs"):
        signed = op == "avgs"
        sh = "s>>" if signed else ">>"
        return vec_wide(o, bits, signed, signed, lambda a, b, i: f"({a} + {b} + 1) {sh} 1", bits, 64 // bits)
    cmps = {"cmpeq": ("==", None), "cmpne": ("!=", None), "cmplts": ("s<", True),
            "cmples": ("s<=", True), "cmpltu": ("<", False), "cmpleu": ("<=", False),
            "cmpeqi": ("==", None), "cmpltsi": ("s<", True), "cmpltui": ("<", False)}
    if op in cmps:
        rel = cmps[op][0]
        return vec_binary(o, bits, lambda a, b, i: f"zext({a} {rel} {b})",
                          b_imm=imm_lane if op.endswith("i") else None)
    if op in ("maxu", "minu", "maxs", "mins", "maxui", "minui", "maxsi", "minsi"):
        signed = op[3] == "s"
        rel = ("s>" if signed else ">") if op.startswith("max") else ("s<" if signed else "<")
        return vec_binary(o, bits, lambda a, b, i: select(f"{a} {rel} {b}", a, b),
                          b_imm=imm_lane if op.endswith("i") else None)
    if op in ("mnz", "mz"):
        return vec_binary(o, bits, lambda a, b, i: select(f"{a} {'!=' if op == 'mnz' else '=='} 0", b, "0"))
    if op == "multu":       # v1multu: low byte of the unsigned product
        return vec_binary(o, bits, lambda a, b, i: f"{a} * {b}")
    if op == "mults":       # v2mults: low 16 bits of the product
        return vec_binary(o, bits, lambda a, b, i: f"{a} * {b}")
    if op in ("mulu", "mulus"):   # v1mulu / v1mulus: lanes 0-3, 16-bit products
        return vec_wide(o, 8, False, op == "mulus", lambda a, b, i: f"{a} * {b}", 16, 4)
    if op == "muls":        # v2muls: lanes 0-1, 32-bit products
        return vec_wide(o, 16, True, True, lambda a, b, i: f"{a} * {b}", 32, 2)
    if op == "mulfsc":      # v2mulfsc: lanes 0-1, signed_saturate32(product << 1)
        return vec_sat(o, 16, True, lambda a, b, i: f"({a} * {b}) << 1", out_bits=32, count=2)
    if op in ("dotp", "dotpa", "dotpu", "dotpua", "dotpus", "dotpusa"):
        sa = op in ("dotp", "dotpa")
        sb = op in ("dotp", "dotpa", "dotpus", "dotpusa")
        return vec_reduce(o, bits, sa, sb, lambda a, b: f"{a} * {b}", op.endswith("a"))
    if op in ("ddotpu", "ddotpua", "ddotpus", "ddotpusa"):
        sb = op in ("ddotpus", "ddotpusa")
        return vec_reduce(o, bits, False, sb, lambda a, b: f"{a} * {b}", op.endswith("a"), halves=True)
    if op in ("sadu", "sadau", "sads", "sadas"):
        signed = op in ("sads", "sadas")
        return vec_reduce(o, bits, signed, signed, absdiff, op in ("sadau", "sadas"))
    if op in ("shl", "shru", "shrs"):
        return vec_shift(o, bits, op, B)
    if op in ("shli", "shrui", "shrsi"):
        return vec_shift(o, bits, op[:-1], S)
    if op == "shlsc":
        return vec_shift_sat(o, bits)
    if op in ("int_h", "int_l"):
        return vec_interleave(o, bits, op == "int_h")
    if op in ("packh", "packl"):
        return vec_pack(o, op == "packh")
    if op == "packuc":
        return vec_pack_sat(o, 16, 8, False)
    if op == "packsc":
        return vec_pack_sat(o, 32, 16, True)
    raise SystemExit(f"no SIMD semantics for {mn}")


# ---------------------------------------------------------------------------------------------

def render(rows, sprs, endian, addr):
    ctx = Ctx(endian, addr)
    ordered, exclusions = prioritize(rows)
    userops = set()
    bodies = {}
    displays = {}
    for row in ordered:
        pipe, mn, mask, value, operands = row
        syms, disp = operand_symbols(mn, operands)
        bodies[row] = semantics(mn, syms, ctx, userops)
        displays[row] = (syms, disp)

    runs = set()
    for row in ordered:
        runs.update(mask_runs(row[2]))
        for extra, _ in exclusions[row]:
            runs.update(mask_runs(extra))

    L = [
        "# TILE-Gx (Tilera/Mellanox) bundles. Generated by support/generate_tilegx_sleigh.py from",
        "# support/tilegx_isa.tsv (Tilera UG401 encodings); do not edit.",
        f"define endian={endian};",
        "define alignment=8;",
        "",
        f"define space ram type=ram_space size={addr} default;",
        "define space register type=register_space size=4;",
        "",
        "define register offset=0x0000 size=8 [",
    ]
    L += ["    " + " ".join(REGISTER_NAMES[i:i + 16]) for i in range(0, 64, 16)]
    L += ["];", "define register offset=0x0400 size=8 ["]
    L += ["    " + " ".join(n + "_new" for n in REGISTER_NAMES[i:i + 16]) for i in range(0, 64, 16)]
    L += ["];",
          f"define register offset=0x0200 size={addr} pc;",
          "define register offset=0x0208 size=8 branch_target;",
          "define register offset=0x0210 size=1 branch_taken;",
          "define register offset=0x0211 size=1 pl;    # current protection level (iret)",
          "",
          "# Special-purpose registers (UG401 / MDE SPR reference): SPR n at 0x10000 + 8 * n"]
    for num, name in sprs:
        L.append(f"define register offset={SPR_BASE + 8 * num:#x} size=8 {name};")
    L.append("")
    for u in sorted(userops):
        L.append(f"define pcodeop {u};")
    L += ["", "define token bundle(64)" + (" endian=little" if endian == "big" else ""),
          "    mode=(62,63)"]
    for name, pieces in FIELDS.items():
        f = lower(name)
        base = name.split("_X")[0].split("_Y")[0]
        signed = " signed" if base in SIGNED_FIELDS else ""
        if len(pieces) == 1:
            lo, hi = pieces[0]
            L.append(f"    {f}=({lo},{hi}){signed}")
            if name in REGISTER_FIELDS:
                L.append(f"    {f}_num=({lo},{hi})")
                L.append(f"    {f}_new=({lo},{hi})")
        else:
            (lo0, hi0), (lo1, hi1) = pieces
            L.append(f"    {f}_lo=({lo0},{hi0})")
            L.append(f"    {f}_hi=({lo1},{hi1}){signed}")
    for lo, hi in sorted(runs):
        L.append(f"    m_{lo:02d}_{hi:02d}=({lo},{hi})")
    L += [";", ""]
    regf = [lower(f) for f in REGISTER_FIELDS]
    L.append(f"attach variables [ {' '.join(regf)} ] [")
    L += ["    " + " ".join(REGISTER_NAMES[i:i + 16]) for i in range(0, 64, 16)]
    L += ["];", f"attach variables [ {' '.join(f + '_new' for f in regf)} ] ["]
    L += ["    " + " ".join(n + "_new" for n in REGISTER_NAMES[i:i + 16]) for i in range(0, 64, 16)]
    L += ["];", ""]

    # register operands: 63 is the zero register (reads 0, writes discarded)
    used = {sym for syms, _ in displays.values() for sym in syms.values()}
    for f in regf:
        if f"R_{f}" in used or f in ("srca_x1", "srca_y1"):
            L.append(f"R_{f}: {f} is {f} & {f}_num=63 {{ export 0:8; }}")
            L.append(f"R_{f}: {f} is {f} {{ export {f}; }}")
        if f"W_{f}" in used:
            L.append(f"W_{f}: {f} is {f} & {f}_num=63 {{ local discard:8 = 0; export discard; }}")
            L.append(f"W_{f}: {f} is {f} & {f}_new {{ export {f}_new; <<COMMIT>> {f} = {f}_new; }}")
        if f"RW_{f}" in used:
            L.append(f"RW_{f}: {f} is {f} & {f}_num=63 {{ local discard:8 = 0; export discard; }}")
            L.append(f"RW_{f}: {f} is {f} & {f}_new {{ {f}_new = {f}; export {f}_new; "
                     f"<<COMMIT>> {f} = {f}_new; }}")
    L += [
        "",
        "brtarget_x1: dest is broff_x1_hi & broff_x1_lo "
        "[ dest = inst_start + (((broff_x1_hi << 6) | broff_x1_lo) << 3); ] { export *[ram]:8 dest; }",
        "jtarget_x1: dest is jumpoff_x1 [ dest = inst_start + (jumpoff_x1 << 3); ] "
        "{ export *[ram]:8 dest; }",
        "dimm8_x1: val is dest_imm8_x1_hi & dest_imm8_x1_lo "
        "[ val = (dest_imm8_x1_hi << 6) | dest_imm8_x1_lo; ] { export *[const]:8 val; }",
        "bundle_address: address is epsilon [ address = inst_start; ] { export *[ram]:8 address; }",
        "",
        "# SPR operands: named SPRs are registers; others are register-space words at 0x10000 + 8 * n",
    ]
    for num, name in sprs:
        L.append(f"spr_mf_x1: {name} is mf_imm14_x1={num:#x} & {name} {{ export {name}; }}")
        L.append(f"spr_mt_x1: {name} is mt_imm14_x1_hi={num >> 6:#x} & mt_imm14_x1_lo={num & 63:#x} "
                 f"& {name} {{ export {name}; }}")
    L += ["sprw_mf_x1: sprAddr is mf_imm14_x1 [ sprAddr = 0x10000 + 8 * mf_imm14_x1; ] "
          "{ export *[register]:8 sprAddr; }",
          "sprw_mt_x1: sprAddr is mt_imm14_x1_hi & mt_imm14_x1_lo "
          "[ sprAddr = 0x10000 + 8 * ((mt_imm14_x1_hi << 6) | mt_imm14_x1_lo); ] { export *[register]:8 sprAddr; }",
          "spr_mf_x1: mf_imm14_x1 is mf_imm14_x1 & sprw_mf_x1 { export sprw_mf_x1; }",
          "spr_mt_x1: num is mt_imm14_x1_hi & mt_imm14_x1_lo & sprw_mt_x1 "
          "[ num = (mt_imm14_x1_hi << 6) | mt_imm14_x1_lo; ] { export sprw_mt_x1; }",
          ""]
    # jr/jrp: a jump through lr is a return
    L += ["JR_J: is srca_x1_num=55 { <<FLOW>> return [branch_target]; }",
          "JR_J: is epsilon { <<FLOW>> goto [branch_target]; }",
          "JR_P: is epsilon { <<FLOW>> return [branch_target]; }",
          "JRY_J: is srca_y1_num=55 { <<FLOW>> return [branch_target]; }",
          "JRY_J: is epsilon { <<FLOW>> goto [branch_target]; }",
          "JRY_P: is epsilon { <<FLOW>> return [branch_target]; }",
          ""]

    for row in ordered:
        pipe, mn, mask, value, operands = row
        syms, disp = displays[row]
        body = bodies[row]
        terms = []
        for s in disp:
            if not s.startswith('"') and s not in terms:
                terms.append(s)
        if mn in ("jr", "jrp"):
            terms.append(("JR" if pipe == "X1" else "JRY") + ("_P" if mn == "jrp" else "_J"))
        display = f'"{mn}"' + ('^" "^' + '^", "^'.join(disp) if disp else "")
        terms += [fixed_term(lo, hi, value) for lo, hi in mask_runs(mask)]
        for extra, hv in exclusions[row]:
            alts = [fixed_term(lo, hi, hv, "!=") for lo, hi in mask_runs(extra)]
            terms.append("(" + " | ".join(alts) + ")")
        if not terms:
            terms = ["epsilon"]
        L.append(f"{pipe.lower()}: {display} is {' & '.join(terms)} {{ {body} }}")
    L += ["",
          ':"{" x0 ";" x1 "}" is mode=0 & x0 & x1 & bundle_address { build x0; build x1; '
          "crossbuild bundle_address,COMMIT; crossbuild bundle_address,FLOW; }",
          ':"{" y0 ";" y1 ";" y2 "}" is mode!=0 & y0 & y1 & y2 & bundle_address { build y0; build y1; '
          "build y2; crossbuild bundle_address,COMMIT; crossbuild bundle_address,FLOW; }",
          ""]
    return "\n".join(L)


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "data" / "languages"
    rows, sprs = load_isa(), load_sprs()
    for name, (endian, addr) in VARIANTS.items():
        (out / f"{name}.slaspec").write_text(render(rows, sprs, endian, addr))
        print(f"wrote {name}.slaspec")


if __name__ == "__main__":
    main()
