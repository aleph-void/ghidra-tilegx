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
"""Extract the TILE-Gx instruction encodings from Tilera's ISA manual.

    ug401_extract.py UG401-ISA.pdf spr.html tilegx_isa.tsv tilegx_sprs.tsv [Tile.idx]

UG401-ISA.pdf is "TILE-Gx Instruction Set Architecture" (Tilera UG401, MDE 4.3.4) and spr.html
the MDE's SPR reference; fetch-manual.sh downloads both by pinned URL and SHA-256. Every
instruction section has one "Bits Encoding" figure per pipeline; the figure's bit-number row and
the 0/1 strings in its boxes give the fixed bits, its labels name the operand fields, and the
section's Syntax line gives the operand order. Needs poppler's pdftotext.

The output tables hold only these facts (pipeline, mnemonic, mask, value, operand fields; SPR
numbers and names). The SLEIGH generator reads them; nothing here comes from GNU binutils.
"""
import html
import re
import subprocess
import sys
from collections import defaultdict

# Operand fields as the manual's format figures (chapter 2) define them: name -> [(lo, hi)] from
# the least significant piece up. Checked below against every figure's field labels.
FIELDS = {
    "Dest_X0": [(0, 5)], "SrcA_X0": [(6, 11)], "SrcB_X0": [(12, 17)], "Imm8_X0": [(12, 19)],
    "Imm16_X0": [(12, 27)], "ShAmt_X0": [(12, 17)], "BFEnd_X0": [(12, 17)], "BFStart_X0": [(18, 23)],
    "Dest_X1": [(31, 36)], "SrcA_X1": [(37, 42)], "SrcB_X1": [(43, 48)], "Imm8_X1": [(43, 50)],
    "Imm16_X1": [(43, 58)], "ShAmt_X1": [(43, 48)], "BrOff_X1": [(31, 36), (43, 53)],
    "JumpOff_X1": [(31, 57)], "MF_Imm14_X1": [(37, 50)], "MT_Imm14_X1": [(31, 36), (43, 50)],
    "Dest_Imm8_X1": [(31, 36), (49, 50)],
    "Dest_Y0": [(0, 5)], "SrcA_Y0": [(6, 11)], "SrcB_Y0": [(12, 17)], "Imm8_Y0": [(12, 19)],
    "ShAmt_Y0": [(12, 17)],
    "Dest_Y1": [(31, 36)], "SrcA_Y1": [(37, 42)], "SrcB_Y1": [(43, 48)], "Imm8_Y1": [(43, 50)],
    "ShAmt_Y1": [(43, 48)],
    "SrcA_Y2": [(20, 25)], "SrcBDest_Y2": [(51, 56)],
}
# Two figures (bfexts and bfextu in X0, pages 157-158) are drawn as outlines without text; their
# encodings are read off the rendered figures: Opcode_X0 0x3, BFOpcodeExtension_X0 0x4 / 0x5.
OUTLINED = {
    ("bfexts", "X0"): (0x3 << 28 | 0x4 << 24, 0x7 << 28 | 0xF << 24,
                       ["Dest_X0 - Dest", "SrcA_X0 - SrcA", "BFEnd_X0 - BFEnd", "BFStart_X0 - BFStart"]),
    ("bfextu", "X0"): (0x3 << 28 | 0x5 << 24, 0x7 << 28 | 0xF << 24,
                       ["Dest_X0 - Dest", "SrcA_X0 - SrcA", "BFEnd_X0 - BFEnd", "BFStart_X0 - BFStart"]),
}
# Figure errors in UG401, each confirmed against GNU objdump's decoder and the manual's own
# pattern. Figure 3-46 ("addx in Y1") repeats the X1 figure; addx in Y1 follows Y0's layout
# (add/addx/subx/sub = RRROpcodeExtension 1/0/2/3 of the same opcode), Opcode_Y1 0x6, extension 0x0.
ERRATA = {
    ("addx", "Y1"): (0x6 << 58 | 0x0 << 49, 0xF << 58 | 0x3 << 49,
                     ["Dest_Y1 - Dest", "SrcA_Y1 - SrcA", "SrcB_Y1 - SrcB"]),
}
# Mnemonics the manual documents twice for one encoding: the name GNU objdump prints wins.
ALIASES = {"prefetch_l1": "prefetch"}
WORD = re.compile(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">(.*?)</word>')


def shifted(text):
    # The figure text uses a font whose code points are the characters' minus 29.
    return "".join(chr(ord(c) + 29) for c in text)


def figures(pdf):
    bbox = subprocess.run(["pdftotext", "-bbox", pdf, "-"], check=True, capture_output=True,
                          text=True, errors="replace").stdout
    for pno, page in enumerate(bbox.split("<page ")[1:], 1):
        words = [(float(a), float(b), float(c), html.unescape(e)) for a, b, c, d, e in WORD.findall(page)]
        captions = []
        for i, w in enumerate(words):
            if w[3] == "Figure" and i + 1 < len(words) and re.fullmatch(r"\d+-\d+:", words[i + 1][3]):
                cap = [x[3] for x in words[i + 2:] if abs(x[1] - w[1]) < 2]
                captions.append((w[1], " ".join(cap)))
        top = 0
        for y, cap in captions:
            region, top = [w for w in words if top < w[1] < y - 1], y + 5
            m = re.match(r"(\S+) in ?(X0|X1|Y0|Y1|Y2) Bits Encoding", cap)  # one caption reads "inY1"
            if not m:
                continue
            mn, pipe = m.groups()
            if (mn, pipe) in OUTLINED or (mn, pipe) in ERRATA:
                value, mask, labels = OUTLINED.get((mn, pipe)) or ERRATA[mn, pipe]
                yield pno, mn, pipe, mask, value, labels, []
                continue
            text = [(x0, y0, x1, shifted(t)) for x0, y0, x1, t in region]
            nums = [w for w in text if re.fullmatch(r"\d{1,2}", w[3])]
            ytop = min(w[1] for w in nums)
            bitx = {int(w[3]): (w[0] + w[2]) / 2 for w in nums if abs(w[1] - ytop) < 2}
            mask = value = 0
            letters = []
            for x0, y0, x1, t in text:
                if not ytop + 5 < y0 < ytop + 30:
                    continue
                cx = (x0 + x1) / 2
                if re.fullmatch(r"[01]+", t):
                    n = len(t)
                    lo = min((lo for lo in bitx if all(k in bitx for k in range(lo, lo + n))),
                             key=lambda lo: abs((bitx[lo] + bitx[lo + n - 1]) / 2 - cx))
                    mask |= ((1 << n) - 1) << lo
                    value |= int(t, 2) << lo
                else:
                    letters.append((t, min(bitx, key=lambda k: abs(bitx[k] - cx))))
            labels = [t for _, _, _, t in text if " - " in t]
            yield pno, mn, pipe, mask, value, labels, letters


def field_mask(name):
    return sum(((1 << (hi - lo + 1)) - 1) << lo for lo, hi in FIELDS[name])


def syntax_lines(pdf):
    raw = subprocess.run(["pdftotext", "-raw", pdf, "-"], check=True, capture_output=True,
                         text=True, errors="replace").stdout
    syntax, page = {}, {}
    for pno, text in enumerate(raw.split("\f"), 1):
        if "Figure 2-1:" in text:
            page.setdefault("{", pno)         # bundle formats: Ghidra shows bundles as "{ ... }"
        lines = text.split("\n")
        for i, line in enumerate(lines[:-1]):
            if line.strip() == "Syntax":
                s = lines[i + 1].strip()
                mn = s.split()[0]
                syntax[mn] = [t for t in re.split(r"[ ,]+", s)[1:] if t]
                page.setdefault(mn, pno)
    return syntax, page


def sprs(path):
    text = html.unescape(re.sub(r"<[^>]+>", " ", open(path, encoding="utf-8", errors="replace").read()))
    found = {}
    for num, name in re.findall(r"\n\s*([0-9a-f]{4})\s+([A-Z][A-Z0-9_]+)\s", text):
        found.setdefault(name, int(num, 16))
    return found


def main():
    pdf, spr_html, out_isa, out_spr = sys.argv[1:5]
    syntax, page = syntax_lines(pdf)
    rows, problems = [], []
    for pno, mn, pipe, mask, value, labels, letters in figures(pdf):
        operands, constants = {}, {}
        for label in labels:
            field, _, role = label.partition(" - ")
            base = re.sub(r"\[\d+:\d+\]$", "", field)
            role = re.sub(r"\[\d+:\d+\]$", "", role)
            if base not in FIELDS:
                continue                       # opcode fields: fixed, already in mask/value
            if role == "Reserved 0x0":
                # Reserved fields ("must be 0") are drawn as fixed boxes, but GNU objdump decodes
                # these instructions whatever the field holds; leave them out of the fixed bits.
                mask &= ~field_mask(base)
                value &= ~field_mask(base)
                continue
            if re.fullmatch(r"0x[0-9A-Fa-f]+", role):
                fixed = int(role, 16)
                want = sum(((fixed >> sum(h - l + 1 for l, h in FIELDS[base][:i])) & ((1 << (hi - lo + 1)) - 1)) << lo
                           for i, (lo, hi) in enumerate(FIELDS[base]))
                if mask & field_mask(base) != field_mask(base) or value & field_mask(base) != want:
                    mask |= field_mask(base)
                    value = value & ~field_mask(base) | want
                constants[re.sub(r"\[\d+:\d+\]$", "", base.split("_")[0])] = fixed
                continue
            operands[role] = base
        # every operand field must be free and every letter box must lie inside an operand field
        for base in operands.values():
            if mask & field_mask(base):
                problems.append(f"{mn} {pipe}: operand {base} overlaps fixed bits")
        for t, bit in letters:
            if "Reserved" in t:
                continue
            if not any(lo <= bit <= hi for f in operands.values() for lo, hi in FIELDS[f]):
                problems.append(f"{mn} {pipe}: letter box {t!r} at bit {bit} outside operand fields")
        order = []
        for token in syntax[mn]:
            if token not in operands and token in constants:
                order.append(f"{token}=#{constants[token]}")   # e.g. ld_tls's Imm8, fixed at 0
                continue
            if token not in operands:
                problems.append(f"{mn} {pipe}: syntax operand {token} has no field ({operands})")
                continue
            order.append(f"{token}={operands[token]}")
        if len([o for o in order if '#' not in o]) != len(operands):
            problems.append(f"{mn} {pipe}: fields {operands} vs syntax {syntax[mn]}")
        rows.append((pipe, mn, mask, value, order, page[mn]))
    # drop the documented duplicate of an alias where both names share one encoding
    keep = {(r[0], r[2], r[3]): r for r in rows if r[1] in ALIASES.values()}
    rows = [r for r in rows if not (r[1] in ALIASES and (r[0], r[2], r[3]) in keep)]
    if problems:
        sys.exit("\n".join(problems))
    rows.sort(key=lambda r: ("X0 X1 Y0 Y1 Y2".split().index(r[0]), r[1]))
    with open(out_isa, "w") as f:
        f.write("# TILE-Gx encodings extracted from Tilera UG401 (TILE-Gx Instruction Set Architecture) by\n"
                "# ug401_extract.py. Columns: pipe, mnemonic, fixed-bit mask, fixed-bit value (64-bit\n"
                "# bundle), operands in syntax order as role=field, manual page.\n")
        for pipe, mn, mask, value, order, pno in rows:
            f.write(f"{pipe}\t{mn}\t{mask:016x}\t{value:016x}\t{','.join(order) or '-'}\t{pno}\n")
    with open(out_spr, "w") as f:
        f.write("# TILE-Gx special-purpose registers (number, name) from the MDE 4.3.4 SPR reference.\n")
        for name, num in sorted(sprs(spr_html).items(), key=lambda kv: (kv[1], kv[0])):
            f.write(f"{num:04x}\t{name}\n")
    if len(sys.argv) > 5:
        with open(sys.argv[5], "w") as f:
            f.write("@UG401-ISA.pdf [TILE-Gx Instruction Set Architecture, UG401]\n")
            for mn in sorted(page):
                f.write(f"{mn}, {page[mn]}\n")
    print(f"{len(rows)} encodings, {len({r[1] for r in rows})} mnemonics")


if __name__ == "__main__":
    main()
