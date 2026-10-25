#!/usr/bin/env python3
"""Compare Ghidra bundle disassembly (DumpSlots.java) with GNU libopcodes (tgxslots) for TILE-Gx.

  compare.py <ghidra.txt> <tgxslots.txt> [examples-per-class]

A bundle is undefined when the reference decodes any slot as <invalid> (objdump prints the other
slots, but the hardware has no partial bundles); Ghidra must reject it too.
exact:    every slot has the same mnemonic and operands after removing blanks and writing every
          number as a signed decimal (Ghidra prints immediates in hex, objdump in decimal)
semantic: additionally branch and jump targets compared modulo 2^32: libopcodes computes them in
          an unsigned int (tilegx-opc.c parse_insn_tilegx), so it truncates targets below 0 or
          above 4 GiB
Classes of differences are keyed by the slot mnemonics.
"""
import re
import sys
from collections import Counter, defaultdict

NUM = re.compile(r"(?<![\w.])(-?)(0x[0-9a-fA-F]+|\d+)(?![\w])")


def load(path, ghidra):
    d = {}
    for line in open(path):
        line = line.rstrip("\n")
        if ghidra:
            off, n, text = line.split(" ", 2)
            if text == "BAD":
                d[int(off, 16)] = None
                continue
            text = text.strip()
            if text.startswith("{") and text.endswith("}"):
                text = text[1:-1]
        else:
            off, _, text = line.partition(" ")
        slots = [s.strip() for s in text.split(" ; ")]
        if not ghidra and any(s == "<invalid>" for s in slots):
            d[int(off, 16)] = None
            continue
        d[int(off, 16)] = slots
    return d


def canon_num(m):
    v = int(m.group(2), 0)
    if m.group(1):
        v = -v
    return str(v)


def norm(slot):
    mn, _, ops = slot.partition(" ")
    ops = ops.replace(" ", "")
    return mn + " " + NUM.sub(canon_num, ops)


BRANCH = re.compile(r"^(j|jal|b\w+)$")


def sem(slot):
    mn, _, ops = slot.partition(" ")
    if BRANCH.match(mn) and ops:
        parts = ops.split(",")
        parts[-1] = str(int(parts[-1]) & 0xffffffff)
        ops = ",".join(parts)
    return mn + " " + ops


def main():
    g = load(sys.argv[1], True)
    o = load(sys.argv[2], False)
    nex = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    total = exact = both_bad = semantic = 0
    classes = Counter()
    examples = defaultdict(list)
    for off in sorted(o):
        if off not in g:
            continue
        total += 1
        gs, os_ = g[off], o[off]
        if gs is None and os_ is None:
            both_bad += 1
            exact += 1
            continue
        if gs is None or os_ is None:
            key = ("ghidra-rejects" if gs is None else "ghidra-accepts", " ; ".join(x.split(" ")[0] for x in (os_ or gs)))
            classes[key] += 1
            if len(examples[key]) < nex:
                examples[key].append((off, gs, os_))
            continue
        gn, on = [norm(x) for x in gs], [norm(x) for x in os_]
        if gn == on:
            exact += 1
            continue
        if [sem(x) for x in gn] == [sem(x) for x in on]:
            semantic += 1
            continue
        for a, b in zip(gn, on):
            if a != b:
                key = ("differs", a.split(" ")[0] + " / " + b.split(" ")[0])
                classes[key] += 1
                if len(examples[key]) < nex:
                    examples[key].append((off, gs, os_))
                break
    diff = total - exact - semantic
    print(f"compared {total} bundles: exact {exact} ({100.0 * exact / max(total, 1):.3f}%), "
          f"semantic {exact + semantic} ({100.0 * (exact + semantic) / max(total, 1):.3f}%), "
          f"both undefined {both_bad}, differences {diff}")
    for key, n in classes.most_common():
        print(f"  {n:6d}  {key[0]}: {key[1]}")
        for off, gs, os_ in examples[key]:
            print(f"          {off:08x}  ghidra: {gs}")
            print(f"                    objdump: {os_}")


if __name__ == "__main__":
    main()
