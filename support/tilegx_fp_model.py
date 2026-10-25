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
"""Reference model of the TILE-Gx floating-point helper instructions, as the SLEIGH implements them.

    tilegx_fp_model.py [count]     self-test: GCC's code sequences against IEEE 754 results

TILE-Gx has no floating-point unit. GCC builds every single and double add, subtract, multiply,
compare and integer conversion from fsingle_* / fdouble_* helper instructions (gcc/config/tilegx/
tilegx.md). UG401 documents the comparison flags (Table 7-2: bits 25-31 of fsingle_add1/sub1 and
fdouble_add_flags/sub_flags) and nothing else of the intermediate values. What GCC's own
expansions put into those intermediates pins down the rest of the layout this model uses:

  fsingle unpacked (input of fsingle_pack1/pack2, built by GCC for int->float):
      bits 0-9 exponent E (two's complement), bit 10 sign, bits 32-63 mantissa M,
      value = M * 2^(E - 158)                        (floatsisf: E = 0x9e, M = |int|)
  fdouble unpacked mantissa (fdouble_unpack_*, input of the integer multiplies in muldf3):
      the 53-bit significand with its hidden bit at bit 59, so the high bits stay clear
  fdouble flags (fdouble_*_flags, input of fdouble_pack1/pack2, built by GCC for int->double):
      bits 7-19 exponent E (two's complement), bit 20 sign,
      value = M * 2^(E - 1082)                       (floatsidf: E = 0x21b00 >> 7, M = |int| << 4)

Bits the manual and GCC leave open are this model's own choice and are marked (model):
  bit 21 NaN result, bit 22 infinite result, bit 24 effective subtraction (fdouble flags; the
  fsingle unpacked word uses bits 11 NaN, 12 infinity, 13 effective subtraction, and fsingle_add1/
  sub1 keep the requested operation in bit 24); fsingle_mul1 keeps the first operand's significand
  in bits 32-55; fdouble_pack1 and fsingle_pack1 pass their flags through. Results round to nearest
  even, keep subnormals, and every NaN result is the default quiet NaN (positive).
"""
import random
import struct
import sys

M64 = (1 << 64) - 1


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def cmp_flags(a, b, bits):
    """UG401 Table 7-2: 25 unordered, 26 lt, 27 le, 28 gt, 29 ge, 30 eq, 31 ne."""
    fa, fb = (unpack_f(a), unpack_f(b)) if bits == 32 else (unpack_d(a), unpack_d(b))
    un = fa != fa or fb != fb
    f = 0
    if un:
        f |= 1 << 25
    else:
        f |= (fa < fb) << 26 | (fa <= fb) << 27 | (fa > fb) << 28 | (fa >= fb) << 29 | (fa == fb) << 30
    f |= (un or fa != fb) << 31
    return f


def unpack_f(x):
    return struct.unpack("<f", struct.pack("<I", x & 0xffffffff))[0]


def unpack_d(x):
    return struct.unpack("<d", struct.pack("<Q", x & M64))[0]


def shr_sticky(v, n):
    if n <= 0:
        return v
    if n >= 64:
        return int(v != 0)
    return (v >> n) | int(v & ((1 << n) - 1) != 0)


# ---- single precision --------------------------------------------------------------------------

def s_fields(x):
    e = (x >> 23) & 0xff
    f = x & 0x7fffff
    return (x >> 31) & 1, max(e, 1), (f | (1 << 23)) if e else f, e == 0xff and f != 0, e == 0xff and f == 0


def fsingle_addsub1(a, b, sub):
    return cmp_flags(a, b, 32) | (int(sub) << 24)


def fsingle_addsub2(tmp, a, b):
    sub = (tmp >> 24) & 1
    b = (b & 0xffffffff) ^ (sub << 31)
    a &= 0xffffffff
    big, small = (a, b) if (a & 0x7fffffff) >= (b & 0x7fffffff) else (b, a)
    sg, eg, mg, nan_g, inf_g = s_fields(big)
    ss, es, ms, nan_s, inf_s = s_fields(small)
    effsub = sg != ss
    nan = nan_g or nan_s or (inf_g and inf_s and effsub)
    inf = (inf_g or inf_s) and not nan
    mg <<= 6
    ms = shr_sticky(ms << 6, eg - es)
    m = (mg - ms) if effsub else (mg + ms)
    sign = 0 if (m == 0 and effsub) else sg
    return (m << 32) | (int(effsub) << 13) | (int(inf) << 12) | (int(nan) << 11) | (sign << 10) | ((eg + 2) & 0x3ff)


def fsingle_mul1(a, b):
    sa, ea, ma, nan_a, inf_a = s_fields(a)
    sb, eb, mb, nan_b, inf_b = s_fields(b)
    zero_a, zero_b = (a & 0x7fffffff) == 0, (b & 0x7fffffff) == 0
    nan = nan_a or nan_b or (inf_a and zero_b) or (inf_b and zero_a)
    inf = (inf_a or inf_b) and not nan
    return (ma << 32) | (int(inf) << 12) | (int(nan) << 11) | ((sa ^ sb) << 10) | ((ea + eb - 126) & 0x3ff)


def fsingle_mul2(tmp1, b):
    _, _, mb, _, _ = s_fields(b)
    ma = (tmp1 >> 32) & 0xffffff
    p = ma * mb
    k = 48 - p.bit_length() if p else 0         # normalize (subnormal operands) before truncating
    m = shr_sticky(p << k, 16) & 0xffffffff
    return (m << 32) | (tmp1 & 0x1c00) | ((tmp1 - k) & 0x3ff)


def fsingle_pack1(tmp):
    return tmp


def fsingle_pack2(tmp, flags):
    sign = (tmp >> 10) & 1
    if (tmp >> 11) & 1:
        return 0x7fc00000
    if (tmp >> 12) & 1:
        return (sign << 31) | 0x7f800000
    m = (tmp >> 32) & 0xffffffff
    if m == 0:
        return sign << 31
    lz = 32 - m.bit_length()
    m <<= lz
    e = sx(tmp, 10) - lz
    if e >= 255:
        return (sign << 31) | 0x7f800000
    if e <= 0:
        m = shr_sticky(m, 1 - e)
        e = 1
    mant, rest = m >> 8, m & 0xff
    up = int(rest > 0x80 or (rest == 0x80 and mant & 1))
    return (sign << 31) | (((e - 1) << 23) + mant + up)


# ---- double precision --------------------------------------------------------------------------

def d_fields(x):
    e = (x >> 52) & 0x7ff
    f = x & ((1 << 52) - 1)
    return (x >> 63) & 1, max(e, 1), (f | (1 << 52)) if e else f, e == 0x7ff and f != 0, e == 0x7ff and f == 0


def d_order(a, b):
    return (a, b) if (a & (M64 >> 1)) >= (b & (M64 >> 1)) else (b, a)


def fdouble_unpack_minmax(a, b, want_min):
    big, small = d_order(a, b)
    _, eg, mg, _, _ = d_fields(big)
    _, es, ms, _, _ = d_fields(small)
    return shr_sticky(ms << 7, eg - es) if want_min else (mg << 7)


def fdouble_addsub_flags(a, b, sub):
    bb = b ^ (int(sub) << 63)
    big, small = d_order(a, bb)
    sg, eg, _, nan_g, inf_g = d_fields(big)
    ss, _, _, nan_s, inf_s = d_fields(small)
    effsub = sg != ss
    nan = nan_g or nan_s or (inf_g and inf_s and effsub)
    inf = (inf_g or inf_s) and not nan
    return (cmp_flags(a, b, 64) | (int(effsub) << 24) | (int(inf) << 22) | (int(nan) << 21) |
            (sg << 20) | ((eg & 0x1fff) << 7))


def fdouble_mul_flags(a, b):
    sa, ea, _, nan_a, inf_a = d_fields(a)
    sb, eb, _, nan_b, inf_b = d_fields(b)
    zero_a, zero_b = (a & (M64 >> 1)) == 0, (b & (M64 >> 1)) == 0
    nan = nan_a or nan_b or (inf_a and zero_b) or (inf_b and zero_a)
    inf = (inf_a or inf_b) and not nan
    return (int(inf) << 22) | (int(nan) << 21) | ((sa ^ sb) << 20) | (((ea + eb - 1018) & 0x1fff) << 7)


def fdouble_addsub(dest, min_m, flags):
    return ((dest - min_m) if (flags >> 24) & 1 else (dest + min_m)) & M64


def fdouble_pack1(m, flags):
    return flags


def fdouble_pack2(dest, m, low):
    flags = dest
    sign = (flags >> 20) & 1
    if (flags >> 21) & 1:
        return 0x7ff8000000000000
    if (flags >> 22) & 1:
        return (sign << 63) | 0x7ff0000000000000
    if m == 0:
        return 0 if (flags >> 24) & 1 else sign << 63
    lz = 64 - m.bit_length()
    sticky = int((low << lz) & M64 != 0)
    m = ((m << lz) | (low >> (64 - lz) if lz else 0)) & M64
    e = sx(flags >> 7, 13) - lz + 4
    if e >= 2047:
        return (sign << 63) | 0x7ff0000000000000
    if e <= 0:
        m = shr_sticky(m, 1 - e)
        e = 1
    mant, rest = m >> 11, (m & 0x7ff) | sticky
    up = int(rest > 0x400 or (rest == 0x400 and mant & 1))
    return (sign << 63) | (((e - 1) << 52) + mant + up)


# ---- GCC's sequences (tilegx.md) ---------------------------------------------------------------

def addsf3(a, b, sub=False):
    tmp = fsingle_addsub1(a, b, sub)
    tmp = fsingle_addsub2(tmp, a, b)
    return fsingle_pack2(tmp, fsingle_pack1(tmp))


def mulsf3(a, b):
    t2 = fsingle_mul2(fsingle_mul1(a, b), b)
    return fsingle_pack2(t2, fsingle_pack1(t2))


def adddf3(a, b, sub=False):
    mn = fdouble_unpack_minmax(a, b, True)
    mx = fdouble_unpack_minmax(a, b, False)
    flags = fdouble_addsub_flags(a, b, sub)
    mx = fdouble_addsub(mx, mn, flags)
    return fdouble_pack2(fdouble_pack1(mx, flags), mx, 0)


def muldf3(a, b):
    au = fdouble_unpack_minmax(a, 0, False)
    bu = fdouble_unpack_minmax(b, 0, False)
    flags = fdouble_mul_flags(a, b)
    p = au * bu
    return fdouble_pack2(fdouble_pack1(p >> 64, flags), p >> 64, p & M64)


def floatsisf(i):
    s = int(i < 0)
    tmp = 0x9e | (s << 10) | ((abs(i) & 0xffffffff) << 32)
    return fsingle_pack2(tmp, fsingle_pack1(tmp))


def floatsidf(i):
    s = int(i < 0)
    flags = 0x21b00 | (s << 20)
    m = (abs(i) << 4) & M64
    return fdouble_pack2(fdouble_pack1(m, flags), m, 0)


# ---- self-test ---------------------------------------------------------------------------------

def rand_f(r):
    k = r.random()
    if k < 0.1:
        return r.choice([0, 0x80000000, 0x7f800000, 0xff800000, 0x7fc00000, 0x00000001, 0x007fffff,
                         0x00800000, 0x7f7fffff, 0x3f800000, 0xbf800000, 0x34000000])
    if k < 0.2:
        return r.getrandbits(23) | (r.getrandbits(1) << 31)          # subnormal
    if k < 0.4:                                                      # close exponents
        return (r.getrandbits(1) << 31) | ((120 + r.getrandbits(3)) << 23) | r.getrandbits(23)
    return r.getrandbits(32)


def rand_d(r):
    k = r.random()
    if k < 0.1:
        return r.choice([0, 1 << 63, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 1,
                         0x000fffffffffffff, 0x0010000000000000, 0x7fefffffffffffff, 0x3ff0000000000000])
    if k < 0.2:
        return r.getrandbits(52) | (r.getrandbits(1) << 63)
    if k < 0.4:
        return (r.getrandbits(1) << 63) | ((1020 + r.getrandbits(3)) << 52) | r.getrandbits(52)
    return r.getrandbits(64)


def same(x, y, bits):
    f = unpack_f if bits == 32 else unpack_d
    return x == y or (f(x) != f(x) and f(y) != f(y))


def ieee_f(op, a, b):
    fa, fb = unpack_f(a), unpack_f(b)
    try:
        v = op(fa, fb)
        return struct.unpack("<I", struct.pack("<f", v))[0]
    except OverflowError:
        return 0x7f800000 | ((1 if op(fa, fb) < 0 else 0) << 31)


def selftest(n):
    r = random.Random(1)
    bad = 0
    import math
    def f32(v):
        # round a double (exact result of a single op) to single; struct raises on overflow
        try:
            return struct.unpack("<I", struct.pack("<f", v))[0]
        except OverflowError:
            return (0x7f800000 | (int(math.copysign(1, v) < 0) << 31))
    for _ in range(n):
        a, b = rand_f(r), rand_f(r)
        fa, fb = unpack_f(a), unpack_f(b)
        for name, got, want in (("add", addsf3(a, b), f32(fa + fb)), ("sub", addsf3(a, b, True), f32(fa - fb)),
                                ("mul", mulsf3(a, b), f32(fa * fb))):
            if not same(got, want, 32):
                bad += 1
                if bad < 20:
                    print(f"single {name} {a:08x} {b:08x}: model {got:08x} ieee {want:08x}")
        da, db = rand_d(r), rand_d(r)
        xa, xb = unpack_d(da), unpack_d(db)
        def d64(v):
            return struct.unpack("<Q", struct.pack("<d", v))[0]
        for name, got, want in (("add", adddf3(da, db), d64(xa + xb)), ("sub", adddf3(da, db, True), d64(xa - xb)),
                                ("mul", muldf3(da, db), d64(xa * xb))):
            if not same(got, want, 64):
                bad += 1
                if bad < 20:
                    print(f"double {name} {da:016x} {db:016x}: model {got:016x} ieee {want:016x}")
        i = sx(r.getrandbits(32), 32)
        if floatsisf(i) != f32(float(i)) or floatsidf(i) != d64(float(i)):
            bad += 1
            print("int conversion", i)
    print(f"{n} rounds: {bad} mismatches")
    return bad


if __name__ == "__main__":
    sys.exit(1 if selftest(int(sys.argv[1]) if len(sys.argv) > 1 else 200000) else 0)
