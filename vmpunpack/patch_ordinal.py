#!/usr/bin/env python3
"""Fill empty ordinal export slots in an emulation-root DLL with a ret-stub, so guest ntdll can resolve
imports-by-ordinal that this DLL version leaves as holes (fixes VMP loader STATUS_ORDINAL_NOT_FOUND /
Emulation terminated with status C0000138). Usage: patch_ordinal.py <dll> <ordinal> [ordinal...]  (edits in place)."""
import sys, struct
p = sys.argv[1]; ords = [int(x, 0) for x in sys.argv[2:]]
f = bytearray(open(p, "rb").read())
pe = struct.unpack_from("<I", f, 0x3c)[0]; optsz = struct.unpack_from("<H", f, pe+20)[0]
opt = pe+24; is64 = struct.unpack_from("<H", f, opt)[0] == 0x20b; ddoff = opt+(112 if is64 else 96)
exp_rva, = struct.unpack_from("<I", f, ddoff)
nsec = struct.unpack_from("<H", f, pe+6)[0]; so = pe+24+optsz
secs = [struct.unpack_from("<IIII", f, so+i*40+8) for i in range(nsec)]  # vs,va,rs,rp
def r2o(rva):
    for vs, va, rs, rp in secs:
        if va <= rva < va+max(vs, rs): return rp+(rva-va)
    return None
# a ret (0xC3) in the first executable section
ret_rva = None
for i in range(nsec):
    o = so+i*40; ch = struct.unpack_from("<I", f, o+36)[0]; vs, va, rs, rp = struct.unpack_from("<IIII", f, o+8)
    if ch & 0x20000000 and rs:
        k = f.find(b"\xc3", rp, rp+rs)
        if k != -1: ret_rva = va+(k-rp); break
if ret_rva is None: sys.exit("no ret byte found")
eo = r2o(exp_rva); Base, = struct.unpack_from("<I", f, eo+16); nFunc, = struct.unpack_from("<I", f, eo+20)
aFunc, = struct.unpack_from("<I", f, eo+28); afo = r2o(aFunc)
for ordv in ords:
    idx = ordv-Base
    if not (0 <= idx < nFunc): print(f"ord {ordv}: out of range {Base}..{Base+nFunc-1}"); continue
    old, = struct.unpack_from("<I", f, afo+idx*4)
    struct.pack_into("<I", f, afo+idx*4, ret_rva)
    print(f"ord {ordv}: func_rva 0x{old:x} -> 0x{ret_rva:x} (ret stub)")
open(p, "wb").write(f)
print(f"patched {p} in place")
