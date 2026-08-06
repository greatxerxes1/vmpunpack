#!/usr/bin/env python3
"""Fill empty ordinal export slots in an emulation-root DLL with a ret-stub, so guest ntdll can resolve
imports-by-ordinal that this DLL version leaves as holes (fixes VMP loader STATUS_ORDINAL_NOT_FOUND /
Emulation terminated with status C0000138).

Usage: patch_ordinal.py [--force] <dll> <ordinal> [ordinal...]   (edits in place, keeps a .bak)

Only EMPTY slots are filled. --force also overwrites a live export, which silently breaks that API for
every future run against this emulation root - in this emu_root ntdll has 0 empty slots out of 2540,
so an unguarded write almost always clobbers something real."""
import sys, struct, shutil, os

force = "--force" in sys.argv
argv = [a for a in sys.argv[1:] if a != "--force"]
if len(argv) < 2: sys.exit(__doc__)
p = argv[0]
try: ords = [int(x, 0) for x in argv[1:]]
except ValueError as e: sys.exit(f"[!] bad ordinal: {e}")

with open(p, "rb") as fh: f = bytearray(fh.read())
if len(f) < 0x40 or f[0:2] != b"MZ": sys.exit(f"[!] {p}: no MZ signature")
pe = struct.unpack_from("<I", f, 0x3c)[0]
if pe + 24 > len(f) or f[pe:pe+4] != b"PE\0\0": sys.exit(f"[!] {p}: no PE signature")
optsz = struct.unpack_from("<H", f, pe+20)[0]
opt = pe+24; is64 = struct.unpack_from("<H", f, opt)[0] == 0x20b; ddoff = opt+(112 if is64 else 96)
if ddoff + 8 > len(f): sys.exit(f"[!] {p}: truncated optional header")
exp_rva, = struct.unpack_from("<I", f, ddoff)
if not exp_rva: sys.exit(f"[!] {p}: no export directory")
nsec = struct.unpack_from("<H", f, pe+6)[0]; so = pe+24+optsz
if so + nsec*40 > len(f): sys.exit(f"[!] {p}: section table runs past end of file")
secs = [struct.unpack_from("<IIII", f, so+i*40+8) for i in range(nsec)]  # vs,va,rs,rp

def r2o(rva, need=1):
    for vs, va, rs, rp in secs:
        if va <= rva < va+max(vs, rs):
            o = rp+(rva-va)
            return o if o >= 0 and o+need <= len(f) else None
    return None

# a ret (0xC3) in the first executable section
ret_rva = None
for i in range(nsec):
    o = so+i*40; ch = struct.unpack_from("<I", f, o+36)[0]; vs, va, rs, rp = struct.unpack_from("<IIII", f, o+8)
    if ch & 0x20000000 and rs and rp+rs <= len(f):
        k = f.find(b"\xc3", rp, rp+rs)
        if k != -1: ret_rva = va+(k-rp); break
if ret_rva is None: sys.exit("[!] no ret byte found")
eo = r2o(exp_rva, 40)
if eo is None: sys.exit(f"[!] {p}: export directory outside the file")
Base, = struct.unpack_from("<I", f, eo+16); nFunc, = struct.unpack_from("<I", f, eo+20)
aFunc, = struct.unpack_from("<I", f, eo+28); afo = r2o(aFunc, max(nFunc, 1)*4)
if afo is None: sys.exit(f"[!] {p}: export address table outside the file")

changed = refused = 0
for ordv in ords:
    idx = ordv-Base
    if not (0 <= idx < nFunc):
        print(f"ord {ordv}: out of range {Base}..{Base+nFunc-1}"); refused += 1; continue
    old, = struct.unpack_from("<I", f, afo+idx*4)
    if old != 0 and not force:
        print(f"ord {ordv}: slot is LIVE (func_rva 0x{old:x}) - refusing without --force"); refused += 1; continue
    if old != 0: print(f"ord {ordv}: WARNING overwriting a LIVE export (func_rva 0x{old:x})")
    struct.pack_into("<I", f, afo+idx*4, ret_rva)
    print(f"ord {ordv}: func_rva 0x{old:x} -> 0x{ret_rva:x} (ret stub)")
    changed += 1

if not changed: sys.exit("nothing changed")
bak = p + ".bak"
if not os.path.exists(bak):
    shutil.copy(p, bak); print(f"backup -> {bak}")
with open(p, "wb") as fh: fh.write(f)
print(f"patched {p} in place ({changed} ordinal(s))")
# a partial apply must not look like a full one to a caller checking the exit code
if refused: sys.exit(f"[!] {refused} ordinal(s) were refused - re-run with --force if you really mean it")
