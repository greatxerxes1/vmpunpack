#!/usr/bin/env python3
"""Fill empty ordinal export slots in an emulation-root DLL with a ret-stub, so guest ntdll can resolve
imports-by-ordinal that this DLL version leaves as holes (fixes VMP loader STATUS_ORDINAL_NOT_FOUND /
Emulation terminated with status C0000138).

Usage: patch_ordinal.py [--force] <dll> <ordinal> [ordinal...]   (edits in place, keeps a .bak)

Only EMPTY slots are filled. --force also overwrites a live export, which silently breaks that API for
every future run against this emulation root - in this emu_root ntdll has 0 empty slots out of 2540,
so an unguarded write almost always clobbers something real.

The PE parsing comes from pe.py, the same bounds-checked code the automatic gap-fill uses.
"""
import os, shutil, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import BadPE, export_dir, find_ret, u32

force = "--force" in sys.argv
argv = [a for a in sys.argv[1:] if a != "--force"]
if len(argv) < 2: sys.exit(__doc__)
p = argv[0]
try: ords = [int(x, 0) for x in argv[1:]]
except ValueError as e: sys.exit(f"[!] bad ordinal: {e}")

try:
    with open(p, "rb") as fh: f = bytearray(fh.read())
    d = export_dir(f)
except (BadPE, struct.error) as e:
    sys.exit(f"[!] {p}: {e}")
except OSError as e:
    sys.exit(f"[!] {e}")
if not d: sys.exit(f"[!] {p}: no readable export directory")

ret_rva = find_ret(d["secs"], f)
if ret_rva is None: sys.exit("[!] no ret byte found")
Base, nFunc, afo = d["Base"], d["nFunc"], d["afo"]

changed = refused = 0
for ordv in ords:
    idx = ordv - Base
    if not (0 <= idx < nFunc):
        print(f"ord {ordv}: out of range {Base}..{Base+nFunc-1}"); refused += 1; continue
    old = u32(f, afo + idx*4)
    if old != 0 and not force:
        print(f"ord {ordv}: slot is LIVE (func_rva 0x{old:x}) - refusing without --force"); refused += 1; continue
    if old != 0: print(f"ord {ordv}: WARNING overwriting a LIVE export (func_rva 0x{old:x})")
    struct.pack_into("<I", f, afo + idx*4, ret_rva)
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
