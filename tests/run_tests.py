"""Regression suite for the 12 vmpunpack fixes. Read-only w.r.t. the repo: the module is imported
from its real path, everything it writes is redirected into a scratch tree."""
import importlib.util, sys, os, io, time, shutil, struct, contextlib, tempfile, subprocess, re, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pebuild import build_pe, import_blob, export_blob

REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "vmpunpack", "vmpunpack.py")
PATCH_ORD = os.path.join(REPO, "vmpunpack", "patch_ordinal.py")
LAB = os.path.join(tempfile.gettempdir(), "vmpunpack-tests", "lab")

spec = importlib.util.spec_from_file_location("vmpu", SRC)
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"   [{detail}]" if detail else ""))

def fresh(sub):
    p = os.path.join(LAB, sub)
    shutil.rmtree(p, ignore_errors=True); os.makedirs(p, exist_ok=True)
    return p

TGT_SOI, TGT_ENTRY, TGT_BASE = 0x4000, 0x1000, 0x140000000

def target_bytes(**kw):
    kw.setdefault("entry", TGT_ENTRY); kw.setdefault("base", TGT_BASE); kw.setdefault("size_of_image", TGT_SOI)
    secs = kw.pop("sections", None) or [dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200,
                                             ch=0x60000020, data=b"\x90" * 0x200)]
    return build_pe(secs, **kw)

def meta_text(soi=TGT_SOI, entry=TGT_ENTRY, base=TGT_BASE, oep=0x1100):
    return f"base=0x{base:x}\nsize_of_image=0x{soi:x}\nentry_rva=0x{entry:x}\noep_rva=0x{oep:x}\n"

def dump_image(soi=TGT_SOI, entry=TGT_ENTRY, base=TGT_BASE, secs=None, total=None):
    secs = secs or [dict(name=b".text", va=0x1000, vs=0x200, rp=0x1000, rs=0x200,
                         ch=0x60000020, data=b"\xcc" * 0x200)]
    return build_pe(secs, entry=entry, base=base, size_of_image=soi, total=total or soi)

# ---------------------------------------------------------------- main() harness
def run_main(argv, writer, *, sogen=None, emuroot=None, dumps=None, rc=0, err="", timeout=False, log=""):
    """writer(dumps_dir, t0) puts files into the fake C:\\dumps. Returns (exit_code, stdout)."""
    lab = fresh("main")
    dumps = dumps or os.path.join(lab, "dumps"); os.makedirs(dumps, exist_ok=True)
    sogen = sogen or os.path.join(lab, "sogen"); os.makedirs(sogen, exist_ok=True)
    open(os.path.join(sogen, "analyzer.exe"), "wb").close()
    emuroot = emuroot or os.path.join(lab, "emu")
    for sub in ("registry", "filesys"): os.makedirs(os.path.join(emuroot, sub), exist_ok=True)
    old_dumps, old_run, old_argv = V.DUMPS, V.run_analyzer, sys.argv
    V.DUMPS = dumps
    def fake(args):
        t0 = time.time() - V.MTIME_SLACK
        writer(dumps, t0)
        return dict(log=log, err=err, rc=rc, timeout=timeout, t0=t0)
    V.run_analyzer = fake
    sys.argv = ["vmpunpack.py"] + argv + ["--sogen", sogen, "--emuroot", emuroot]
    buf = io.StringIO(); code = 0
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            V.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        if isinstance(e.code, str): buf.write(e.code + "\n")
    finally:
        V.DUMPS, V.run_analyzer, sys.argv = old_dumps, old_run, old_argv
    return code, buf.getvalue()

def std_case(sub, **kw):
    lab = fresh(sub)
    tp = os.path.join(lab, "sample_B.exe")
    with open(tp, "wb") as f: f.write(target_bytes(**kw))
    return lab, tp

# ================================================================ FIX 1
print("\n=== FIX 1: dump identity / stale C:\\dumps ===")

lab, tp = std_case("f1a")
out = os.path.join(lab, "out")
def w_stale(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
    old = time.time() - 3600
    for n in ("unpacked.bin", "unpacked.meta"): os.utime(os.path.join(d, n), (old, old))
code, sout = run_main([tp, "-o", out], w_stale)
check("1a stale-mtime dump is refused", code != 0 and "predates this run" in sout, f"code={code}")
check("1a nothing published", not os.path.exists(os.path.join(out, "sample_B.unpacked.exe")))

lab, tp = std_case("f1b")
out = os.path.join(lab, "out")
def w_wrongsample(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image(soi=0x9000, entry=0x2000))
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi=0x9000, entry=0x2000))
code, sout = run_main([tp, "-o", out], w_wrongsample)
check("1b foreign dump (SizeOfImage/entry mismatch) refused", code != 0 and "does not describe this target" in sout)
check("1b nothing published", not os.path.exists(os.path.join(out, "sample_B.unpacked.exe")))

lab, tp = std_case("f1c")
out = os.path.join(lab, "out")
def w_good(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
code, sout = run_main([tp, "-o", out], w_good)
check("1c happy path still publishes", code == 0 and "DONE" in sout, f"code={code}")
check("1c reconstructed exe written", os.path.isfile(os.path.join(out, "sample_B.unpacked.exe")))
if os.path.isfile(os.path.join(out, "sample_B.unpacked.exe")):
    with open(os.path.join(out, "sample_B.unpacked.exe"), "rb") as f: rb = f.read()
    pe = struct.unpack_from("<I", rb, 0x3c)[0]
    check("1c entry set to OEP 0x1100", struct.unpack_from("<I", rb, pe+24+16)[0] == 0x1100)

lab, tp = std_case("f1d")
out = os.path.join(lab, "out")
def w_partialmeta(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write("base=0x140000000\n")
code, sout = run_main([tp, "-o", out], w_partialmeta)
check("1d meta missing keys refused", code != 0 and "missing" in sout)
check("1d nothing copied into out", not os.path.exists(os.path.join(out, "unpacked.bin")))

lab, tp = std_case("f1e")
out = os.path.join(lab, "out")
def w_emptymeta(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    open(os.path.join(d, "unpacked.meta"), "wb").close()
code, sout = run_main([tp, "-o", out], w_emptymeta)
check("1e zero-byte meta refused (no KeyError)", code != 0 and "no unpacked image produced" in sout)

lab, tp = std_case("f1f")
out = os.path.join(lab, "out")
def w_badoep(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(oep=0x99999))
code, sout = run_main([tp, "-o", out], w_badoep)
check("1f oep outside image refused", code != 0 and "outside the image" in sout)

# cleanup loop must be fatal, not silent
lab = fresh("f1g"); dumps = os.path.join(lab, "dumps"); os.makedirs(dumps)
stale = os.path.join(dumps, "unpacked.bin")
with open(stale, "wb") as f: f.write(b"OLD SAMPLE A IMAGE")
hold = open(stale, "rb")                      # keep a handle open -> os.remove raises PermissionError
old_dumps = V.DUMPS; V.DUMPS = dumps
class A: pass
a = A(); a.target = os.path.join(lab, "s.exe"); a.emuroot = os.path.join(lab, "emu")
a.sogen = lab; a.run_payload = False; a.nodelay = False; a.tsc = None; a.oep = None
a.late = None; a.timeout = 5
with open(a.target, "wb") as f: f.write(target_bytes())
got = ""
try:
    with contextlib.redirect_stdout(io.StringIO()):
        V.run_analyzer(a)
    got = "<returned normally>"
except SystemExit as e:
    got = str(e.code)
except Exception as e:
    got = f"{type(e).__name__}: {e}"
finally:
    hold.close(); V.DUMPS = old_dumps
check("1g undeletable stale dump aborts the run", "cannot clear stale" in got, got[:90])

# ================================================================ FIX 2
print("\n=== FIX 2: reconstruct_pe header validation ===")
o2 = fresh("f2")
try:
    V.reconstruct_pe(b"\x00" * 0x3000, {"oep_rva": "0x1b3dc"}, os.path.join(o2, "x.exe"))
    check("2a zeroed header page rejected", False, "no exception")
except V.BadPE as e:
    check("2a zeroed header page rejected", True, str(e)[:50])
except Exception as e:
    check("2a zeroed header page rejected", False, f"{type(e).__name__}")
check("2a no file emitted", not os.path.exists(os.path.join(o2, "x.exe")))

img = dump_image(secs=[dict(name=b".data", va=0x1000, vs=0, rp=0x1000, rs=0x1000,
                            ch=0xC0000040, data=b"S" * 0x1000)])
V.reconstruct_pe(img, {"oep_rva": "0x1000"}, os.path.join(o2, "vs0.exe"))
with open(os.path.join(o2, "vs0.exe"), "rb") as f: rb = f.read()
pe = struct.unpack_from("<I", rb, 0x3c)[0]; so = pe + 24 + struct.unpack_from("<H", rb, pe+20)[0]
srd, prd = struct.unpack_from("<II", rb, so + 16)
check("2b VirtualSize==0 section keeps its bytes", srd == 0x1000, f"SizeOfRawData=0x{srd:x}")

img = dump_image(secs=[dict(name=b".text", va=0x1000, vs=0x40000, rp=0x1000, rs=0x200,
                            ch=0x60000020, data=b"\xcc" * 0x200)], total=0x2000)
V.reconstruct_pe(img, {"oep_rva": "0x1000"}, os.path.join(o2, "big.exe"))
with open(os.path.join(o2, "big.exe"), "rb") as f: rb = f.read()
pe = struct.unpack_from("<I", rb, 0x3c)[0]; so = pe + 24 + struct.unpack_from("<H", rb, pe+20)[0]
srd, prd = struct.unpack_from("<II", rb, so + 16)
check("2c inflated VirtualSize clamped to file", prd + srd <= len(rb), f"0x{prd:x}+0x{srd:x} vs 0x{len(rb):x}")

bad = bytearray(dump_image()); bad[0:2] = b"ZM"
try:
    V.reconstruct_pe(bytes(bad), {"oep_rva": "0x1000"}, os.path.join(o2, "nomz.exe")); r = False
except V.BadPE: r = True
check("2d missing MZ rejected", r)

# ================================================================ FIX 3
print("\n=== FIX 3: attacker-controlled DLL name ===")
lab = fresh("f3")
sys32 = os.path.join(lab, "emu", "filesys", "c", "windows", "system32"); os.makedirs(sys32)
victim = os.path.join(lab, "victim.dll")
vic = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020,
                     data=b"\xc3" + b"\x90" * 0x1ff),
                dict(name=b".edata", va=0x2000, vs=0x200, rp=0x600, rs=0x200, ch=0x40000040,
                     data=export_blob(base_rva=0x2000, base_ord=1, func_rvas=[0x1000, 0, 0]).ljust(0x200, b"\0"))],
               dirs={0: (0x2000, 0x200)})
with open(victim, "wb") as f: f.write(vic)
before = open(victim, "rb").read()
inside = os.path.join(sys32, "ws2_32.dll")
with open(inside, "wb") as f: f.write(vic)

class A3: pass
for nm, label in ((victim, "absolute host path"),
                  (r"..\..\..\..\..\..\victim.dll", "..\\ escape"),
                  (r"\\attacker\pub\x.dll", "UNC")):
    a3 = A3(); a3.emuroot = os.path.join(lab, "emu")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        V.gap_fill(a3, [(nm, 2)])
    txt = buf.getvalue()
    check(f"3 {label} refused", "refusing" in txt or "outside the emulation root" in txt, txt.strip()[:70])
check("3 victim outside emu_root untouched", open(victim, "rb").read() == before)

a3 = A3(); a3.emuroot = os.path.join(lab, "emu")
buf = io.StringIO()
with contextlib.redirect_stdout(buf): V.gap_fill(a3, [("ws2_32.dll", 2)])
check("3 legitimate in-root gap-fill still works", "gap-filled" in buf.getvalue(), buf.getvalue().strip()[:70])
buf = io.StringIO()
with contextlib.redirect_stdout(buf): V.gap_fill(a3, [("ws2_32.dll", 1)])
check("3 live slot reported, not overwritten", "already populated" in buf.getvalue())
buf = io.StringIO()
with contextlib.redirect_stdout(buf): V.gap_fill(a3, [("ws2_32.dll", 900)])
check("3 out-of-range ordinal explained (fix 11)", "outside this DLL's export range" in buf.getvalue()
      and "1..3" in buf.getvalue(), buf.getvalue().strip()[:100])

# ================================================================ FIX 4 + 9
print("\n=== FIX 4/9: IOC extraction ===")
d, u, i = V.grep_iocs(b"\x00 10.0.0.5 5.2.75.14 6.1.44.9 91.243.59.7 192.168.1.9 \x00")
check("4a RFC1918/5.x/6.x C2 IPs no longer dropped",
      {"10.0.0.5", "5.2.75.14", "6.1.44.9", "91.243.59.7", "192.168.1.9"} <= set(i), str(i))
d, u, i = V.grep_iocs(b"\x00 999.1.1.1 0.0.0.0 127.0.0.1 \x00")
check("4a invalid/loopback octets still filtered", i == [], str(i))

w = "http://wide-c2.xyz/gate.php 45.66.77.88".encode("utf-16le")
d, u, i = V.grep_iocs(b"\x00\x00" + w + b"\x00\x00")
check("4b wide URL extracted", any("wide-c2.xyz/gate.php" in x for x in u), str(u))
check("4b wide IP extracted", "45.66.77.88" in i, str(i))
d, u, i = V.grep_iocs(b"\x00" + w + b"\x00\x00")
check("4b odd-aligned wide string extracted", "wide-c2.xyz" in d and any("gate.php" in x for x in u), f"{d} {u}")

d, u, i = V.grep_iocs(b"http://windows-defender-update.top/gate.php")
check("4c MS-impersonating host survives NOISE", "windows-defender-update.top" in d and len(u) == 1, f"{d} {u}")
d, u, i = V.grep_iocs(b"http://evil-plain.top/windows/gate.php")
check("4c noise word in path no longer kills the URL", len(u) == 1 and "evil-plain.top" in d, f"{d} {u}")
d, u, i = V.grep_iocs(b"http://schemas.microsoft.com/foo http://crl.digicert.com/x.crl")
check("4c genuine noise still filtered", d == [] and u == [], f"{d} {u}")

d, u, i = V.grep_iocs(b"http://c2.top/a\x81b and more")
check("9 high byte no longer captured into the URL", all("\x81" not in x for x in u), str(u))
o9 = fresh("f9")
with open(os.path.join(o9, "iocs.txt"), "w", encoding="utf-8", errors="backslashreplace") as f:
    f.write("urls: " + ", ".join(u) + "\n")
check("9 iocs.txt writes without UnicodeEncodeError", os.path.getsize(os.path.join(o9, "iocs.txt")) > 0)

big = (b"\x00" * (64 << 20)) + b" http://chunk-edge-c2.top/x "
t = time.time(); d, u, i = V.grep_iocs(big); dt = time.time() - t
check("4 chunked scan finds a match past the first chunk", any("chunk-edge-c2.top" in x for x in u), f"{dt:.1f}s")

# ================================================================ FIX 5 + 4d
print("\n=== FIX 5/4d: output dir hygiene + late dumps ===")
lab, tp = std_case("f5"); out = os.path.join(lab, "out"); os.makedirs(out)
with open(os.path.join(out, "heap.bin"), "wb") as f: f.write(b"STALE RUN-1 HEAP evil-old-c2.top")
def w_nolate(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
code, sout = run_main([tp, "-o", out], w_nolate)
check("5 stale heap.bin purged from out", code == 0 and not os.path.exists(os.path.join(out, "heap.bin")))

lab, tp = std_case("f5b"); out = os.path.join(lab, "out")
def w_late(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
    with open(os.path.join(d, "unpacked_late.bin"), "wb") as f: f.write(b"late http://late-only-c2.top/cfg")
    with open(os.path.join(d, "heap.bin"), "wb") as f: f.write(b"heap 45.11.22.33")
code, sout = run_main([tp, "-o", out, "--late", "5000", "--run-payload"], w_late)
ioc = open(os.path.join(out, "iocs.txt"), encoding="utf-8").read() if os.path.exists(os.path.join(out, "iocs.txt")) else ""
check("4d late dump IOCs reach iocs.txt", "late-only-c2.top" in ioc, ioc[:120].replace("\n", " | "))
check("4d heap IOCs reach iocs.txt", "45.11.22.33" in ioc)
check("4d iocs.txt is per-source", "[unpacked_late.bin]" in ioc and "[heap.bin]" in ioc)

# ================================================================ FIX 6
print("\n=== FIX 6: bounded import walk ===")
imp = import_blob("ws2_32.dll", [7, 9], base_rva=0x2000, terminate_thunks=False)
pe6 = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020, data=b"\x90"*0x200),
                dict(name=b".idata", va=0x2000, vs=len(imp), rp=0x600, rs=len(imp), ch=0xC0000040, data=imp)],
               dirs={1: (0x2000, 40)})
try:
    r = V.ordinal_imports(pe6); ok = True; why = str(r)
except Exception as e:
    ok = False; why = f"{type(e).__name__}: {e}"
check("6a unterminated thunk array does not raise", ok, why[:80])

hostile = bytearray(build_pe([dict(name=b".text", va=0x1000, vs=0x20000, rp=0x400, rs=0x20000,
                                   ch=0x60000020, data=b"\x11" * 0x20000)],
                             dirs={1: (0x1000, 0)}, total=0x21000))
t = time.time()
try:
    r = V.ordinal_imports(bytes(hostile)); ok = True; why = f"{len(r)} entries"
except Exception as e:
    ok = False; why = f"{type(e).__name__}"
dt = time.time() - t
check("6b hostile import dir is bounded (<5s, capped)", ok and dt < 5.0, f"{dt:.2f}s {why}")

lab, tp = std_case("f6c", sections=[dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200,
                                         ch=0x60000020, data=b"\x90"*0x200)])
with open(tp, "wb") as f:
    b = bytearray(target_bytes()); pe = struct.unpack_from("<I", b, 0x3c)[0]
    dd = pe + 24 + 112; struct.pack_into("<II", b, dd + 8, 0xDEADBEEF, 0x100)   # import dir into nowhere
    f.write(bytes(b))
code, sout = run_main([tp, "-o", os.path.join(lab, "out")], w_good)
check("6c unresolvable import dir does not traceback", "Traceback" not in sout and code == 0, sout[-90:].strip())

# ================================================================ FIX 7
print("\n=== FIX 7: analyzer rc / stderr / timeout surfaced ===")
lab, tp = std_case("f7"); out = os.path.join(lab, "out")
code, sout = run_main([tp, "-o", out], lambda d, t0: None, rc=1,
                      err="FATAL: Bad hive file 'SOFTWARE' - looks like a Git LFS pointer")
check("7a stderr surfaced", "Bad hive file" in sout and "analyzer stderr" in sout)
check("7a exit code surfaced", "analyzer exited 1" in sout)
lab, tp = std_case("f7b"); out = os.path.join(lab, "out")
code, sout = run_main([tp, "-o", out], w_good, timeout=True)
check("7b timeout reported but a valid dump still publishes", "timeout and was killed" in sout and code == 0,
      f"code={code}")

# ================================================================ FIX 8
print("\n=== FIX 8: patch_ordinal.py guards ===")
lab = fresh("f8")
tgt8 = os.path.join(lab, "cryptbase.dll")
with open(tgt8, "wb") as f: f.write(vic)          # ordinals 1..3, slot 1 live (0x1000), 2 and 3 empty
orig = open(tgt8, "rb").read()
def po(*a):
    p = subprocess.run([sys.executable, PATCH_ORD] + list(a), capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")
rc, o = po(tgt8, "1")
check("8a live slot refused by default", rc != 0 and "refusing without --force" in o, o.strip()[:80])
check("8a file untouched", open(tgt8, "rb").read() == orig)
check("8a no .bak created on refusal", not os.path.exists(tgt8 + ".bak"))
rc, o = po(tgt8, "900")
check("8b out-of-range alone exits non-zero", rc != 0 and "nothing changed" in o, o.strip()[:80])
rc, o = po(tgt8, "2")
check("8c empty slot still patched", rc == 0 and "ret stub" in o, o.strip()[:80])
check("8c .bak written", os.path.exists(tgt8 + ".bak"))
check("8c .bak is the original", open(tgt8 + ".bak", "rb").read() == orig)
rc, o = po("--force", tgt8, "1")
check("8d --force overwrites a live slot with a warning", rc == 0 and "WARNING overwriting a LIVE export" in o,
      o.strip()[:80])

# ================================================================ FIX 10
print("\n=== FIX 10: 32-bit target ===")
lab = fresh("f10"); tp = os.path.join(lab, "x86.exe")
with open(tp, "wb") as f:
    f.write(build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020,
                           data=b"\x90"*0x200)], is64=False, base=0x400000))
code, sout = run_main([tp, "-o", os.path.join(lab, "out")], w_good)
check("10 32-bit PE rejected cleanly", code != 0 and "32-bit PE" in sout and "Traceback" not in sout)

lab = fresh("f10b"); tp = os.path.join(lab, "junk.exe")
with open(tp, "wb") as f: f.write(b"not a pe at all" * 10)
code, sout = run_main([tp, "-o", os.path.join(lab, "out")], w_good)
check("10b non-PE rejected cleanly", code != 0 and "unparseable PE" in sout and "Traceback" not in sout)

# ================================================================ summary
print("\n" + "=" * 64)
bad = [n for n, ok, _ in RESULTS if not ok]
print(f"{len(RESULTS) - len(bad)}/{len(RESULTS)} passed")
if bad:
    print("FAILED:")
    for n in bad: print("  -", n)
sys.exit(1 if bad else 0)
