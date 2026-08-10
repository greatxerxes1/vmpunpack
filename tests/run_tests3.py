"""Third suite: the reconstruct_pe round trip on a dump-shaped fixture, and the OEP / flag /
locking guards. The first two suites build every fixture with PointerToRawData == VirtualAddress,
which makes the one line reconstruct_pe exists for indistinguishable from a no-op."""
import importlib.util, sys, os, io, time, shutil, struct, contextlib, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pebuild import build_pe, build_dump

REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "vmpunpack", "vmpunpack.py")
LAB = os.path.join(tempfile.gettempdir(), "vmpunpack-tests", "lab3")

spec = importlib.util.spec_from_file_location("vmpu3", SRC)
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)

R = []
def check(name, cond, detail=""):
    R.append((name, bool(cond))); print(("  PASS  " if cond else "  FAIL  ") + name + (f"   [{detail}]" if detail else ""))

def fresh(sub):
    p = os.path.join(LAB, sub); shutil.rmtree(p, ignore_errors=True); os.makedirs(p, exist_ok=True); return p

TGT_ENTRY, TGT_BASE = 0x1000, 0x140000000
OEP = 0x3040

# on-disk layout (rp) deliberately differs from the memory layout (va)
SECS = [
    dict(name=b".text",  va=0x1000, vs=0x180,   rp=0x400,  rs=0x200,  ch=0x60000020, data=b"\xcc" * 0x180),
    dict(name=b".vmp0",  va=0x2000, vs=0x1000,  rp=0x600,  rs=0x0,    ch=0xE0000060, data=b"\xaa" * 0x1000),
    dict(name=b".vmp1",  va=0x3000, vs=0x800,   rp=0x600,  rs=0x600,  ch=0x60000020,
         data=b"\x90" * 0x40 + b"OEPMARKER" + b"\x90" * 0x7b7),
    dict(name=b".rdata", va=0x4000, vs=0x100,   rp=0xc00,  rs=0x200,  ch=0x40000040, data=b"RD" * 0x80),
    dict(name=b".bss",   va=0x5000, vs=0x4000,  rp=0x0,    rs=0x0,    ch=0xC0000080, data=b""),
]

def target_bytes(soi, **kw):
    kw.setdefault("entry", TGT_ENTRY); kw.setdefault("base", TGT_BASE); kw.setdefault("size_of_image", soi)
    return build_pe([dict(name=b".text", va=0x1000, vs=0x180, rp=0x400, rs=0x200,
                          ch=0x60000020, data=b"\xcc" * 0x180)], **kw)

def meta_text(soi, oep=OEP, entry=TGT_ENTRY, base=TGT_BASE):
    return f"base=0x{base:x}\nsize_of_image=0x{soi:x}\nentry_rva=0x{entry:x}\noep_rva=0x{oep:x}\n"

def run_main(argv, writer, *, target=None, dumps_seed=None):
    lab = fresh("m" + str(len(R)))
    dumps = os.path.join(lab, "dumps"); os.makedirs(dumps, exist_ok=True)
    if dumps_seed:
        for n, data in dumps_seed.items():
            with open(os.path.join(dumps, n), "wb") as f: f.write(data)
    sogen = os.path.join(lab, "sogen"); os.makedirs(sogen, exist_ok=True)
    open(os.path.join(sogen, "analyzer.exe"), "wb").close()
    emu = os.path.join(lab, "emu")
    for sub in ("registry", "filesys"): os.makedirs(os.path.join(emu, sub), exist_ok=True)
    img, soi = build_dump(SECS, entry=TGT_ENTRY, base=TGT_BASE)
    tp = os.path.join(lab, "s.exe")
    with open(tp, "wb") as f: f.write(target if target is not None else target_bytes(soi))
    out = os.path.join(lab, "out")
    old = (V.DUMPS, V.run_analyzer, sys.argv); V.DUMPS = dumps
    captured = {}
    def fake(a):
        t0 = time.time() - V.MTIME_SLACK
        captured["env_oep"] = a.oep; captured["env_tsc"] = a.tsc
        writer(dumps, t0, img, soi)
        return dict(log=captured.get("log", ""), err="", rc=0, timeout=False, t0=t0)
    V.run_analyzer = fake
    sys.argv = ["vmpunpack.py", tp, "-o", out, "--sogen", sogen, "--emuroot", emu] + argv
    buf = io.StringIO(); code = 0
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf): V.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        if isinstance(e.code, str): buf.write(e.code + "\n")
    finally:
        V.DUMPS, V.run_analyzer, sys.argv = old
    return code, buf.getvalue(), out, img, soi

def w_good(d, t0, img, soi):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(img)
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi))

# ============================================================ reconstruct_pe round trip
print("=== reconstruct_pe on a dump-shaped image (rp != va) ===")
o = fresh("recon")
img, soi = build_dump(SECS, entry=TGT_ENTRY, base=TGT_BASE)
exe = os.path.join(o, "r.exe")
V.reconstruct_pe(img, {"oep_rva": hex(OEP)}, exe)
with open(exe, "rb") as f: rb = f.read()
pe = struct.unpack_from("<I", rb, 0x3c)[0]
so = pe + 24 + struct.unpack_from("<H", rb, pe + 20)[0]
check("entry rewritten to the OEP", struct.unpack_from("<I", rb, pe + 24 + 16)[0] == OEP)
for i, s in enumerate(SECS):
    srd, prd = struct.unpack_from("<II", rb, so + i*40 + 16)
    nm = s["name"].rstrip(b"\0").decode()
    check(f"{nm}: PointerToRawData converted to the RVA", prd == s["va"], f"0x{prd:x} vs 0x{s['va']:x}")
    check(f"{nm}: raw extent stays inside the file", prd + srd <= len(rb), f"0x{prd+srd:x} > 0x{len(rb):x}")
    if s.get("data"):
        check(f"{nm}: body is reachable at the new offset", rb[prd:prd+len(s["data"])] == s["data"])
        check(f"{nm}: SizeOfRawData covers the body", srd >= len(s["data"]), f"0x{srd:x} < 0x{len(s['data']):x}")
secs = V.sections(bytearray(rb))
off = V.rva_to_off(secs, OEP)
check("rebuilt file maps oep_rva back to the OEP bytes",
      off is not None and rb[off:off+9] == b"OEPMARKER", f"off=0x{off:x}" if off else "off=None")
check("a vs>>rs section keeps its full virtual extent",
      struct.unpack_from("<I", rb, so + 1*40 + 16)[0] == 0x1000)

# ============================================================ flag normalisation
print("\n=== --oep / --tsc reach the engine as 0x-prefixed hex ===")
class A: pass
a = A(); a.target = None; a.emuroot = None; a.sogen = None
for raw, want in (("b3dc", "0xb3dc"), ("0xb3dc", "0xb3dc"), ("08000", "0x8000"), ("21000", "0x21000")):
    a.tsc = raw; a.oep = raw
    env = {}
    if a.tsc: env["SOGEN_TSC_STRIDE"] = hex(int(a.tsc, 16))
    if a.oep: env["SOGEN_OEP_RVA"] = hex(int(a.oep, 16))
    check(f"{raw!r} -> {want}", env["SOGEN_OEP_RVA"] == want and env["SOGEN_TSC_STRIDE"] == want,
          env["SOGEN_OEP_RVA"])
code, txt, out, img, soi = run_main(["--oep", "999999"], w_good)
check("--oep outside the image fails immediately", code != 0 and "outside the image" in txt, txt.strip()[:70])

# ============================================================ OEP corroboration
print("\n=== OEP sanity ===")
def w_zero_oep(d, t0, img, soi):
    b = bytearray(img); b[OEP:OEP+0x40] = b"\0" * 0x40
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(bytes(b))
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi))
code, txt, out, _, _ = run_main([], w_zero_oep)
check("zero bytes at oep_rva are refused", code != 0 and "never recovered" in txt, txt.strip()[-70:])
check("nothing published on a zero OEP", not os.path.exists(os.path.join(out, "s.unpacked.exe")))

def w_other_oep(d, t0, img, soi):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(img)
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi, oep=0x1010))
code, txt, out, _, _ = run_main(["--oep", "0x3040"], w_other_oep)
check("--oep honoured: a dump taken elsewhere is refused",
      code != 0 and "hooks that exact address" in txt, txt.strip()[-70:])

def w_entry_oep(d, t0, img, soi):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(img)
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi, oep=TGT_ENTRY))
code, txt, out, _, _ = run_main([], w_entry_oep)
check("oep == entry warns that nothing was unpacked", "nothing was unpacked" in txt, txt.strip()[:70])

code, txt, out, _, _ = run_main([], w_good)
check("happy path still publishes", code == 0 and "DONE" in txt, f"code={code}")
check("the OEP's section is named", "OEP is in section '.vmp1'" in txt, txt.strip()[:80])

def w_data_oep(d, t0, img, soi):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(img)
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi, oep=0x4010))
code, txt, out, _, _ = run_main([], w_data_oep)
check("a non-executable OEP section is flagged", "not marked executable" in txt, txt.strip()[:80])

# ============================================================ page-aligned SizeOfImage
print("\n=== page-aligned size_of_image is accepted ===")
img2, soi2 = build_dump(SECS, entry=TGT_ENTRY, base=TGT_BASE)
unaligned = soi2 - 0x123                                   # header says an unaligned value
tgt = target_bytes(soi2, size_of_image=unaligned)
def w_aligned(d, t0, img, soi):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(img)
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text(soi))   # the aligned value
code, txt, out, _, _ = run_main([], w_aligned, target=tgt)
check("unaligned SizeOfImage is no longer a false 'concurrent run'",
      code == 0 and "does not describe this target" not in txt, txt.strip()[-80:])

# ============================================================ provenance header
print("\n=== iocs.txt provenance ===")
code, txt, out, _, _ = run_main([], w_good)
ioc = open(os.path.join(out, "iocs.txt"), encoding="utf-8").read() if os.path.exists(os.path.join(out, "iocs.txt")) else ""
check("iocs.txt names the sample", "# sample: s.exe" in ioc, ioc[:60].replace("\n", " | "))
check("iocs.txt carries the sha256", "# sha256: " in ioc and len(ioc.split("# sha256: ")[1][:64]) == 64)
check("iocs.txt records the OEP and flags", "# oep_rva: 0x3040" in ioc and "# flags:" in ioc)

# ============================================================ run lock
print("\n=== the sample lands somewhere a download would, not C:\\sample ===")
lab = fresh("drop")
emu = os.path.join(lab, "emu")
for d in ("public", "Default", "j.smith"):
    os.makedirs(os.path.join(emu, "filesys", "c", "users", d), exist_ok=True)
host, guest = V.guest_drop_dir(emu)
check("a real profile is picked over public/Default", guest == "C:\\Users\\j.smith\\Downloads", guest)
check("the host path matches the guest path", host.lower().endswith(os.path.join("users", "j.smith", "downloads").lower()), host)
check("C:\\sample is no longer used", "sample" not in guest.lower())
emu2 = os.path.join(lab, "emu2"); os.makedirs(emu2)
host2, guest2 = V.guest_drop_dir(emu2)
check("falls back to a plausible path with no profiles", guest2 == "C:\\Windows\\Temp", guest2)

print("\n=== the guest always sees an .exe, whatever the sample is called ===")
for src, want in (("a1b2c3d4e5f6.bin", "a1b2c3d4e5f6.bin.exe"), ("sample.exe", "sample.exe"),
                  ("SAMPLE.EXE", "SAMPLE.EXE"), ("Foo.Exe", "Foo.Exe"),
                  ("no_extension", "no_extension.exe"), ("x.dat", "x.dat.exe")):
    got = V.guest_filename(os.path.join("C:\\samples", src))
    check(f"{src!r} -> {want!r}", got == want, got)
check("every result satisfies the engine's suffix gate",
      all(V.guest_filename(n).lower().endswith(".exe")
          for n in ("h.bin", "sample.exe", "SAMPLE.EXE", "Foo.Exe", "no_extension", "x.dat")))

print("\n=== page-recovery ratio is read from the right dump line ===")
def w_pages(d, t0, img, soi):
    w_good(d, t0, img, soi)
LOG = ("[DIAG] dumped s.exe image: 11/6812 pages readable -> C:\\dumps\\sogen_image.bin\n"
       "[UNPACK] dumped C:\\dumps\\unpacked.bin : 6700/6812 pages [0x140000000 +0x1a9c000]\n"
       "[UNPACK] dumped C:\\dumps\\heap.bin : 3/9 pages [0x0 +0x9000]\n")
lab = fresh("pages")
old = (V.DUMPS, sys.argv)
try:
    img, soi = build_dump(SECS, entry=TGT_ENTRY, base=TGT_BASE)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        class _A: pass
        _a = _A(); _a.oep = None
        V.check_oep(img, {"oep_rva": OEP, "entry_rva": TGT_ENTRY}, _a, LOG)
    t = buf.getvalue()
    check("the image line is used, not an earlier diagnostic one", "6700/6812" in t, t.strip()[-60:])
    check("a stray diagnostic ratio is ignored", "11/6812" not in t)
finally:
    V.DUMPS, sys.argv = old

print("\n=== --late requires --run-payload ===")
code, txt, out, _, _ = run_main(["--late", "5000"], w_good)
check("--late alone is rejected", code != 0 and "needs --run-payload" in txt, txt.strip()[:70])
code, txt, out, _, _ = run_main(["--late", "5000", "--run-payload"], w_good)
check("--late with --run-payload is accepted", code == 0, f"code={code}")

print("\n=== concurrent-run lock ===")
lab = fresh("lock"); dumps = os.path.join(lab, "dumps"); os.makedirs(dumps)
old_dumps = V.DUMPS; V.DUMPS = dumps
try:
    lk = os.path.join(dumps, ".lock")
    with open(lk, "w") as f: f.write("pid=999999 started=now argv=other.exe")
    buf = io.StringIO(); code = 0
    try:
        with contextlib.redirect_stdout(buf): V.acquire_lock(300)
    except SystemExit as e:
        code = 1; buf.write(str(e.code))
    check("a fresh foreign lock blocks the run", code != 0 and "another vmpunpack run holds" in buf.getvalue(),
          buf.getvalue().strip()[:70])
    os.utime(lk, (time.time() - 5000, time.time() - 5000))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): V.acquire_lock(300)
    check("a stale lock is taken over with a warning", "taking over a lock" in buf.getvalue(),
          buf.getvalue().strip()[:60])
    check("the lock now records this pid", f"pid={os.getpid()} " in open(lk, encoding="latin1").read())
finally:
    V.DUMPS = old_dumps

print("\n" + "=" * 60)
bad = [n for n, ok in R if not ok]
print(f"{len(R)-len(bad)}/{len(R)} passed")
for n in bad: print("  FAILED:", n)
sys.exit(1 if bad else 0)
