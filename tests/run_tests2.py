"""Second suite: the cases the first suite structurally could not reach, per the verification review."""
import importlib.util, sys, os, io, time, shutil, struct, contextlib, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pebuild import build_pe, import_blob, export_blob

REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "vmpunpack", "vmpunpack.py")
PATCH_ORD = os.path.join(REPO, "vmpunpack", "patch_ordinal.py")
LAB = os.path.join(tempfile.gettempdir(), "vmpunpack-tests", "lab2")

spec = importlib.util.spec_from_file_location("vmpu2", SRC)
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)

R = []
def check(name, cond, detail=""):
    R.append((name, bool(cond))); print(("  PASS  " if cond else "  FAIL  ") + name + (f"   [{detail}]" if detail else ""))

def fresh(sub):
    p = os.path.join(LAB, sub); shutil.rmtree(p, ignore_errors=True); os.makedirs(p, exist_ok=True); return p

TGT_SOI, TGT_ENTRY, TGT_BASE = 0x4000, 0x1000, 0x140000000
def target_bytes(**kw):
    kw.setdefault("entry", TGT_ENTRY); kw.setdefault("base", TGT_BASE); kw.setdefault("size_of_image", TGT_SOI)
    return build_pe(kw.pop("sections", None) or [dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200,
                                                      ch=0x60000020, data=b"\x90"*0x200)], **kw)
def meta_text(soi=TGT_SOI, entry=TGT_ENTRY, base=TGT_BASE, oep=0x1100):
    return f"base=0x{base:x}\nsize_of_image=0x{soi:x}\nentry_rva=0x{entry:x}\noep_rva=0x{oep:x}\n"
def dump_image(soi=TGT_SOI, entry=TGT_ENTRY, extra_data=b"", total=None):
    return build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x1000, rs=0x200, ch=0x60000020,
                          data=(b"\xcc"*0x200 + extra_data)[:0x200] if not extra_data else b"\xcc"*0x100 + extra_data)],
                    entry=entry, base=TGT_BASE, size_of_image=soi, total=total or soi)

def run_main(argv, writer, *, out_seed=None, rc=0, err="", timeout=False, stdout_cp=None, dumps_as_out=False):
    lab = fresh("m" + str(len(R)))
    dumps = os.path.join(lab, "dumps"); os.makedirs(dumps, exist_ok=True)
    sogen = os.path.join(lab, "sogen"); os.makedirs(sogen, exist_ok=True)
    open(os.path.join(sogen, "analyzer.exe"), "wb").close()
    emu = os.path.join(lab, "emu")
    for sub in ("registry", "filesys"): os.makedirs(os.path.join(emu, sub), exist_ok=True)
    tp = os.path.join(lab, "sample_B.exe")
    with open(tp, "wb") as f: f.write(target_bytes())
    out = dumps if dumps_as_out else os.path.join(lab, "out")
    if out_seed:
        os.makedirs(out, exist_ok=True)
        for n, data in out_seed.items():
            with open(os.path.join(out, n), "wb") as f: f.write(data)
    old = (V.DUMPS, V.run_analyzer, sys.argv); V.DUMPS = dumps
    def fake(args):
        t0 = time.time() - V.MTIME_SLACK
        writer(dumps, t0)
        return dict(log="", err=err, rc=rc, timeout=timeout, t0=t0)
    V.run_analyzer = fake
    sys.argv = ["vmpunpack.py", tp, "-o", out, "--sogen", sogen, "--emuroot", emu] + argv
    raw = io.BytesIO()
    sink = io.TextIOWrapper(raw, encoding=stdout_cp, newline="") if stdout_cp else io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            V.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        if isinstance(e.code, str): sink.write(e.code + "\n")
    finally:
        V.DUMPS, V.run_analyzer, sys.argv = old
    if stdout_cp:
        sink.flush(); txt = raw.getvalue().decode(stdout_cp, "replace")
    else:
        txt = sink.getvalue()
    return code, txt, out

def w_good(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image())
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())

print("=== 2.1  -o aliasing the dumps dir ===")
code, txt, out = run_main([], w_good, dumps_as_out=True,
                          out_seed={"unpacked.bin": b"PRE-EXISTING DUMP FROM AN EARLIER RUN"})
check("2.1 -o == DUMPS refused up front", code != 0 and "-o must not be" in txt, f"code={code}")
# the guard must fire before the purge loop, so anything already in that directory is untouched
survived = os.path.isfile(os.path.join(out, "unpacked.bin")) and \
           open(os.path.join(out, "unpacked.bin"), "rb").read() == b"PRE-EXISTING DUMP FROM AN EARLIER RUN"
check("2.1 pre-existing dump in that dir is not destroyed", survived)

print("\n=== 2.2 / 2.11  import walk really is bounded ===")
th = b"".join(struct.pack("<Q", 0x8000000000000000 | (n & 0xffff)) for n in range(65536)) + b"\0"*8
name = b"ntdll.dll\0"
blob = bytearray(20*2); blob += name; blob += b"\0" * ((-len(blob)) % 8)
toff = len(blob); blob += th
struct.pack_into("<IIIII", blob, 0, 0x10000 + toff, 0, 0, 0x10000 + 40, 0x10000 + toff)
pe = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020, data=b"\x90"*0x200),
               dict(name=b".idata", va=0x10000, vs=len(blob), rp=0x1000, rs=len(blob), ch=0xC0000040, data=bytes(blob))],
              dirs={1: (0x10000, 40)}, total=0x1000 + len(blob) + 0x1000)
t = time.time()
with contextlib.redirect_stdout(io.StringIO()): r = V.ordinal_imports(pe)
dt = time.time() - t
check("2.2 single descriptor cannot exceed MAX_ORDINALS", len(r) <= V.MAX_ORDINALS, f"{len(r)} entries, {dt:.2f}s")
check("2.2 result is deduplicated", len(r) == len(set(r)))

# 4096 descriptors all pointing at one long non-ordinal thunk array -> product must be budgeted
th2 = b"".join(struct.pack("<Q", 0x1000 + n) for n in range(65536)) + b"\0"*8
nm = b"a.dll\0"
ndesc = 4096
hdr = bytearray(20 * (ndesc + 1)); base = 0x10000
noff = len(hdr); hdr += nm; hdr += b"\0" * ((-len(hdr)) % 8)
toff2 = len(hdr); hdr += th2
for i in range(ndesc):
    struct.pack_into("<IIIII", hdr, i*20, base + toff2, 0, 0, base + noff, base + toff2)
pe2 = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020, data=b"\x90"*0x200),
                dict(name=b".idata", va=base, vs=len(hdr), rp=0x1000, rs=len(hdr), ch=0xC0000040, data=bytes(hdr))],
               dirs={1: (base, 0)}, total=0x1000 + len(hdr) + 0x1000)
t = time.time()
with contextlib.redirect_stdout(io.StringIO()): r2 = V.ordinal_imports(pe2)
dt = time.time() - t
check("2.11 descriptors x thunks product is budgeted (<15s)", dt < 15.0, f"{dt:.2f}s, {len(r2)} entries")

print("\n=== 2.3  imp_sz must not narrow the walk (regression) ===")
imp = import_blob("ws2_32.dll", [23, 115, 1234], base_rva=0x2000)
for size in (0, 19, 20, 55, len(imp)):
    p = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020, data=b"\x90"*0x200),
                  dict(name=b".idata", va=0x2000, vs=len(imp), rp=0x600, rs=len(imp), ch=0xC0000040, data=imp)],
                 dirs={1: (0x2000, size)})
    got = V.ordinal_imports(p)
    check(f"2.3 imp_sz={size:<3} still finds all 3 ordinals", len(got) == 3, str(got))

print("\n=== 2.4  encoding: non-ASCII must not reach the sets, file must survive the console ===")
d, u, i = V.grep_iocs("abſ-panel.top".encode("utf-16le"))
check("2.4 re.A keeps U+017F out of domains", all(x.isascii() for x in d), str(d))
d, u, i = V.grep_iocs("\u0661.2.3.4".encode("utf-16le"))
check("2.4 re.A keeps Unicode digits out of IPs", all(x.isascii() for x in i), str(i))
code, txt, out = run_main([], w_good, err="FATAL \x81\x9d bad hive file", stdout_cp="cp1251")
check("2.4 high-byte analyzer stderr does not kill the run", code == 0 and "DONE" in txt, f"code={code}")
check("2.4 iocs.txt written despite the cp1251 console", os.path.isfile(os.path.join(out, "iocs.txt")))

print("\n=== 2.5 / 2.6  output-dir hygiene ===")
def w_nomz(d, t0):
    b = bytearray(dump_image()); b[0:2] = b"ZZ"
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(bytes(b))
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
code, txt, out = run_main([], w_nomz, out_seed={"sample_B.unpacked.exe": b"RUN-1 STALE EXE"})
check("2.5 stale .unpacked.exe purged even when reconstruct fails",
      code != 0 and not os.path.exists(os.path.join(out, "sample_B.unpacked.exe")), f"code={code}")

lab = fresh("lock"); out = os.path.join(lab, "out"); os.makedirs(out)
locked = os.path.join(out, "heap.bin")
with open(locked, "wb") as f: f.write(b"RUN-1 HEAP")
hold = open(locked, "rb")
try:
    code, txt, _ = run_main([], w_good, out_seed=None)
    lab2 = fresh("lock2"); out2 = os.path.join(lab2, "out"); os.makedirs(out2)
    l2 = os.path.join(out2, "heap.bin")
    with open(l2, "wb") as f: f.write(b"RUN-1 HEAP")
    h2 = open(l2, "rb")
    try:
        old = (V.DUMPS, V.run_analyzer, sys.argv)
        dumps = os.path.join(lab2, "dumps"); os.makedirs(dumps)
        sog = os.path.join(lab2, "sogen"); os.makedirs(sog); open(os.path.join(sog, "analyzer.exe"), "wb").close()
        for sub in ("registry", "filesys"): os.makedirs(os.path.join(lab2, sub), exist_ok=True)
        tp = os.path.join(lab2, "s.exe")
        with open(tp, "wb") as f: f.write(target_bytes())
        V.DUMPS = dumps
        V.run_analyzer = lambda a: (w_good(dumps, 0), dict(log="", err="", rc=0, timeout=False,
                                                           t0=time.time() - V.MTIME_SLACK))[1]
        sys.argv = ["vmpunpack.py", tp, "-o", out2, "--sogen", sog, "--emuroot", lab2]
        buf = io.StringIO(); c = 0
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf): V.main()
        except SystemExit as e:
            c = e.code if isinstance(e.code, int) else 1
        finally:
            V.DUMPS, V.run_analyzer, sys.argv = old
        check("2.6 locked stale artefact in out is reported loudly",
              "could not be removed" in buf.getvalue(), buf.getvalue().strip()[-90:])
    finally: h2.close()
finally: hold.close()

print("\n=== 2.7  host_of must not read the userinfo ===")
_ispec = importlib.util.spec_from_file_location("vmpiocs", os.path.join(REPO, "vmpunpack", "iocs.py"))
IOC = importlib.util.module_from_spec(_ispec); _ispec.loader.exec_module(IOC)
check("2.7 userinfo spoof no longer suppresses the URL",
      IOC.host_of("http://update.microsoft.com@185.220.101.5/p.bin") == "185.220.101.5",
      IOC.host_of("http://update.microsoft.com@185.220.101.5/p.bin"))
d, u, i = V.grep_iocs(b"http://www.microsoft.com@c2host.top/gate.php")
check("2.7 spoofed URL survives into iocs", len(u) == 1 and "c2host.top" in d, f"{d} {u}")
check("2.7 genuine CA noise with userinfo still filtered",
      IOC.NOISE_HOST.match(IOC.host_of("http://ocsp@digicert.com/x.crl")) is not None)

print("\n=== 2.8  torn .bin / .meta pair ===")
def w_torn(d, t0):
    with open(os.path.join(d, "unpacked.bin"), "wb") as f: f.write(dump_image(soi=0x9000, total=0x9000))
    with open(os.path.join(d, "unpacked.meta"), "w") as f: f.write(meta_text())
code, txt, out = run_main([], w_torn)
check("2.8 .bin whose headers disagree with .meta is refused",
      code != 0 and "disagree with unpacked.meta" in txt, f"code={code}")
check("2.8 nothing published", not os.path.exists(os.path.join(out, "sample_B.unpacked.exe")))

print("\n=== 2.9  patch_ordinal partial refusal ===")
lab = fresh("po")
vic = build_pe([dict(name=b".text", va=0x1000, vs=0x200, rp=0x400, rs=0x200, ch=0x60000020,
                     data=b"\xc3" + b"\x90"*0x1ff),
                dict(name=b".edata", va=0x2000, vs=0x200, rp=0x600, rs=0x200, ch=0x40000040,
                     data=export_blob(base_rva=0x2000, base_ord=1, func_rvas=[0x1000, 0, 0]).ljust(0x200, b"\0"))],
               dirs={0: (0x2000, 0x200)})
t8 = os.path.join(lab, "t.dll")
with open(t8, "wb") as f: f.write(vic)
p = subprocess.run([sys.executable, PATCH_ORD, t8, "1", "2"], capture_output=True, text=True)
o = (p.stdout or "") + (p.stderr or "")
check("2.9 partial apply exits non-zero", p.returncode != 0, f"code={p.returncode}")
check("2.9 the empty slot was still patched", "ord 2: func_rva 0x0 ->" in o, o.strip()[:80])
check("2.9 the live slot was refused", "refusing without --force" in o)

print("\n=== install check points at setup.cmd ===")
lab = fresh("noeng")
tp = os.path.join(lab, "s.exe")
with open(tp, "wb") as f: f.write(target_bytes())
sog = os.path.join(lab, "sogen"); os.makedirs(sog)
old = sys.argv
sys.argv = ["vmpunpack.py", tp, "-o", os.path.join(lab, "out"), "--sogen", sog, "--emuroot", os.path.join(lab, "emu")]
buf = io.StringIO(); c = 0
try:
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf): V.main()
except SystemExit as e:
    c = e.code if isinstance(e.code, int) else 1
    if isinstance(e.code, str): buf.write(e.code)
finally: sys.argv = old
t = buf.getvalue()
check("missing engine names every missing path", "analyzer.exe" in t and "registry" in t and "filesys" in t)
check("missing engine points at setup.cmd", c != 0 and "setup.cmd" in t, t.strip()[:80])

print("\n=== --version ===")
p = subprocess.run([sys.executable, SRC, "--version"], capture_output=True, text=True)
check("--version prints a version", p.returncode == 0 and "vmpunpack" in (p.stdout + p.stderr),
      (p.stdout + p.stderr).strip()[:40])

print("\n" + "=" * 60)
bad = [n for n, ok in R if not ok]
print(f"{len(R)-len(bad)}/{len(R)} passed")
for n in bad: print("  FAILED:", n)
sys.exit(1 if bad else 0)
