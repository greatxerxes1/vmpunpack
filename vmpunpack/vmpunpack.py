import argparse, atexit, hashlib, os, re, struct, subprocess, sys, shutil, time

__version__ = "0.2.0.dev0"

DUMPS = r"C:\dumps"
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_FILES = ("unpacked.bin", "unpacked.meta", "unpacked_late.bin", "heap.bin")
# Written by the engine but not consumed here. Cleared best-effort only: a leftover one is noise,
# not a correctness problem, so it must never abort a run the way a stale DUMP_FILES entry does.
SCRATCH_FILES = ("sogen_image.bin", "vmp_run.jsonl", "vmp_guest.txt")
META_KEYS = ("base", "size_of_image", "entry_rva", "oep_rva")
MTIME_SLACK = 2.0          # filesystem timestamp granularity; keeps the staleness floor from false-firing
MAX_DESCRIPTORS = 4096     # bounds on the import walk: every byte of it is attacker-controlled
MAX_THUNKS = 65536
MAX_ORDINALS = 4096
MAX_THUNK_READS = 1 << 20  # budget across ALL descriptors: the per-dimension caps multiply otherwise

class BadPE(Exception): pass

def _page_up(x): return (x + 0xfff) & ~0xfff

def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(chunk), b""): h.update(blk)
    return h.hexdigest()

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def pe_at(b):
    if len(b) < 0x40 or b[0:2] != b"MZ": raise BadPE("no MZ signature")
    pe = u32(b, 0x3c)
    if pe + 24 > len(b) or b[pe:pe+4] != b"PE\0\0": raise BadPE(f"no PE signature at e_lfanew 0x{pe:x}")
    return pe

def sections(b):
    pe = pe_at(b); nsec = u16(b, pe+6); optsz = u16(b, pe+20); so = pe+24+optsz
    if so + nsec*40 > len(b): raise BadPE(f"section table ({nsec} sections at 0x{so:x}) runs past end of image")
    out = []
    for i in range(nsec):
        o = so + i*40
        name = b[o:o+8].split(b"\0")[0].decode("latin1", "replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", b, o+8)
        ch = u32(b, o+36)
        out.append(dict(name=name, va=va, vs=vs, rp=rp, rs=rs, ch=ch, hdr_off=o))
    return out

def rva_to_off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["rp"] + (rva - s["va"])
    return None

def _off(secs, rva, blen, need=1):
    """rva_to_off, but only if the result is actually readable for `need` bytes."""
    o = rva_to_off(secs, rva)
    return o if o is not None and o >= 0 and o + need <= blen else None

def pe_basics(b):
    pe = pe_at(b); opt = pe+24
    if opt + 2 > len(b): raise BadPE("truncated optional header")
    magic = u16(b, opt)
    if magic not in (0x10b, 0x20b): raise BadPE(f"bad optional-header magic 0x{magic:x}")
    is64 = magic == 0x20b
    dd = opt + (112 if is64 else 96)
    if dd + 16*8 > len(b): raise BadPE("truncated optional header / data directories")
    return dict(is64=is64, entry_rva=u32(b, opt+16),
                base=(u64(b, opt+24) if is64 else u32(b, opt+28)),
                size_of_image=u32(b, opt+56), datadir_off=dd)

def ordinal_imports(b):
    secs = sections(b); pb = pe_basics(b)
    tw = 8 if pb["is64"] else 4                                   # thunk width follows the PE class
    flag = 0x8000000000000000 if pb["is64"] else 0x80000000
    rd = u64 if pb["is64"] else u32
    imp_rva, _imp_sz = struct.unpack_from("<II", b, pb["datadir_off"] + 1*8)
    res = []
    if not imp_rva: return res
    io = _off(secs, imp_rva, len(b), 20)
    if io is None: return res
    # Deliberately NOT derived from imp_sz: the Windows loader ignores the directory Size and walks to
    # the null descriptor, and packers routinely ship a stale/short Size. Trusting it loses real imports.
    budget = MAX_THUNK_READS
    for i in range(MAX_DESCRIPTORS):
        d = b[io+i*20: io+i*20+20]
        if len(d) < 20: break
        oft, ts, fc, nameRva, fthunk = struct.unpack("<IIIII", d)
        if oft == 0 and nameRva == 0 and fthunk == 0: break
        no = _off(secs, nameRva, len(b)) if nameRva else None
        if no is None: continue
        e = b.find(b"\0", no, min(no+256, len(b)))
        if e < 0: continue
        dll = b[no:e].decode("latin1", "replace")
        to = _off(secs, oft or fthunk, len(b), tw)
        if to is None: continue
        j = 0
        while j < MAX_THUNKS and budget > 0 and to + (j+1)*tw <= len(b):
            budget -= 1
            v = rd(b, to + j*tw)
            if v == 0: break
            if v & flag:
                res.append((dll, v & 0xffff))
                if len(res) >= MAX_ORDINALS: break        # cap here, not just between descriptors
            j += 1
        if len(res) >= MAX_ORDINALS or budget <= 0:
            print(f"[!] import table exceeds the parse budget - the ordinal list below is truncated")
            break
    return sorted(set(res))                               # gap_fill rewrites a DLL per entry; dedup first

def _export_dir(b):
    secs = sections(b); pb = pe_basics(b)
    exp_rva, _ = struct.unpack_from("<II", b, pb["datadir_off"] + 0*8)
    if not exp_rva: return None
    eo = _off(secs, exp_rva, len(b), 40)
    if eo is None: return None
    Base = u32(b, eo+16); nFunc = u32(b, eo+20); aFunc = u32(b, eo+28)
    if nFunc > 0x10000: return None
    afo = _off(secs, aFunc, len(b), nFunc*4)
    if afo is None: return None
    return dict(secs=secs, Base=Base, nFunc=nFunc, afo=afo)

def export_ordinal_range(b):
    d = _export_dir(b)
    return (d["Base"], d["nFunc"]) if d else None

def patch_export_ordinal_to_ret(dll_path, ordinal):
    with open(dll_path, "rb") as f: b = bytearray(f.read())
    d = _export_dir(b)
    if not d: return "oor"
    idx = ordinal - d["Base"]
    if not (0 <= idx < d["nFunc"]): return "oor"
    if u32(b, d["afo"] + idx*4) != 0: return "already"
    ret_rva = None
    for s in d["secs"]:
        if (s["ch"] & 0x20000000) and s["rs"] and s["rp"] + s["rs"] <= len(b):
            k = b.find(b"\xc3", s["rp"], s["rp"] + s["rs"])
            if k != -1: ret_rva = s["va"] + (k - s["rp"]); break
    if ret_rva is None: return "noret"
    struct.pack_into("<I", b, d["afo"] + idx*4, ret_rva)
    with open(dll_path, "wb") as f: f.write(b)
    return "patched"

def reconstruct_pe(img, meta, out_path):
    b = bytearray(img)
    pe = pe_at(b)                                    # raises BadPE if the packer erased its own header page
    optsz = u16(b, pe+20); nsec = u16(b, pe+6); so = pe+24+optsz
    if so + nsec*40 > len(b): raise BadPE(f"section table ({nsec} sections) runs past end of dump")
    oep_rva = int(meta["oep_rva"], 16)
    struct.pack_into("<I", b, pe+24+16, oep_rva)
    for i in range(nsec):
        o = so + i*40; vs, va, rs, rp = struct.unpack_from("<IIII", b, o+8)
        # max(vs, rs) matches rva_to_off's convention: vs==0 with rs>0 is loader-legal and the bytes are
        # really in the dump. Clamp to what the buffer actually holds so no header points past EOF.
        size = 0 if va >= len(b) else min(max(vs, rs), len(b) - va)
        struct.pack_into("<II", b, o+16, size, va)
    with open(out_path, "wb") as f: f.write(b)
    return oep_rva

TLD = (r"com|net|org|ru|su|io|xyz|top|info|biz|cc|onion|pw|club|online|site|dev|app|shop|"
       r"cyou|sbs|store|cfd|icu|monster|quest")
# re.A everywhere: without it [a-z] under re.I matches U+017F and \d matches any Unicode digit, so
# binary noise decoded as UTF-16 injects non-ASCII into the IOC sets and breaks the console write.
RE_DOM = re.compile(r"\b(?:[a-z0-9-]{2,50}\.){1,3}(?:" + TLD + r")\b", re.I | re.A)
RE_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{6,90}", re.A)
RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", re.A)
# Anchored against the registrable host only. A substring match here would drop exactly the
# Microsoft-impersonating C2 hostnames the tool most needs to surface.
NOISE_HOST = re.compile(r"^(?:[a-z0-9-]+\.)*(?:" + "|".join((
    r"microsoft\.com", r"windows\.com", r"windowsupdate\.com", r"msftconnecttest\.com", r"msftncsi\.com",
    r"live\.com", r"msn\.com", r"bing\.com", r"office\.com", r"azure\.com", r"windows\.net", r"skype\.com",
    r"w3\.org", r"xmlsoap\.org", r"openxmlformats\.org", r"mozilla\.org", r"apache\.org", r"openssl\.org",
    r"python\.org", r"letsencrypt\.org", r"nuget\.org", r"chocolatey\.org", r"oasis-open\.org",
    r"verisign\.com", r"digicert\.com", r"sectigo\.com", r"globalsign\.com", r"godaddy\.com",
    r"comodoca\.com", r"entrust\.net", r"thawte\.com", r"geotrust\.com", r"symcb\.com", r"symcd\.com",
    r"amazontrust\.com", r"usertrust\.com", r"trustwave\.com", r"identrust\.com", r"sectigo\.net",
)) + r")$", re.I)

def _host(u):
    # take the LAST @-separated part: http://update.microsoft.com@<real-c2>/ must not read as Microsoft
    m = re.match(r"https?://([^/\s]+)", u, re.I)
    a = (m.group(1) if m else "").rsplit("@", 1)[-1]
    return a.split(":")[0].lower().rstrip(".")

def _ok_ip(x):
    p = x.split(".")
    if any(not (q.isdigit() and len(q) <= 3 and int(q) <= 255) for q in p): return False
    return x not in ("0.0.0.0", "127.0.0.1", "255.255.255.255")

def _scan(text, dom, url, ip):
    for s in RE_DOM.findall(text):
        s = s.lower()
        if len(s) > 6 and not NOISE_HOST.match(s): dom.add(s)
    for x in RE_URL.findall(text):
        if not NOISE_HOST.match(_host(x)): url.add(x)
    for x in RE_IP.findall(text):
        if _ok_ip(x): ip.add(x)

def grep_iocs(b, chunk=64 << 20, overlap=1 << 12):
    """All three patterns see all three views. Chunked so a several-hundred-MB heap dump cannot
    blow memory up by decoding the whole buffer twice and concatenating it."""
    dom, url, ip = set(), set(), set()
    n = len(b)
    spans = [(0, n)] if n <= chunk else [(s, min(s + chunk + overlap, n)) for s in range(0, n, chunk)]
    for s, e in spans:
        seg = bytes(b[s:e])
        _scan(seg.decode("latin1", "ignore"), dom, url, ip)         # single-byte
        _scan(seg.decode("utf-16le", "ignore"), dom, url, ip)       # wide, even-aligned
        _scan(seg[1:].decode("utf-16le", "ignore"), dom, url, ip)   # wide, odd-aligned
    return sorted(dom), sorted(url), sorted(ip)

def acquire_lock(timeout):
    """C:\\dumps is shared by every invocation on the machine and its path is compiled into
    analyzer.exe. Two runs interleave on the same four filenames, and the identity checks cannot
    catch it when both runs are of the same sample. Enforce the rule the README states."""
    os.makedirs(DUMPS, exist_ok=True)
    lock = os.path.join(DUMPS, ".lock")
    def _take():
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, f"pid={os.getpid()} started={time.strftime('%Y-%m-%dT%H:%M:%S')} "
                     f"argv={' '.join(sys.argv[1:])}".encode("latin1", "replace"))
        os.close(fd)
        atexit.register(lambda: os.path.isfile(lock) and os.remove(lock))
    try:
        return _take()
    except FileExistsError:
        pass
    try:
        with open(lock, encoding="latin1") as f: held = f.read().strip()
        age = time.time() - os.path.getmtime(lock)
    except OSError:
        held, age = "<unreadable>", 0.0
    mine = f"pid={os.getpid()} " in held + " "
    if not mine and age <= timeout + 60:
        sys.exit(f"[!] another vmpunpack run holds {lock} ({int(age)}s ago):\n"
                 f"    {held}\n"
                 f"    {DUMPS} is shared and its path is baked into analyzer.exe, so runs must be\n"
                 f"    sequential. Wait for it, or delete the lock if that run is gone.")
    if not mine:
        print(f"[!] taking over a lock left behind {int(age)}s ago by: {held}")
    try: os.remove(lock)
    except OSError as e: sys.exit(f"[!] cannot remove the lock {lock}: {e}")
    _take()

def guest_filename(target):
    """The engine identifies the target module by a case-sensitive '.exe'/'.EXE' suffix, so a sample
    named by its hash - the norm in triage - would arm nothing and produce no dump. Present it to the
    guest under a name the engine recognises."""
    name = os.path.basename(target)
    return name if name.lower().endswith(".exe") else name + ".exe"

def guest_drop_dir(emuroot):
    """Where the sample appears to the guest, as (host path, guest path).

    Nothing arrives at C:\\sample\\ in a real infection - it is the one identifying artefact vmpunpack
    itself adds to an otherwise stock emulation root, and it costs nothing to drop the file somewhere
    a download would actually land. The profile name is discovered, not assumed, so this follows
    whatever root is installed."""
    users = os.path.join(emuroot, "filesys", "c", "users")
    skip = {"public", "default", "defaultuser0", "all users", "default user"}
    if os.path.isdir(users):
        for d in sorted(os.listdir(users)):
            if d.lower() not in skip and os.path.isdir(os.path.join(users, d)):
                return os.path.join(users, d, "downloads"), f"C:\\Users\\{d}\\Downloads"
    return os.path.join(emuroot, "filesys", "c", "windows", "temp"), "C:\\Windows\\Temp"

def run_analyzer(args):
    guest_name = guest_filename(args.target)
    if guest_name != os.path.basename(args.target):
        print(f"[i] presenting the sample to the guest as {guest_name} "
              "(the engine identifies its target by an .exe suffix)")
    guest_dir, guest_prefix = guest_drop_dir(args.emuroot)
    os.makedirs(guest_dir, exist_ok=True)
    shutil.copy(args.target, os.path.join(guest_dir, guest_name))
    for f in DUMP_FILES:
        p = os.path.join(DUMPS, f)
        try: os.remove(p)
        except FileNotFoundError: pass
        except OSError as e:
            sys.exit(f"[!] cannot clear stale dump {p}: {e}\n"
                     "    Close whatever holds it open and re-run. Refusing to continue rather than risk\n"
                     "    publishing a previous sample's image as this one's result.")
    for f in SCRATCH_FILES:
        try: os.remove(os.path.join(DUMPS, f))
        except OSError: pass
    env = dict(os.environ); env["SOGEN_UNPACK"] = "1"
    for k in ("SOGEN_STOP_AT_OEP", "SOGEN_NODELAY", "SOGEN_TSC_STRIDE", "SOGEN_OEP_RVA", "SOGEN_LATEDUMP_AT"):
        env.pop(k, None)
    if not args.run_payload: env["SOGEN_STOP_AT_OEP"] = "1"
    if args.nodelay: env["SOGEN_NODELAY"] = "1"
    # The engine parses these with strtoull(base 0), so a bare "b3dc" would arrive as 0 and "08000"
    # as an invalid octal. The flags accept hex with or without the prefix; normalise before handing over.
    if args.tsc: env["SOGEN_TSC_STRIDE"] = hex(int(args.tsc, 16))
    if args.oep: env["SOGEN_OEP_RVA"] = hex(int(args.oep, 16))
    if args.late: env["SOGEN_LATEDUMP_AT"] = str(args.late)
    cmd = [os.path.join(args.sogen, "analyzer.exe"), "--backend", "unicorn", "--no-inst-precision",
           "-e", args.emuroot, "-r", os.path.join(args.emuroot, "registry"),
           "--report", os.path.join(DUMPS, "vmp_run.jsonl"), "--stdout", os.path.join(DUMPS, "vmp_guest.txt"),
           "--first-exec", "-c", guest_prefix + "\\" + guest_name]
    dec = lambda s: s if isinstance(s, str) else (s.decode("latin1", "replace") if s else "")
    t0 = time.time() - MTIME_SLACK              # captured immediately before launch: the staleness floor
    try:
        p = subprocess.run(cmd, cwd=args.sogen, env=env, capture_output=True, text=True,
                           encoding="latin1", timeout=args.timeout, stdin=subprocess.DEVNULL)
        return dict(log=p.stdout or "", err=p.stderr or "", rc=p.returncode, timeout=False, t0=t0)
    except subprocess.TimeoutExpired as e:
        return dict(log=dec(e.stdout), err=dec(e.stderr), rc=None, timeout=True, t0=t0)

def gap_fill(args, ords):
    sys32 = os.path.join(args.emuroot, "filesys", "c", "windows", "system32")
    try: sys32_real = os.path.realpath(sys32)
    except OSError: return
    for dll, ordv in ords:
        # every byte of `dll` came out of the sample: it must be a plain filename, never a path
        if dll != os.path.basename(dll) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", dll):
            print(f"[!] refusing import DLL name {dll!r} from the sample (not a plain filename)"); continue
        dpath = os.path.join(sys32, dll)
        if not os.path.isfile(dpath) and os.path.isdir(sys32):
            hit = next((f for f in os.listdir(sys32) if f.lower() == dll.lower()), None)
            if hit: dpath = os.path.join(sys32, hit)
        try:
            if os.path.commonpath([os.path.realpath(dpath), sys32_real]) != sys32_real: raise ValueError
        except ValueError:
            print(f"[!] {dll!r} resolves outside the emulation root - skipping"); continue
        if not os.path.isfile(dpath):
            print(f"[!] emu-root DLL not found for {dll} (ordinal {ordv}) at {dpath}"); continue
        try: r = patch_export_ordinal_to_ret(dpath, ordv)
        except (BadPE, struct.error, OSError) as e:
            print(f"[!] {dll}: cannot patch the emulation-root copy ({e})"); continue
        if r == "patched": print(f"[+] gap-filled {dll}#{ordv} (empty export slot -> ret stub)")
        elif r == "already": print(f"[i] {dll}#{ordv}: export slot already populated - left alone")
        elif r == "noret": print(f"[!] {dll}#{ordv}: no ret byte to point at - not gap-filled")
        elif r == "oor":
            rng = None
            try:
                with open(dpath, "rb") as f: rng = export_ordinal_range(bytearray(f.read()))
            except (BadPE, struct.error, OSError): pass
            if rng:
                print(f"[!] {dll}#{ordv}: ordinal is outside this DLL's export range "
                      f"(it exports {rng[0]}..{rng[0]+rng[1]-1}).")
                print(f"    Neither the auto gap-fill nor patch_ordinal.py can fix that - the emulation")
                print(f"    root's {dll} is a different build from the one this sample was linked against.")
            else:
                print(f"[!] {dll}#{ordv}: the emulation root's copy has no readable export directory.")

def check_oep(img, m, args, log):
    """The OEP is the one value in the meta with no independent check, and the whole result hangs on
    it. The engine dumps on the first execution anywhere in the chosen section, with no corroboration,
    so a stub-entry dump satisfies every other gate. Catch the cases that are detectable from here."""
    oep = m["oep_rva"]
    # dump_mem writes [base, base+SizeOfImage) contiguously, so a file offset IS the RVA
    if oep + 16 <= len(img) and not any(img[oep:oep+16]):
        sys.exit(f"[!] the 16 bytes at oep_rva 0x{oep:x} are all zero - that page was never recovered.\n"
                 "    Refusing to publish an image whose entry point is empty.")
    if args.oep and oep != int(args.oep, 16):
        sys.exit(f"[!] --oep 0x{int(args.oep, 16):x} was requested but the dump was taken at 0x{oep:x}.\n"
                 "    The engine hooks that exact address, so the two can only disagree if the installed\n"
                 "    analyzer.exe predates that behaviour and still hooks the whole section containing\n"
                 "    the RVA. Refusing to publish. Run setup.cmd --force to refresh the engine.")
    if oep == m["entry_rva"]:
        print(f"[!] oep_rva == entry_rva (0x{oep:x}): the dump was taken at the packer's own entry point,")
        print("    so nothing was unpacked. Treat this result as suspect.")
    try:
        secs = sections(bytearray(img))
        hit = next((s for s in secs if s["va"] <= oep < s["va"] + max(s["vs"], s["rs"])), None)
        if hit is None:
            print(f"[!] oep_rva 0x{oep:x} falls outside every section of the dump")
        else:
            print(f"[i] OEP is in section {hit['name']!r} (rva 0x{hit['va']:x})")
            if not hit["ch"] & 0x20000000:
                print(f"[!] that section is not marked executable - the OEP heuristic likely misfired")
    except (BadPE, struct.error):
        pass
    # The engine already counted readable pages; the line goes to stdout, which is discarded on success.
    # Anchored on the filename: a bare "N/M pages" search would happily pick up any other dump line the
    # engine prints first - which is exactly how an earlier diagnostic dump's page count got reported
    # as the image-recovery rate.
    mm = re.search(r"unpacked\.bin\s*:\s*(\d+)\s*/\s*(\d+)\s+pages", log)
    if mm and int(mm.group(2)):
        good, total = int(mm.group(1)), int(mm.group(2))
        pct = 100 * good // total
        print(f"[i] image recovered: {good}/{total} pages ({pct}%)")
        if pct < 50: print("    [!] most of the image was unreadable; the dump is largely zeros")

def main():
    # Sample-derived text (import DLL names) and the analyzer's latin1-decoded stderr both get printed.
    # Under a redirect stdout uses the ANSI codepage, where 0x80-0x9F is unencodable in every variant.
    for _s in (sys.stdout, sys.stderr):
        try: _s.reconfigure(errors="backslashreplace")
        except Exception: pass
    ap = argparse.ArgumentParser(description="Self-contained generic VMProtect unpacker (runs locally on the sogen VM).")
    ap.add_argument("target")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--run-payload", action="store_true", help="run past OEP (capture behaviour) instead of freezing at OEP")
    ap.add_argument("--nodelay", action="store_true", help="neutralize anti-sandbox NtDelayExecution sleeps")
    ap.add_argument("--tsc", default=None, help="rdtsc stride per call, e.g. 0x8000 (collapse rdtsc delay loops)")
    ap.add_argument("--oep", default=None, help="force OEP RVA, e.g. 0xb3dc (override the heuristic)")
    ap.add_argument("--late", type=int, default=None, help="dump image+heap after N post-OEP basic blocks")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--sogen", default=os.path.join(_ROOT, "sogen"))
    ap.add_argument("--emuroot", default=os.path.join(_ROOT, "emu_root", "root"))
    ap.add_argument("--version", action="version", version=f"vmpunpack {__version__}")
    args = ap.parse_args()

    os.makedirs(DUMPS, exist_ok=True)
    if not os.path.isfile(args.target): sys.exit(f"[!] target not found: {args.target}")
    missing = [p for p in (os.path.join(args.sogen, "analyzer.exe"),
                           os.path.join(args.emuroot, "registry"),
                           os.path.join(args.emuroot, "filesys")) if not os.path.exists(p)]
    if missing:
        sys.exit("[!] the engine or emulation root is not installed:\n"
                 + "".join(f"    missing {p}\n" for p in missing)
                 + "    Run setup.cmd to fetch them (they are third-party and not part of this repo),\n"
                 "    or pass --sogen/--emuroot if you keep them elsewhere. See THIRD_PARTY.md.")
    for k in ("tsc", "oep"):
        v = getattr(args, k)
        if v is not None and not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", v):
            sys.exit(f"[!] --{k} must be a hex number, got {v!r}")
    out = args.out or (os.path.splitext(args.target)[0] + "_unpacked")
    if os.path.normcase(os.path.realpath(out)) == os.path.normcase(os.path.realpath(DUMPS)):
        sys.exit(f"[!] -o must not be {DUMPS}: that is the shared scratch dir this run purges and reads back.")
    os.makedirs(out, exist_ok=True)
    with open(args.target, "rb") as f: tgt = f.read()
    try:
        pb = pe_basics(tgt)
    except (BadPE, struct.error) as e:
        sys.exit(f"[!] unparseable PE headers in target: {e}")
    if not pb["is64"]:
        sys.exit("[!] target is a 32-bit PE. This tool and the bundled emulation root are x64-only.\n"
                 "    For 32-bit packers use x32dbg + Scylla, or unipacker.")
    # The late dump is taken N basic blocks PAST the OEP, and without --run-payload the emulator is
    # stopped at the OEP, so there are none. The combination is inert rather than merely useless.
    if args.late is not None and not args.run_payload:
        sys.exit("[!] --late needs --run-payload: it dumps N basic blocks past the OEP, and without\n"
                 "    --run-payload the emulator stops at the OEP and never executes any.\n"
                 "    Note that --run-payload means the sample runs past its entry point.")
    if args.oep and not (0 < int(args.oep, 16) < pb["size_of_image"]):
        sys.exit(f"[!] --oep 0x{int(args.oep, 16):x} is outside the image "
                 f"(size_of_image=0x{pb['size_of_image']:x}) - a typo fails now rather than after "
                 f"{args.timeout}s.")
    print(f"[i] target base=0x{pb['base']:x} entry_rva=0x{pb['entry_rva']:x} size_of_image=0x{pb['size_of_image']:x}")

    # Taken before the gap-fill, not just before the run: gap_fill rewrites DLLs inside the emulation
    # root, which every invocation on the machine shares just as C:\dumps does.
    acquire_lock(args.timeout)

    try:
        ords = ordinal_imports(tgt)
    except (BadPE, struct.error) as e:
        print(f"[!] import table unparseable ({e}) - skipping the ordinal gap-fill"); ords = []
    if ords:
        print("[i] ordinal imports: " + ", ".join(f"{d}#{o}" for d, o in ords))
        gap_fill(args, ords)

    print(f"[*] running sogen (unicorn+JIT){' [payload]' if args.run_payload else ' [stop@OEP]'} timeout={args.timeout}s")
    run = run_analyzer(args)
    log = run["log"]
    if run["timeout"]: print(f"[!] analyzer hit the {args.timeout}s timeout and was killed - any dump may be partial")
    if run["rc"]: print(f"[!] analyzer exited {run['rc']}")
    if run["err"].strip():
        print("[analyzer stderr]")
        for ln in run["err"].strip().splitlines()[-20:]: print("    " + ln)

    upath = os.path.join(DUMPS, "unpacked.bin"); mpath = os.path.join(DUMPS, "unpacked.meta")
    if not (os.path.isfile(upath) and os.path.getsize(upath)
            and os.path.isfile(mpath) and os.path.getsize(mpath)):
        for ln in log.splitlines():
            if any(k in ln for k in ("UNPACK", "terminated", "HardError", "backend")): print("    " + ln)
        if "C0000138" in log:
            print("[!] STATUS_ORDINAL_NOT_FOUND: an import-by-ordinal has no emu-root export. Re-check the")
            print("    ordinal-imports list above; patch its DLL with patch_ordinal.py and retry.")
        sys.exit("[!] no unpacked image produced. Hints: --nodelay --tsc 0x8000 --timeout 480, or --oep 0xRVA.")

    # Nothing above proves the dump belongs to THIS run: C:\dumps is a fixed path baked into analyzer.exe
    # and shared by every invocation on the machine. Bind it to the run before publishing anything.
    if min(os.path.getmtime(upath), os.path.getmtime(mpath)) < run["t0"]:
        sys.exit(f"[!] the dump in {DUMPS} predates this run - it belongs to an earlier sample.\n"
                 "    Refusing to publish it. Delete it and re-run.")
    with open(mpath, encoding="latin1") as f:
        meta = dict(l.strip().split("=", 1) for l in f if "=" in l)
    missing = [k for k in META_KEYS if k not in meta]
    if missing: sys.exit(f"[!] unpacked.meta is missing {', '.join(missing)} - refusing to publish a partial dump.")
    try:
        m = {k: int(meta[k], 16) for k in META_KEYS}
    except ValueError as e:
        sys.exit(f"[!] unpacked.meta holds a non-hex value ({e}) - refusing to publish.")
    # The loader page-aligns SizeOfImage, so the meta legitimately carries the rounded-up value while
    # the on-disk header may not be aligned at all - a known anti-analysis malformation, i.e. exactly
    # this tool's input. Accept either; keep entry_rva strict, it is not transformed.
    if m["size_of_image"] not in (pb["size_of_image"], _page_up(pb["size_of_image"])) \
            or m["entry_rva"] != pb["entry_rva"]:
        sys.exit("[!] the dump does not describe this target - refusing to publish it:\n"
                 f"    target: size_of_image=0x{pb['size_of_image']:x} entry_rva=0x{pb['entry_rva']:x}\n"
                 f"    dump  : size_of_image=0x{m['size_of_image']:x} entry_rva=0x{m['entry_rva']:x}\n"
                 f"    Another vmpunpack run is probably sharing {DUMPS}; run them one at a time.")
    if m["base"] != pb["base"]:
        print(f"[i] dump base 0x{m['base']:x} differs from the header's 0x{pb['base']:x} (image was relocated)")
    if not (0 < m["oep_rva"] < pb["size_of_image"]):
        sys.exit(f"[!] oep_rva 0x{m['oep_rva']:x} is outside the image (size_of_image="
                 f"0x{pb['size_of_image']:x}) - refusing to publish a bogus entry point.")

    # a rerun that produces fewer artefacts must not leave the previous run's next to the new ones
    name = os.path.splitext(os.path.basename(args.target))[0]
    out_exe = os.path.join(out, name + ".unpacked.exe")
    for f in DUMP_FILES + ("iocs.txt", name + ".unpacked.exe"):
        try: os.remove(os.path.join(out, f))
        except FileNotFoundError: pass
        except OSError as e:
            print(f"[!] stale {f} in the output dir could not be removed ({e})")
            print("    - it is NOT from this run; close whatever holds it open.")
    shutil.copy(upath, os.path.join(out, "unpacked.bin")); shutil.copy(mpath, os.path.join(out, "unpacked.meta"))
    extras = []
    for extra in ("unpacked_late.bin", "heap.bin"):
        ep = os.path.join(DUMPS, extra)
        if os.path.isfile(ep) and os.path.getsize(ep) and os.path.getmtime(ep) >= run["t0"]:
            shutil.copy(ep, os.path.join(out, extra)); extras.append(extra)

    with open(upath, "rb") as f: img = f.read()
    # the .meta was matched to the target above, but the image published is unpacked.bin - bind it too,
    # or a torn .bin/.meta pair from a concurrent run still gets through
    try:
        ib = pe_basics(img)
        if ib["size_of_image"] not in (m["size_of_image"], _page_up(m["size_of_image"])) \
                and m["size_of_image"] != _page_up(ib["size_of_image"]) \
                or ib["entry_rva"] != m["entry_rva"]:
            sys.exit("[!] unpacked.bin's own headers disagree with unpacked.meta - the two files come from\n"
                     f"    different runs sharing {DUMPS}. Refusing to publish.")
    except (BadPE, struct.error):
        pass                        # erased header page: the reconstruct_pe path below reports it
    check_oep(img, m, args, log)
    if len(img) != m["size_of_image"]:
        print(f"[!] dump is 0x{len(img):x} bytes but SizeOfImage is 0x{m['size_of_image']:x} - size mismatch;")
        print("    section raw sizes are clamped to what is actually present.")
    try:
        oep = reconstruct_pe(img, meta, out_exe)
    except (BadPE, struct.error) as e:
        print(f"[!] cannot rebuild a loadable PE: {e}")
        print(f"    The packer most likely erased its own header page before jumping to OEP.")
        print(f"    unpacked.bin and unpacked.meta are in {out} - rebuild the headers from the")
        print(f"    target's on-disk ones by hand (base=0x{m['base']:x} oep_rva=0x{m['oep_rva']:x}).")
        sys.exit(1)
    print(f"[+] OEP rva 0x{oep:x}; wrote {out_exe}")

    def _sources():                      # one dump resident at a time: heap.bin can be hundreds of MB
        yield "unpacked.bin", img
        for extra in extras:
            with open(os.path.join(out, extra), "rb") as f: yield extra, f.read()
    blocks, lines = [], []
    for src, buf in _sources():
        dom, url, ip = grep_iocs(buf)
        blocks.append(f"[{src}]\ndomains: {', '.join(dom)}\nurls: {', '.join(url)}\nips: {', '.join(ip)}\n")
        lines.append(f"[IOC] {src}: domains={dom or '-'}  urls={url or '-'}  ips={ip or '-'}")
    # Name the sample in the file itself. iocs.txt has a fixed name, so a shared -o overwrites it and
    # an unlabelled set of C2 domains is one copy-paste away from being attributed to the wrong sample.
    head = (f"# vmpunpack {__version__}\n"
            f"# sample: {os.path.basename(args.target)}\n"
            f"# sha256: {sha256_file(args.target)}\n"
            f"# oep_rva: 0x{m['oep_rva']:x}   base: 0x{m['base']:x}\n"
            f"# flags: {' '.join(sys.argv[1:])}\n"
            f"# utc: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\n")
    with open(os.path.join(out, "iocs.txt"), "w", encoding="utf-8", errors="backslashreplace") as f:
        f.write(head + "\n".join(blocks))  # write before printing: a console failure must not lose the file
    for ln in lines: print(ln)
    print(f"[+] DONE -> {out}")

if __name__ == "__main__":
    main()
