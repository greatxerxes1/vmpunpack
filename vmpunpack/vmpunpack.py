import argparse, os, re, struct, subprocess, sys, shutil

DUMPS = r"C:\dumps"
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def pe_at(b): return u32(b, 0x3c)

def sections(b):
    pe = pe_at(b); nsec = u16(b, pe+6); optsz = u16(b, pe+20); so = pe+24+optsz
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

def pe_basics(b):
    pe = pe_at(b); opt = pe+24; is64 = u16(b, opt) == 0x20b
    return dict(is64=is64, entry_rva=u32(b, opt+16),
                base=(u64(b, opt+24) if is64 else u32(b, opt+28)),
                size_of_image=u32(b, opt+56),
                datadir_off=opt + (112 if is64 else 96))

def ordinal_imports(b):
    secs = sections(b); pb = pe_basics(b)
    imp_rva, imp_sz = struct.unpack_from("<II", b, pb["datadir_off"] + 1*8)
    io = rva_to_off(secs, imp_rva)
    res = []
    if not io:
        return res
    def rstr(off):
        e = b.index(b"\0", off); return b[off:e].decode("latin1", "replace")
    i = 0
    while True:
        d = b[io+i*20: io+i*20+20]
        if len(d) < 20: break
        oft, ts, fc, nameRva, fthunk = struct.unpack("<IIIII", d)
        if oft == 0 and nameRva == 0 and fthunk == 0: break
        dll = rstr(rva_to_off(secs, nameRva)) if rva_to_off(secs, nameRva) else "?"
        to = rva_to_off(secs, oft or fthunk)
        if to is not None:
            j = 0
            while True:
                v = u64(b, to + j*8)
                if v == 0: break
                if v & 0x8000000000000000:
                    res.append((dll, v & 0xffff))
                j += 1
        i += 1
    return res

def export_ordinal_rva(b, ordinal):
    secs = sections(b); pb = pe_basics(b)
    exp_rva, exp_sz = struct.unpack_from("<II", b, pb["datadir_off"] + 0*8)
    if not exp_rva: return None
    eo = rva_to_off(secs, exp_rva)
    Base = u32(b, eo+16); nFunc = u32(b, eo+20); aFunc = u32(b, eo+28)
    afo = rva_to_off(secs, aFunc)
    idx = ordinal - Base
    if not (0 <= idx < nFunc): return None
    return u32(b, afo + idx*4)

def patch_export_ordinal_to_ret(dll_path, ordinal):
    b = bytearray(open(dll_path, "rb").read())
    cur = export_ordinal_rva(b, ordinal)
    if cur is None: return "oor"
    if cur != 0: return "already"
    secs = sections(b); pb = pe_basics(b)
    ret_rva = None
    for s in secs:
        if (s["ch"] & 0x20000000) and s["rs"]:
            k = b.find(b"\xc3", s["rp"], s["rp"] + s["rs"])
            if k != -1: ret_rva = s["va"] + (k - s["rp"]); break
    if ret_rva is None: return "noret"
    exp_rva, _ = struct.unpack_from("<II", b, pb["datadir_off"] + 0*8)
    eo = rva_to_off(secs, exp_rva); Base = u32(b, eo+16); aFunc = u32(b, eo+28)
    afo = rva_to_off(secs, aFunc)
    struct.pack_into("<I", b, afo + (ordinal - Base)*4, ret_rva)
    open(dll_path, "wb").write(b)
    return "patched"

def reconstruct_pe(img, meta, out_path):
    b = bytearray(img)
    oep_rva = int(meta["oep_rva"], 16)
    pe = pe_at(b); optsz = u16(b, pe+20)
    struct.pack_into("<I", b, pe+24+16, oep_rva)
    nsec = u16(b, pe+6); so = pe+24+optsz
    for i in range(nsec):
        o = so + i*40; vs, va = struct.unpack_from("<II", b, o+8)
        struct.pack_into("<II", b, o+16, vs, va)
    open(out_path, "wb").write(b)
    return oep_rva

def grep_iocs(b):
    t = bytes(b).decode("latin1", "ignore"); u = bytes(b).decode("utf-16le", "ignore")
    NOISE = re.compile(r"(microsoft|windows|schemas\.|api-ms|\.dll$|mozilla/5\.0 \(windows|w3\.org|"
                       r"verisign|digicert|sectigo|globalsign|chocolatey|hostedtoolcache|nuget|vcpkg)", re.I)
    dom = sorted({s.lower() for s in re.findall(
        r"\b(?:[a-z0-9-]{2,50}\.){1,3}(?:com|net|org|ru|su|io|xyz|top|info|biz|cc|onion|pw|club|online|"
        r"site|dev|app|shop|cyou|sbs|store|cfd|icu|monster|quest)\b", t+" "+u, re.I) if not NOISE.search(s) and len(s) > 6})
    url = sorted({x for x in re.findall(r"https?://[^\s\"'<>\x00]{6,90}", t) if not NOISE.search(x)})
    ip = sorted({x for x in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", t)
                 if x not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and not x.startswith(("6.0.", "10.0.", "5.2.", "6.1.", "6.2.", "6.3."))})
    return dom, url, ip

def run_analyzer(a, args):
    guest_name = os.path.basename(args.target)
    guest_dir = os.path.join(args.emuroot, "filesys", "c", "sample")
    os.makedirs(guest_dir, exist_ok=True)
    shutil.copy(args.target, os.path.join(guest_dir, guest_name))
    for f in ("unpacked.bin", "unpacked.meta", "unpacked_late.bin", "heap.bin"):
        try: os.remove(os.path.join(DUMPS, f))
        except OSError: pass
    env = dict(os.environ); env["SOGEN_UNPACK"] = "1"
    for k in ("SOGEN_STOP_AT_OEP", "SOGEN_NODELAY", "SOGEN_TSC_STRIDE", "SOGEN_OEP_RVA", "SOGEN_LATEDUMP_AT"):
        env.pop(k, None)
    if not args.run_payload: env["SOGEN_STOP_AT_OEP"] = "1"
    if args.nodelay: env["SOGEN_NODELAY"] = "1"
    if args.tsc: env["SOGEN_TSC_STRIDE"] = args.tsc
    if args.oep: env["SOGEN_OEP_RVA"] = args.oep
    if args.late: env["SOGEN_LATEDUMP_AT"] = str(args.late)
    cmd = [os.path.join(args.sogen, "analyzer.exe"), "--backend", "unicorn", "--no-inst-precision",
           "-e", args.emuroot, "-r", os.path.join(args.emuroot, "registry"),
           "--report", os.path.join(DUMPS, "vmp_run.jsonl"), "--stdout", os.path.join(DUMPS, "vmp_guest.txt"),
           "--first-exec", "-c", "C:\\sample\\" + guest_name]
    try:
        p = subprocess.run(cmd, cwd=args.sogen, env=env, capture_output=True, text=True,
                           encoding="latin1", timeout=args.timeout, stdin=subprocess.DEVNULL)
        log = p.stdout or ""
    except subprocess.TimeoutExpired as e:
        log = (e.stdout or "") if isinstance(e.stdout, str) else ""
    return log

def main():
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
    args = ap.parse_args()

    os.makedirs(DUMPS, exist_ok=True)
    if not os.path.isfile(args.target): sys.exit(f"[!] target not found: {args.target}")
    if not os.path.isfile(os.path.join(args.sogen, "analyzer.exe")): sys.exit(f"[!] analyzer.exe not in {args.sogen}")
    out = args.out or (os.path.splitext(args.target)[0] + "_unpacked")
    os.makedirs(out, exist_ok=True)
    tgt = open(args.target, "rb").read()
    pb = pe_basics(tgt)
    print(f"[i] target base=0x{pb['base']:x} entry_rva=0x{pb['entry_rva']:x} size_of_image=0x{pb['size_of_image']:x}")

    ords = ordinal_imports(tgt)
    if ords:
        print(f"[i] ordinal imports: " + ", ".join(f"{d}#{o}" for d, o in ords))
        for dll, ordv in ords:
            dpath = os.path.join(args.emuroot, "filesys", "c", "windows", "system32", dll)
            if not os.path.isfile(dpath):
                d = os.path.dirname(dpath)
                hit = next((f for f in os.listdir(d) if f.lower() == dll.lower()), None) if os.path.isdir(d) else None
                dpath = os.path.join(d, hit) if hit else dpath
            if os.path.isfile(dpath):
                r = patch_export_ordinal_to_ret(dpath, ordv)
                if r == "patched": print(f"[+] gap-filled {dll}#{ordv} (empty export slot -> ret stub)")
            else:
                print(f"[!] emu-root DLL not found for {dll} (ordinal {ordv}) at {dpath}")

    print(f"[*] running sogen (unicorn+JIT){' [payload]' if args.run_payload else ' [stop@OEP]'} timeout={args.timeout}s")
    log = run_analyzer(args, args)

    upath = os.path.join(DUMPS, "unpacked.bin"); mpath = os.path.join(DUMPS, "unpacked.meta")
    if not (os.path.isfile(upath) and os.path.getsize(upath) and os.path.isfile(mpath)):
        for ln in log.splitlines():
            if any(k in ln for k in ("UNPACK", "terminated", "HardError", "backend")): print("    " + ln)
        if "C0000138" in log:
            print("[!] STATUS_ORDINAL_NOT_FOUND: an import-by-ordinal has no emu-root export. Re-check the")
            print("    ordinal-imports list above; patch its DLL with patch_ordinal.py and retry.")
        sys.exit("[!] no unpacked image produced. Hints: --nodelay --tsc 0x8000 --timeout 480, or --oep 0xRVA.")

    meta = dict(l.strip().split("=", 1) for l in open(mpath) if "=" in l)
    shutil.copy(upath, os.path.join(out, "unpacked.bin")); shutil.copy(mpath, os.path.join(out, "unpacked.meta"))
    for extra in ("unpacked_late.bin", "heap.bin"):
        ep = os.path.join(DUMPS, extra)
        if os.path.isfile(ep) and os.path.getsize(ep): shutil.copy(ep, os.path.join(out, extra))
    name = os.path.splitext(os.path.basename(args.target))[0]
    out_exe = os.path.join(out, name + ".unpacked.exe")
    oep = reconstruct_pe(open(upath, "rb").read(), meta, out_exe)
    print(f"[+] OEP rva 0x{oep:x}; wrote {out_exe}")

    dom, url, ip = grep_iocs(open(upath, "rb").read())
    with open(os.path.join(out, "iocs.txt"), "w") as f:
        f.write("domains: " + ", ".join(dom) + "\nurls: " + ", ".join(url) + "\nips: " + ", ".join(ip) + "\n")
    print(f"[IOC] domains={dom or '-'}  urls={url or '-'}  ips={ip or '-'}")
    print(f"[+] DONE -> {out}")

if __name__ == "__main__":
    main()
