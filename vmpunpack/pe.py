"""PE parsing for vmpunpack.

Every byte reaching these functions came out of a packed malware sample, so nothing here trusts a
header field: sizes are bounded, offsets are checked against the buffer, and loops are budgeted.
Malformed input raises BadPE rather than escaping as struct.error or IndexError.

Shared by vmpunpack.py and patch_ordinal.py so the manual path gets the same bounds checks.
"""
import struct

# Bounds on the import walk: every byte of it is attacker-controlled.
MAX_DESCRIPTORS = 4096
MAX_THUNKS = 65536
MAX_ORDINALS = 4096
MAX_THUNK_READS = 1 << 20  # budget across ALL descriptors: the per-dimension caps multiply otherwise


class BadPE(Exception):
    pass


def page_up(x): return (x + 0xfff) & ~0xfff

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


def ordinal_imports(b, on_truncate=None):
    """[(dll, ordinal)] for every import-by-ordinal, deduplicated and sorted.

    on_truncate is called with a message if the walk hit its budget - the caller decides how to
    report that, so this stays a library."""
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
            if on_truncate: on_truncate("import table exceeds the parse budget - the ordinal list is truncated")
            break
    return sorted(set(res))                               # gap_fill rewrites a DLL per entry; dedup first


def export_dir(b):
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
    d = export_dir(b)
    return (d["Base"], d["nFunc"]) if d else None

def find_ret(secs, b):
    """RVA of a 0xC3 byte in the first executable section, or None."""
    for s in secs:
        if (s["ch"] & 0x20000000) and s["rs"] and s["rp"] + s["rs"] <= len(b):
            k = b.find(b"\xc3", s["rp"], s["rp"] + s["rs"])
            if k != -1: return s["va"] + (k - s["rp"])
    return None

def patch_export_ordinal_to_ret(dll_path, ordinal):
    """Point an EMPTY ordinal export slot at a ret stub. Returns patched / already / oor / noret."""
    with open(dll_path, "rb") as f: b = bytearray(f.read())
    d = export_dir(b)
    if not d: return "oor"
    idx = ordinal - d["Base"]
    if not (0 <= idx < d["nFunc"]): return "oor"
    if u32(b, d["afo"] + idx*4) != 0: return "already"
    ret_rva = find_ret(d["secs"], b)
    if ret_rva is None: return "noret"
    struct.pack_into("<I", b, d["afo"] + idx*4, ret_rva)
    with open(dll_path, "wb") as f: f.write(b)
    return "patched"


def reconstruct_pe(img, meta, out_path):
    """Turn a memory dump into a file a disassembler can map: entry -> the real OEP, and every
    section's raw pointer/size rewritten from disk layout to memory layout."""
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
