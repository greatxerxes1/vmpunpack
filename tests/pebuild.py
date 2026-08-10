import struct

def build_pe(sections, *, is64=True, entry=0x1000, base=0x140000000, size_of_image=0x4000,
             dirs=None, e_lfanew=0x80, total=None, magic=None, nsec_over=None):
    """Minimal but loader-plausible PE. sections: list of dict(name,va,vs,rp,rs,ch,data).
    dirs: {dir_index: (rva, size)}."""
    optsz = 240 if is64 else 224
    nsec = len(sections)
    hdr_end = e_lfanew + 24 + optsz + nsec * 40
    total = total or max([s["rp"] + len(s["data"]) for s in sections] + [hdr_end, 0x400])
    b = bytearray(total)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3c, e_lfanew)
    b[e_lfanew:e_lfanew+4] = b"PE\0\0"
    struct.pack_into("<H", b, e_lfanew+4, 0x8664 if is64 else 0x14c)
    struct.pack_into("<H", b, e_lfanew+6, nsec if nsec_over is None else nsec_over)
    struct.pack_into("<H", b, e_lfanew+20, optsz)
    opt = e_lfanew + 24
    struct.pack_into("<H", b, opt, magic if magic is not None else (0x20b if is64 else 0x10b))
    struct.pack_into("<I", b, opt+16, entry)
    if is64: struct.pack_into("<Q", b, opt+24, base)
    else:    struct.pack_into("<I", b, opt+28, base)
    struct.pack_into("<I", b, opt+56, size_of_image)
    dd = opt + (112 if is64 else 96)
    for idx, (rva, sz) in (dirs or {}).items():
        struct.pack_into("<II", b, dd + idx*8, rva, sz)
    so = opt + optsz
    for i, s in enumerate(sections):
        o = so + i*40
        b[o:o+8] = s["name"][:8].ljust(8, b"\0")
        struct.pack_into("<IIII", b, o+8, s["vs"], s["va"], s["rs"], s["rp"])
        struct.pack_into("<I", b, o+36, s.get("ch", 0x60000020))
        b[s["rp"]:s["rp"]+len(s["data"])] = s["data"]
    return bytes(b)

def import_blob(dll_name, ordinals, *, base_rva, is64=True, terminate_thunks=True, terminate_desc=True):
    """Returns (blob, size) for one IMAGE_IMPORT_DESCRIPTOR + name + thunk array, laid out at base_rva."""
    tw = 8 if is64 else 4
    flag = 0x8000000000000000 if is64 else 0x80000000
    desc_sz = 20 * (2 if terminate_desc else 1)
    name_off = desc_sz
    name = dll_name.encode("latin1") + b"\0"
    thunk_off = name_off + len(name)
    thunk_off += (-thunk_off) % 8
    blob = bytearray(thunk_off)
    blob[name_off:name_off+len(name)] = name
    for o in ordinals:
        blob += struct.pack("<Q" if is64 else "<I", flag | o)
    if terminate_thunks:
        blob += b"\0" * tw
    struct.pack_into("<IIIII", blob, 0,
                     base_rva + thunk_off, 0, 0, base_rva + name_off, base_rva + thunk_off)
    return bytes(blob)

def export_blob(*, base_rva, base_ord, func_rvas):
    """IMAGE_EXPORT_DIRECTORY with an AddressOfFunctions array; 0 entries mean an empty slot."""
    hdr = 40
    afo = hdr
    blob = bytearray(hdr + 4*len(func_rvas))
    struct.pack_into("<I", blob, 16, base_ord)
    struct.pack_into("<I", blob, 20, len(func_rvas))
    struct.pack_into("<I", blob, 28, base_rva + afo)
    for i, r in enumerate(func_rvas):
        struct.pack_into("<I", blob, afo + i*4, r)
    return bytes(blob)
