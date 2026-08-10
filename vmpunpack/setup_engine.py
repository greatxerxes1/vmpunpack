"""Fetch the third-party pieces vmpunpack drives but does not redistribute.

`emu_root/` is sogen's emulation root (a capture of a Windows userland, including Microsoft system
DLLs) and `sogen/` is a patched GPL-2.0 build of the sogen emulator. Neither is ours to ship, so the
repository carries only the driver and this script pulls the rest on first use. See THIRD_PARTY.md.
"""
import argparse, hashlib, os, shutil, sys, tempfile, zipfile
import urllib.request

ROOT_URL = "https://sogen.dev/root.zip"
# Patched sogen. Its source is the vmpunpack branch of milk-analyzer/sogen, published so that this
# GPL-2.0 binary travels with the code it was built from. Pinned by hash: the archive is fetched over
# the network and executed against live malware, so a silent substitution must not go unnoticed.
ANALYZER_URL = ("https://github.com/milk-analyzer/sogen/releases/download/"
                "vmpunpack-1.0.0/sogen-vmpunpack-win-x64.zip")
ANALYZER_SHA256 = "6d077827cc590d740611cbc5ce1ded3bc9cff9cf0c840275ad744d9fd0d6760b"

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMUROOT = os.path.join(_HERE, "emu_root")
SOGEN = os.path.join(_HERE, "sogen")


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def download(url, dest):
    print(f"[*] {url}")
    h = hashlib.sha256()
    with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk: break
            f.write(chunk); h.update(chunk); done += len(chunk)
            if total:
                print(f"\r    {_human(done)} / {_human(total)}  ({done*100//total}%)", end="", flush=True)
            else:
                print(f"\r    {_human(done)}", end="", flush=True)
    print()
    return h.hexdigest()


def unpack_root(zip_path):
    """root.zip may hold `root/...` or `filesys/...` at the top; normalise to emu_root/root/."""
    tmp = tempfile.mkdtemp(prefix="vmpunpack-root-", dir=_HERE)
    try:
        with zipfile.ZipFile(zip_path) as z:
            for m in z.namelist():                       # refuse absolute / traversing members
                p = os.path.normpath(m)
                if os.path.isabs(p) or p.startswith(".."):
                    sys.exit(f"[!] refusing archive entry {m!r}: it escapes the extraction directory")
            z.extractall(tmp)
        top = os.listdir(tmp)
        src = os.path.join(tmp, "root") if "root" in top else tmp
        if not os.path.isdir(os.path.join(src, "registry")):
            sys.exit(f"[!] {ROOT_URL} did not contain a registry/ directory - layout changed upstream?")
        os.makedirs(EMUROOT, exist_ok=True)
        dst = os.path.join(EMUROOT, "root")
        if os.path.isdir(dst): shutil.rmtree(dst)
        shutil.move(src, dst)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check(verbose=True):
    """Report what is present. Returns a list of human-readable problems."""
    bad = []
    analyzer = os.path.join(SOGEN, "analyzer.exe")
    if not os.path.isfile(analyzer):
        bad.append(f"missing {analyzer}")
    reg = os.path.join(EMUROOT, "root", "registry")
    fs = os.path.join(EMUROOT, "root", "filesys")
    for p in (reg, fs):
        if not os.path.isdir(p): bad.append(f"missing {p}")
    hive = os.path.join(reg, "SOFTWARE")
    if os.path.isfile(hive):
        with open(hive, "rb") as f: magic = f.read(4)
        if magic != b"regf":
            bad.append(f"{hive} is not a registry hive (starts with {magic!r}) - a truncated download?")
    if verbose:
        for b in bad: print(f"[!] {b}")
        if not bad: print("[+] engine and emulation root look complete")
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="only report what is installed, download nothing")
    ap.add_argument("--root-url", default=ROOT_URL, help=f"emulation root archive (default {ROOT_URL})")
    ap.add_argument("--analyzer-url", default=os.environ.get("VMPUNPACK_ANALYZER_URL", ANALYZER_URL),
                    help="zip holding the patched analyzer.exe and its runtime DLLs")
    ap.add_argument("--analyzer-sha256", default=None,
                    help=f"expected sha256 of that zip (default: the pinned {ANALYZER_SHA256[:12]}…)")
    ap.add_argument("--sha256", default=None, help="expected sha256 of the emulation-root archive")
    ap.add_argument("--force", action="store_true", help="re-download even if already present")
    args = ap.parse_args()

    if args.check:
        sys.exit(1 if check() else 0)

    if args.force or not os.path.isdir(os.path.join(EMUROOT, "root", "registry")):
        with tempfile.TemporaryDirectory(prefix="vmpunpack-dl-") as td:
            zp = os.path.join(td, "root.zip")
            got = download(args.root_url, zp)
            print(f"[i] sha256 {got}")
            if args.sha256 and got.lower() != args.sha256.lower():
                sys.exit(f"[!] sha256 mismatch: expected {args.sha256}")
            unpack_root(zp)
        print(f"[+] emulation root -> {os.path.join(EMUROOT, 'root')}")
    else:
        print(f"[i] emulation root already present ({os.path.join(EMUROOT, 'root')}); --force to refresh")

    if args.force or not os.path.isfile(os.path.join(SOGEN, "analyzer.exe")):
        # Only enforce the pin for the build we published; a custom --analyzer-url is the caller's
        # own build, so demanding our hash would be nonsense.
        want = args.analyzer_sha256 or (ANALYZER_SHA256 if args.analyzer_url == ANALYZER_URL else None)
        with tempfile.TemporaryDirectory(prefix="vmpunpack-dl-") as td:
            zp = os.path.join(td, "sogen.zip")
            got = download(args.analyzer_url, zp)
            print(f"[i] sha256 {got}")
            if want and got.lower() != want.lower():
                sys.exit(f"[!] sha256 mismatch for the engine archive\n"
                         f"    expected {want}\n    got      {got}\n"
                         "    Refusing to install it. This archive is executed against live malware.")
            os.makedirs(SOGEN, exist_ok=True)
            with zipfile.ZipFile(zp) as z:
                for m in z.namelist():
                    p = os.path.normpath(m)
                    if os.path.isabs(p) or p.startswith(".."):
                        sys.exit(f"[!] refusing archive entry {m!r}: it escapes the extraction directory")
                z.extractall(SOGEN)
        print(f"[+] engine -> {SOGEN}")
    else:
        print(f"[i] engine already present ({SOGEN}); --force to refresh")

    sys.exit(1 if check() else 0)


if __name__ == "__main__":
    main()
