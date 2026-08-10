"""Fetch the third-party pieces vmpunpack drives but does not redistribute.

`emu_root/` is sogen's emulation root (a capture of a Windows userland, including Microsoft system
DLLs) and `sogen/` is a patched GPL-2.0 build of the sogen emulator. Neither is ours to ship, so the
repository carries only the driver and this script pulls the rest on first use. See THIRD_PARTY.md.
"""
import argparse, hashlib, json, os, shutil, sys, tempfile, time, zipfile
import urllib.request

__version__ = "0.2.0.dev0"

ROOT_URL = "https://sogen.dev/root.zip"
# Patched sogen. Its source is the vmpunpack branch of milk-analyzer/sogen, published so that this
# GPL-2.0 binary travels with the code it was built from. Pinned by hash: the archive is fetched over
# the network and executed against live malware, so a silent substitution must not go unnoticed.
ANALYZER_URL = ("https://github.com/milk-analyzer/sogen/releases/download/"
                "vmpunpack-1.0.1/sogen-vmpunpack-win-x64.zip")
ANALYZER_SHA256 = "464263badb031875f81b42dc6b4083ffbcee45163f363d53b90d701553ec1e13"

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMUROOT = os.path.join(_HERE, "emu_root")
SOGEN = os.path.join(_HERE, "sogen")


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def download(url, dest, timeout=60):
    print(f"[*] {url}")
    h = hashlib.sha256()
    # Without this a server that stalls after the headers hangs setup.cmd forever behind a frozen
    # progress bar: socket.getdefaulttimeout() is None.
    with urllib.request.urlopen(url, timeout=timeout) as r, open(dest, "wb") as f:
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


def safe_extract(z, dest):
    """extractall, but refuse an archive that would write outside dest."""
    for m in z.namelist():
        p = os.path.normpath(m)
        if os.path.isabs(p) or p.startswith("..") or (len(p) > 1 and p[1] == ":"):
            sys.exit(f"[!] refusing archive entry {m!r}: it escapes the extraction directory")
    z.extractall(dest)


def unpack_root(zip_path):
    """root.zip may hold `root/...` or `filesys/...` at the top; normalise to emu_root/root/."""
    tmp = tempfile.mkdtemp(prefix="vmpunpack-root-", dir=_HERE)
    try:
        with zipfile.ZipFile(zip_path) as z:
            safe_extract(z, tmp)
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


MANIFEST = ".vmpunpack-bundle.json"

def _tree(root, label):
    """(archive name, host path) for every file under root, so the zip mirrors the install layout."""
    out = []
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            out.append((label + "/" + os.path.relpath(p, root).replace("\\", "/"), p))
    return out


def export_bundle(path):
    """Pack the installed engine and emulation root into one archive, for carrying to a machine with
    no network. This redistributes nothing: it repackages what THIS machine already downloaded, for
    the same operator. Whether it may go any further is governed by the upstream licences -
    see THIRD_PARTY.md, and note the emulation root contains Microsoft system files."""
    bad = check(verbose=False)
    if bad:
        for b in bad: print(f"[!] {b}")
        sys.exit("[!] refusing to export an incomplete install - run setup.cmd first.")
    items = _tree(SOGEN, "sogen") + _tree(EMUROOT, "emu_root")
    total = sum(os.path.getsize(p) for _, p in items)
    print(f"[*] packing {len(items)} files ({_human(total)}) -> {path}")
    manifest = {
        "vmpunpack_bundle": 1, "tool_version": __version__,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "analyzer_url": ANALYZER_URL, "analyzer_sha256": ANALYZER_SHA256, "root_url": ROOT_URL,
        "files": len(items), "bytes": total,
    }
    done = 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        z.writestr(MANIFEST, json.dumps(manifest, indent=2))
        for i, (arc, p) in enumerate(items):
            z.write(p, arc)
            done += os.path.getsize(p)
            if total: print(f"\r    {_human(done)} / {_human(total)}  ({done*100//total}%)", end="", flush=True)
    print()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""): h.update(blk)
    print(f"[+] {path}  {_human(os.path.getsize(path))}")
    print(f"[i] sha256 {h.hexdigest()}")
    print("[i] copy it to the offline machine next to a vmpunpack checkout and run:")
    print(f"      setup.cmd --import {os.path.basename(path)}")


def import_bundle(path, force=False, want_sha=None):
    """Install a bundle produced by --export. Nothing is fetched."""
    if not os.path.isfile(path): sys.exit(f"[!] no such bundle: {path}")
    if want_sha:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""): h.update(blk)
        if h.hexdigest().lower() != want_sha.lower():
            sys.exit(f"[!] sha256 mismatch\n    expected {want_sha}\n    got      {h.hexdigest()}")
        print(f"[i] sha256 verified")
    existing = [d for d in (SOGEN, os.path.join(EMUROOT, "root")) if os.path.isdir(d)]
    if existing and not force:
        sys.exit("[!] already installed:\n" + "".join(f"    {d}\n" for d in existing)
                 + "    Pass --force to replace it.")
    with zipfile.ZipFile(path) as z:
        try:
            man = json.loads(z.read(MANIFEST))
        except KeyError:
            sys.exit(f"[!] {path} is not a vmpunpack bundle (no {MANIFEST})")
        print(f"[i] bundle from {man.get('created_utc')}, tool {man.get('tool_version')}, "
              f"{man.get('files')} files")
        print(f"[i] engine {man.get('analyzer_sha256', '?')[:16]}… from {man.get('analyzer_url')}")
        for d in existing:
            shutil.rmtree(d)
        safe_extract(z, _HERE)
    sys.exit(1 if check() else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="only report what is installed, download nothing")
    ap.add_argument("--export", metavar="ZIP", default=None,
                    help="pack this machine's installed engine and emulation root into one archive, "
                         "for carrying to a machine with no network")
    ap.add_argument("--import", metavar="ZIP", dest="import_path", default=None,
                    help="install a bundle produced by --export; downloads nothing")
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
    if args.export and args.import_path:
        sys.exit("[!] --export and --import are opposite directions; pick one.")
    if args.export:
        return export_bundle(args.export)
    if args.import_path:
        return import_bundle(args.import_path, args.force, args.sha256)

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
            # sogen/ is analyzer.exe's own DLL search directory. Extracting over a previous install
            # would leave that version's DLLs mixed with this version's analyzer.
            if args.force and os.path.isdir(SOGEN):
                try: shutil.rmtree(SOGEN)
                except OSError as e:
                    sys.exit(f"[!] cannot clear {SOGEN}: {e}\n"
                             "    Close anything holding a file there and re-run.")
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
