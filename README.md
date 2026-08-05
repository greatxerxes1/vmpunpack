# vmpunpack

Self-contained generic **VMProtect / basic-packer unpacker** for x64 PEs. One command, runs **locally on any
analysis VM**.

It runs the target through a patched [sogen](https://github.com/momo5502/sogen) emulator (which sails past
VMProtect's anti-VM / anti-debug that bail on any.run / CAPE / bare metal), drives the packer stub to the
**original OEP**, dumps the fully-unpacked image, reconstructs a loadable PE, greps IOCs, and **auto-fills
emulation-root ordinal-import gaps** so a fresh sample just works.

> Unpacks/decompresses — it does **not** devirtualize. VMProtect-virtualized functions stay VM bytecode; you
> get a working, analyzable image with the VM intact, not the original pre-VMP assembly.

## Quick start

1. Download & extract **`vmpunpack-dist.zip`** anywhere (e.g. `C:\vmpunpack-dist`).
2. Install **Python 3** and make sure `python` is on `PATH`. *(That's the only external dependency — the patched
   engine and emulation root are already inside the bundle.)*
3. Run it:

```bat
RUN_ME.cmd C:\samples\thing.exe
```

Output lands in `<sample>_unpacked\` next to the sample.

## Flags

| flag | meaning |
|---|---|
| `-o OUTDIR` | output dir (default `<sample>_unpacked`) |
| `--run-payload` | run PAST OEP and capture behaviour (network / files / registry) instead of freezing at OEP |
| `--nodelay` | neutralize anti-sandbox `NtDelayExecution` sleeps |
| `--tsc 0x8000` | advance rdtsc by a stride per call (collapse rdtsc delay loops) |
| `--oep 0xRVA` | force the OEP RVA (override the heuristic; the log prints every candidate section) |
| `--late N` | also dump `unpacked_late.bin` + `heap.bin` after N post-OEP blocks (runtime-decrypted config) |
| `--timeout SEC` | run cap (default 300) |
| `--sogen DIR` / `--emuroot DIR` | override engine paths (default: inside the bundle) |

## Output

| file | what |
|---|---|
| `<name>.unpacked.exe` | reconstructed PE, entry set to the real OEP — load in IDA/Ghidra (image base `0x140000000`) |
| `unpacked.bin` / `.meta` | raw memory image + base / SizeOfImage / entry / OEP |
| `iocs.txt` | domains / URLs / IPs grepped from the image |
| `unpacked_late.bin`, `heap.bin` | only with `--late` |

The reconstructed PE is an **analysis** image (its IAT holds emulator addresses), not guaranteed runnable
elsewhere without a Scylla-style IAT rebuild.

## How it works

1. **Backend `unicorn` + `--no-inst-precision`** — sogen defaults to per-instruction hooks (single-step, slow);
   this lets unicorn (TCG) JIT, so the whole stub + decompression finishes in ~2 min instead of never.
2. **OEP detection** — arms an address-execution hook on the target's original code section (the lowest-RVA
   executable section that does **not** contain the packer entry point). First hit there = OEP → dump the image.
   All addresses come from the target PE headers, nothing is hard-coded.
3. **Ordinal gap-fill** — before running, scans the target's imports for `#ORD` entries and, if the emulation-root
   DLL leaves that ordinal an empty export slot, points it at a ret-stub so the loader can snap it (otherwise a
   fresh sample dies with `Emulation terminated with status C0000138` / `STATUS_ORDINAL_NOT_FOUND`).

## What's in the bundle

```
vmpunpack-dist/
  RUN_ME.cmd     top launcher (checks python, creates C:\dumps scratch, calls the tool)
  README.md      this file
  vmpunpack/     the tool (vmpunpack.py, vmpunpack.cmd, patch_ordinal.py)
  sogen/         patched analyzer.exe + runtime DLLs + Ghidra specs  (~18 MB)
  emu_root/      Windows system DLLs + registry the emulator boots against  (~540 MB)
```

`C:\dumps\` is used only as transient scratch (auto-created). The bundle is location-independent — the tool
resolves its engine paths relative to itself.

> **Note:** stock sogen from upstream will **not** work — this needs the patched `analyzer.exe` in the bundle
> (unpack / OEP-dump / ordinal-gap-fill hooks).

## Caveats

- Not a devirtualizer (see top).
- Full-program virtualization, multi-stage loaders, or TLS-callback tricks may need `--oep`, `--late`, a bigger
  `--timeout`, or manual work.
- **Live C2 is usually runtime-only** (e.g. resolved via DoH) and not in the dump — use `--run-payload`
  (best-effort; the emulator has no real network) or run the unpacked PE in a net-connected sandbox / RE the resolver.
- New samples may import a *different* function by ordinal; the auto gap-fill covers empty slots. `patch_ordinal.py
  <emuroot-dll> <ordinal>` is the manual version for anything exotic.
