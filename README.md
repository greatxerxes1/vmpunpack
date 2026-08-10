<div align="center">

# vmpunpack

**Generic VMProtect / packer unpacker for x64 PE malware.**

[![CI](https://github.com/milk-analyzer/vmpunpack/actions/workflows/ci.yml/badge.svg)](https://github.com/milk-analyzer/vmpunpack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](#requirements)

**English** · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

</div>

---

One command turns a packed x64 PE into a loadable, analysable image.

vmpunpack runs the sample inside a patched [sogen](https://github.com/momo5502/sogen) emulator — which
walks past the anti-VM and anti-debug checks that make VMProtect bail on any.run, CAPE and bare metal —
drives the packer stub to the **original entry point (OEP)**, dumps memory there, rebuilds a PE for
IDA/Ghidra, and greps IOCs.

> **It unpacks. It does not devirtualize.** VMProtect-virtualized functions stay VM bytecode. You get a
> working image with the VM intact, not the original pre-VMP assembly.

## Install

```bat
git clone https://github.com/milk-analyzer/vmpunpack.git
cd vmpunpack
setup.cmd
```

`setup.cmd` fetches the two third-party pieces this repository does not redistribute — roughly 500 MB,
once:

- the **emulation root** from [sogen.dev](https://sogen.dev/root.zip): a captured Windows userland the
  emulator boots against;
- the **patched emulator** from [milk-analyzer/sogen](https://github.com/milk-analyzer/sogen/releases/tag/vmpunpack-1.0.0),
  pinned by SHA-256. Stock upstream sogen will not work — the unpack hooks live in the emulator, not in
  this Python — and that build is GPL-2.0, so its source is published on the
  [`vmpunpack` branch](https://github.com/milk-analyzer/sogen/tree/vmpunpack) of that fork.

`setup.cmd --check` verifies an existing install at any time. `--analyzer-url <zip>` substitutes your
own build. See [THIRD_PARTY.md](THIRD_PARTY.md).

### Requirements

Windows x64, Python 3.8+. Nothing else — the tool is stdlib-only so it runs on locked-down analysis VMs.

## Use

```bat
RUN_ME.cmd C:\samples\thing.exe
```

Output lands in `<sample>_unpacked\` next to the sample.

> **Run one sample at a time.** `C:\dumps` is a fixed scratch path compiled into the emulator, so every
> invocation on the machine shares it. Two concurrent runs are detected and refused, not silently mixed.

### Flags

| flag | meaning |
|---|---|
| `-o OUTDIR` | output dir (default `<sample>_unpacked`); cleared of stale artefacts each run, so it must not be `C:\dumps` |
| `--run-payload` | run past OEP and capture behaviour instead of freezing there |
| `--nodelay` | neutralize anti-sandbox `NtDelayExecution` sleeps |
| `--tsc 0x8000` | advance rdtsc by a stride per call, collapsing rdtsc delay loops |
| `--oep 0xRVA` | force the OEP RVA, overriding the heuristic |
| `--late N` | also dump `unpacked_late.bin` + `heap.bin` after N post-OEP blocks (runtime-decrypted config) |
| `--timeout SEC` | run cap, default 300 |
| `--sogen DIR` / `--emuroot DIR` | engine paths, if you keep them outside the checkout |

### Output

| file | what |
|---|---|
| `<name>.unpacked.exe` | reconstructed PE, entry set to the real OEP |
| `unpacked.bin` / `.meta` | raw memory image + base / SizeOfImage / entry / OEP |
| `iocs.txt` | domains, URLs and IPs, in a section per dump |
| `unpacked_late.bin`, `heap.bin` | only with `--late` |

The reconstructed PE is an **analysis** image: its IAT holds emulator addresses, so it is not guaranteed
to run elsewhere without a Scylla-style IAT rebuild.

IOC extraction reads each dump as single-byte text and as UTF-16 at both alignments, so wide-string URLs
and IPs are caught. Hosts are filtered against an anchored list of known-noise domains; a C2 that merely
looks Microsoft-ish, like `windows-defender-update[.]top`, is reported, not suppressed.

## How it works

1. **`unicorn` backend, `--no-inst-precision`.** sogen defaults to per-instruction hooks; letting the
   TCG JIT run finishes the stub and its decompression in about two minutes instead of never.
2. **OEP detection.** An execution hook is armed on the target's original code section — the lowest-RVA
   executable section that does not contain the packer entry point. The first hit there is the OEP.
   Every address comes from the target's own headers; nothing is hard-coded.
3. **Ordinal gap-fill.** Imports are scanned for `#ORD` entries; where the emulation root's DLL leaves
   that ordinal an empty export slot, it is pointed at a `ret` stub so the guest loader can snap it.
   Without this a fresh sample dies with `STATUS_ORDINAL_NOT_FOUND` (`C0000138`).

## Limits

- Not a devirtualizer.
- Full-program virtualization, multi-stage loaders and TLS-callback tricks may need `--oep`, `--late`,
  a larger `--timeout`, or manual work.
- **Live C2 is usually runtime-only** (resolved via DoH, say) and absent from the dump. `--run-payload`
  is best-effort — the emulator has no real network.
- x64 only. 32-bit targets are rejected rather than misparsed.
- If the packer erases its own header page before jumping to OEP, no loadable PE can be rebuilt; the raw
  `unpacked.bin` and `.meta` are still written for a manual rebuild.

## Project

[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) ·
[Third-party licences](THIRD_PARTY.md)

Tests need neither the engine nor a sample — every fixture is a synthetic PE built in memory:

```bat
py -3 tests\run_tests.py
py -3 tests\run_tests2.py
powershell -ExecutionPolicy Bypass -File tests\launcher.ps1
```

MIT, for the driver and launchers in this repository. The emulator and emulation root it downloads carry
their own licences — [THIRD_PARTY.md](THIRD_PARTY.md).
