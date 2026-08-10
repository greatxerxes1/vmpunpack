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
- the **patched emulator** from [milk-analyzer/sogen](https://github.com/milk-analyzer/sogen/releases/tag/vmpunpack-1.0.1),
  pinned by SHA-256. Stock upstream sogen will not work — the unpack hooks live in the emulator, not in
  this Python — and that build is GPL-2.0, so its source is published on the
  [`vmpunpack` branch](https://github.com/milk-analyzer/sogen/tree/vmpunpack) of that fork.

`setup.cmd --check` verifies an existing install at any time. `--analyzer-url <zip>` substitutes your
own build. See [THIRD_PARTY.md](THIRD_PARTY.md).

### Air-gapped machines

`setup.cmd` needs the network, so on an isolated analysis VM install on a connected machine first and
carry the result across:

```bat
setup.cmd                              :: on the connected machine
setup.cmd --export bundle.zip          :: ~150 MB, prints a SHA-256
:: move bundle.zip and a checkout to the VM, then:
setup.cmd --import bundle.zip --sha256 <the printed hash>
```

`--import` fetches nothing. Cloning on the offline VM instead will not work — `sogen/` and `emu_root/`
are not in the repository, which is the whole point of `setup.cmd`.

The bundle is the emulation root you downloaded plus the engine, repackaged for your own transfer; it
is not ours to hand to anyone else, and the Microsoft system files inside it are not yours to either.
See [THIRD_PARTY.md](THIRD_PARTY.md).

### Requirements

Windows x64, Python 3.8+. Nothing else — the tool is stdlib-only so it runs on locked-down analysis VMs.

## Use

```bat
RUN_ME.cmd C:\samples\thing.exe
```

Output lands in `<sample>_unpacked\` next to the sample.

> **Run one sample at a time.** `C:\dumps` is a fixed scratch path compiled into the emulator, so every
> invocation on the machine shares it. A run takes a lock on `C:\dumps\.lock` and a second one refuses
> to start while it is held; a lock left behind by a crash is taken over automatically after the
> timeout elapses. Published output is separately bound to the run that produced it.

### Flags

| flag | meaning |
|---|---|
| `-o OUTDIR` | output dir (default `<sample>_unpacked`); cleared of the previous run's artefacts once a dump is accepted, so it must not be `C:\dumps` |
| `--run-payload` | run past OEP and capture behaviour instead of freezing there |
| `--nodelay` | neutralize anti-sandbox `NtDelayExecution` sleeps |
| `--tsc 0x8000` | advance rdtsc by a stride per call, collapsing rdtsc delay loops |
| `--oep 0xRVA` | force the OEP RVA, overriding the heuristic |
| `--late N` | also dump `unpacked_late.bin` + `heap.bin` after N post-OEP blocks (runtime-decrypted config); requires `--run-payload`, since without it there are no post-OEP blocks |
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
   executable section that does not contain the packer entry point. The first hit there is the OEP,
   derived from the target's own headers. It is a heuristic with no corroboration, so vmpunpack checks
   the result: it names the section the OEP landed in, warns if that section is not executable or if
   the OEP equals the packer's entry point, and refuses to publish an image whose OEP page came back
   empty. Treat a warned-about result as suspect rather than as an unpack.
3. **Ordinal gap-fill.** Imports are scanned for `#ORD` entries; where the emulation root's DLL leaves
   that ordinal an empty export slot, it is pointed at a `ret` stub so the guest loader can snap it.
   Without this a fresh sample dies with `STATUS_ORDINAL_NOT_FOUND` (`C0000138`).

## What the sample sees

The emulation root is a capture of a **GitHub Actions Windows runner**, so from inside it the guest
looks like a Hyper-V virtual machine and says so loudly: the `SYSTEM` hive carries hundreds of
`Hyper-V`, `VMBus` and `Azure` entries, `USERNAME` is `runneradmin`, and `COMPUTERNAME` is a
`runnervm…` string that changes with each upstream rebuild. vmpunpack drops the sample where a
download would land rather than in a directory of its own, but nothing here disguises the environment.

That matters for evasive samples. If one bails immediately, exits cleanly with no dump, or behaves
differently than it does in a sandbox, assume it detected the VM before assuming vmpunpack is broken.
`--nodelay` and `--tsc` defeat the timing checks, not the environment ones.

If you need an environment that does not look like CI, build the root from a machine you control with
sogen's [`grab-registry.bat`](https://github.com/momo5502/sogen/blob/main/src/tools/grab-registry.bat)
and point `--emuroot` at it. That replaces the username, the machine name and the hardware artefacts
together, which is why it beats renaming anything.

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
