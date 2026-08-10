# Third-party components

The MIT licence in [LICENSE](LICENSE) covers **only what lives in this repository**: the Python driver
under `vmpunpack/`, the `.cmd` launchers, the tests and the docs.

vmpunpack drives components it does not contain and does not redistribute. `setup.cmd` fetches them
onto your machine at install time, directly from their own publishers. Their licences are theirs.

| Component | Fetched from | Licence | Notes |
|---|---|---|---|
| **sogen** (`analyzer.exe`) | [milk-analyzer/sogen release `vmpunpack-1.0.1`](https://github.com/milk-analyzer/sogen/releases/tag/vmpunpack-1.0.1), SHA-256 pinned | **GPL-2.0** | Windows/Linux userspace emulator by [momo5502](https://github.com/momo5502/sogen), patched — source on the [`vmpunpack` branch](https://github.com/milk-analyzer/sogen/tree/vmpunpack). |
| **Unicorn Engine** (`unicorn-emulator.dll`) | bundled in the sogen build | **GPL-2.0** | CPU backend. |
| **Icicle** (`icicle-emulator.dll`) | bundled in the sogen build | see upstream | Alternative CPU backend. |
| **Ghidra processor specs** (`sogen/Ghidra/`) | bundled in the sogen build | **Apache-2.0** | Instruction definitions used by the emulator. |
| **MSVC runtime** (`msvcp140.dll`, `vcruntime140.dll`, …) | bundled in the sogen build | Microsoft VC++ redistributable terms | |
| **Emulation root** (`emu_root/`) | `https://sogen.dev/root.zip` | **not redistributable** | A capture of a Windows userland: ~310 Microsoft system DLLs plus registry hives. Microsoft does not licence redistribution of these, which is why they are downloaded from sogen's own host rather than shipped here. |

## The patched analyzer, and GPL-2.0

vmpunpack needs a **patched** sogen build — stock upstream will not work, because the unpack hooks, the
OEP dump and the ordinal gap-fill live in the emulator, not in this Python. sogen is GPL-2.0, so anyone
distributing that modified binary must also make the corresponding modified source available
(GPL-2.0 §3).

That obligation is met: the build `setup.cmd` downloads is released from
[**milk-analyzer/sogen**](https://github.com/milk-analyzer/sogen), a public fork whose
[`vmpunpack` branch](https://github.com/milk-analyzer/sogen/tree/vmpunpack) carries the corresponding
source — five reviewable commits on top of upstream `e3a416b`, 8 files, +406 / −10, documented in
[VMPUNPACK.md](https://github.com/milk-analyzer/sogen/blob/vmpunpack/VMPUNPACK.md). The binary is built
by CI from that branch and pinned here by SHA-256.

If you build your own, point `setup.cmd --analyzer-url` (or `VMPUNPACK_ANALYZER_URL`) at it; the hash
pin is only enforced for the build published above. If you then redistribute your binary, publish your
source alongside it — the same obligation applies to you.

## What is in the emulation root

`root.zip` is built by sogen's own CI on a GitHub Actions Windows runner, so the registry hives inside
it (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`) describe that ephemeral build VM — the local
account is `runneradmin`, the machine name is `runnervmhisb5`. They are genuine hives because guest
`ntdll` and `kernel32` read the registry during process init, but they contain no real person's
credentials. If you would rather not trust a third-party capture, sogen's
[`grab-registry.bat`](https://github.com/momo5502/sogen/blob/main/src/tools/grab-registry.bat) builds a
root from a machine you control.
