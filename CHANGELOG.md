# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The pinned engine is now `vmpunpack-1.0.1`. It fixes a host-pointer dereference of a guest-authored
  exception record, de-hardcodes the self-modification write window (previously two literals from one
  sample, which also granted write during ordinary sogen runs), makes `SOGEN_OEP_RVA` hook the exact
  address instead of the whole section containing it, stops the emulator rather than one vCPU at the
  OEP, refuses to write `unpacked.meta` when the image dump failed, and gates the `[DIAG]` scaffolding.
  See the [release notes](https://github.com/milk-analyzer/sogen/releases/tag/vmpunpack-1.0.1).
- `--late` now requires `--run-payload`. Without it the emulator stops at the OEP, so there are no
  post-OEP basic blocks and the late dump could never be taken — the combination was silently inert.

### Fixed

- `--oep` and `--tsc` accepted hex without the `0x` prefix and forwarded it verbatim to an engine that
  parses with `strtoull(base 0)`, so `--oep b3dc` arrived as 0 and `--tsc 08000` as an invalid octal.
  Both are normalised now, and an `--oep` outside the image is rejected before the run rather than
  after the timeout.
- A sample whose `SizeOfImage` is not page-aligned — an anti-analysis malformation, i.e. this tool's
  input — was refused with a message blaming a concurrent run. The loader's page-aligned value is now
  accepted alongside the header's.
- The OEP is a heuristic with no corroboration in the engine, so a dump taken at the packer's own entry
  point satisfied every other check and published as a successful unpack. The driver now refuses an
  image whose OEP page is empty, refuses a dump whose OEP is not the one `--oep` asked for, names the
  section the OEP landed in, warns when that section is not executable or when the OEP equals the
  packer entry, and reports the engine's readable-page ratio.

### Added

- A lock on `C:\dumps\.lock` for the duration of a run. The README already promised concurrent runs
  were refused; the identity checks could not detect two runs of the *same* sample.
- `iocs.txt` now opens with the sample name, its SHA-256, the OEP, the flags used and a UTC timestamp.
  The file has a fixed name, so a shared `-o` overwrote it and left the C2 list unattributable.
- `tests/run_tests3.py`: the `reconstruct_pe` round trip on a dump-shaped fixture (`PointerToRawData`
  != `VirtualAddress`, a `vs >> rs` tail section, a `rs == 0` section), plus the OEP and locking
  guards. Every earlier fixture had `rp == va`, which made the conversion the function exists for
  indistinguishable from a no-op — three mutants that deleted it survived all 89 previous checks.

### Changed

- **The engine and emulation root are no longer committed.** `sogen/` (a patched GPL-2.0 build) and
  `emu_root/` (a capture of a Windows userland, ~464 MB) are now fetched by `setup.cmd` from their own
  publishers. The clone drops from ~464 MB to well under a megabyte, Git LFS is no longer needed, and
  the repository no longer redistributes anything that is not its own. See [THIRD_PARTY.md](THIRD_PARTY.md).
- `iocs.txt` gained a per-source section for every dump the run produced, not just `unpacked.bin`.

### Added

- MIT licence for the driver, launchers, tests and docs.
- `setup.cmd` / `vmpunpack/setup_engine.py`, with `--check` to validate an existing install.
- `tests/` — 86 checks across three suites, run in CI on every push. They need neither the engine nor a
  sample: every fixture is a synthetic PE built in memory.
- Russian and Simplified Chinese READMEs.
- `--version`.

## [0.1.1] - 2026-08-06

Hardening pass over the whole tool. Every byte of a target sample is attacker-controlled and the
analyst acts on what this prints, so most of these are about never reporting success over output that
does not correspond to the input.

### Security

- An import DLL name taken verbatim from the sample reached `os.path.join` and then an in-place file
  rewrite, so a crafted name escaped the emulation root before the emulator started. Names are now
  constrained to plain filenames and containment-checked with `realpath`/`commonpath`.
- The import walk was unbounded: a malformed table raised `struct.error`, and a crafted one went
  quadratic. Descriptors, thunks and their product are now all bounded.
- `iocs.txt` is written with an explicit encoding and the URL pattern is ASCII-only, so a single high
  byte in a dump can no longer abort the run.

### Fixed

- **Dumps are now bound to the run that produced them.** `C:\dumps` is a fixed path compiled into
  `analyzer.exe` and shared by every invocation on the machine; a failed cleanup was swallowed and the
  acceptance check was existence-and-size, which a previous sample's files pass. Cleanup failure is now
  fatal, dumps must post-date a timestamp taken before launch, and both the `.meta` and the image's own
  headers must match the target.
- `reconstruct_pe` trusted the dumped header. An erased header page produced a non-PE file reported as
  success, and `SizeOfRawData = VirtualSize` dropped sections whose `VirtualSize` is 0. Signatures and
  the section-table extent are validated, and raw sizes are clamped to what the dump holds.
- The IOC extractor discarded real C2 addresses via a prefix filter whose targets never matched the
  pattern anyway; wide strings fed only the domain pattern; the noise filter was an unanchored
  substring, so a Microsoft-impersonating hostname was dropped. All three patterns now see single-byte
  and both UTF-16 alignments, noise is anchored to the registrable host, and the scan is chunked.
- The analyzer's exit code and stderr were discarded, so the documented Git LFS pointer failure
  surfaced as advice to spend longer on tuning flags. Both are reported; a timeout is reported without
  gating publication, since `--run-payload` and `--late` are killed by design after a valid dump.
- 32-bit targets were misread as 64-bit rather than rejected.
- Only the successful gap-fill outcome was reported; `oor` — the exact condition the tool later
  diagnoses as `STATUS_ORDINAL_NOT_FOUND` — printed nothing.
- Stale artefacts from an earlier run survived in the output directory beside new ones.
- `patch_ordinal.py` overwrote live export slots with no guard. It now refuses without `--force`, keeps
  a `.bak`, and exits non-zero on a partial apply.
- `RUN_ME.cmd`'s Python guard never exited — `^&` escaped the separator, so `exit /b 1` was echoed as
  text and the script fell through. It now selects an interpreter by running it and reading its output,
  which also rejects the Windows Store alias stub and Python 2.

## [0.1.0] - 2026-08-05

### Added

- Initial release: drive a packed x64 PE through a patched sogen emulator to its original entry point,
  dump the unpacked image, reconstruct a loadable PE, grep IOCs, and auto-fill ordinal-import gaps in
  the emulation root.

[Unreleased]: https://github.com/milk-analyzer/vmpunpack/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/milk-analyzer/vmpunpack/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/milk-analyzer/vmpunpack/releases/tag/v0.1.0
