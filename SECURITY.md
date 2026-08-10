# Security policy

## What this project is

vmpunpack is **defensive tooling**: it recovers an analysable image from a packed binary so malware
analysts can read it. It does not create, arm or obfuscate anything.

## Run it in a VM

You are pointing this tool at live malware. The emulator is a sandbox, but nothing here is a security
boundary you should bet a workstation on:

- `--run-payload` deliberately executes the sample past its entry point.
- The sample is copied into `emu_root/root/filesys/c/sample/` on your disk before the run.
- The reconstructed `.unpacked.exe` is malware with a rewritten header. It is for a disassembler, not
  for double-clicking.

Use a disposable analysis VM with no credentials and no network path you care about.

## Reporting a vulnerability

Report privately through GitHub's [security advisory
form](https://github.com/milk-analyzer/vmpunpack/security/advisories/new) rather than a public issue.
Please include the vmpunpack commit, your Python version, and a sample or synthetic PE that reproduces
it. Expect a first response within about a week.

In scope, and taken seriously:

- A crafted PE that makes vmpunpack write outside its output directory or the emulation root.
- A crafted PE that makes vmpunpack read or transmit anything off the analysis machine.
- Any path where the tool reports success over output that does not correspond to the input sample.

Out of scope: bugs in [sogen](https://github.com/momo5502/sogen) or its CPU backends — report those
upstream. A crafted PE that merely makes vmpunpack exit with an error message is working as intended.

## Hardening already in place

The parser treats every byte of a sample as hostile. Import DLL names are constrained to plain
filenames and containment-checked before any file is touched; the import walk is bounded in both
dimensions and in total; dumps are bound to the run that produced them before anything is published.
See [CHANGELOG.md](CHANGELOG.md) for the full list.
