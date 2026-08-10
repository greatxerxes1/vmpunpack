# Contributing

## Getting set up

```bat
git clone https://github.com/milk-analyzer/vmpunpack.git
cd vmpunpack
setup.cmd
```

Python 3.8+ is the only dependency. The tool is stdlib-only on purpose — it runs on locked-down
analysis VMs where `pip install` is not an option. **Please do not add third-party packages** without
opening an issue first.

## Running the tests

```bat
py -3 tests\run_tests.py
py -3 tests\run_tests2.py
powershell -ExecutionPolicy Bypass -File tests\launcher.ps1
```

They need neither the engine nor a malware sample: every fixture is a synthetic PE built in memory, and
`analyzer.exe` is stubbed. That is deliberate — CI runs the same suites on every push.

## What a good change looks like

This tool tells an analyst what a piece of malware is. **Silently wrong output is worse than a crash**,
so the bar is:

- A new parsing path treats sample bytes as hostile: bounded loops, no unchecked index, no
  sample-derived string used as a path.
- Anything published to the output directory is provably derived from *this* run's input.
- A failure says what happened and what to do about it, rather than falling through.

Add a test that fails without your change. If you are fixing a case the suites structurally could not
reach, say so in the PR — that is the most valuable kind of test here.

## Style

Match the surrounding code. It is deliberately compact: short helpers, few comments, and comments that
explain *why* rather than what. No formatter is enforced; no type annotations are expected.

## Reporting bugs

Open an issue with the template. For a misidentified OEP or a bad dump, the log output and the sample's
SHA-256 are worth more than a description — **do not attach the sample itself**, link to VirusTotal or
Malware Bazaar instead.

Security-relevant bugs go through [SECURITY.md](SECURITY.md), not the issue tracker.
