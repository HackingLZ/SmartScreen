# Development and commit preparation

Run commands from the repository root. The project is usable directly from a checkout; installation is not required.

## Source layout

`smartscreen/` contains the client and reusable modules. `smartscreen.py` is a small launcher, and `python -m smartscreen` runs the same command. Tests live in `tests/`; optional collection and validation helpers live in `tools/`. Use package imports such as `smartscreen.data`, `smartscreen.model`, and `smartscreen.vision`. The `SmartScreenClient` interface remains exported by `smartscreen`.

`tools/lab.py` requires an explicit `--host user@host`. It has no saved host or password and retains strict SSH host verification. `tools/validate_native_murmur.py` requires an explicit `--ghidra` installation directory; `--java` defaults to the `java` on PATH. These helpers require separately collected local evidence and tools.

The long command reference and research findings are preserved in [guide.md](guide.md). Relative `analysis/` evidence references describe the optional local archive, not files included in Git. Historical scripts in that archive retain their original layout assumptions; maintained helpers use the package imports above.

## Tests

```sh
python3 -m unittest discover -s tests -t . -v
.venv-vision/bin/python -m unittest discover -s tests -t . -v
.venv-vision/bin/python tools/validate_vision.py --assets models/scareware --require-baseline
```

The cleanup was checked against an export of the exact staged files in a separate directory, without access through the checkout to `analysis/`, `artifacts/`, `models/`, or `local/`:

| Environment | Discovered | Passed | Explicit skips | Failures/errors |
|---|---:|---:|---:|---:|
| Full local research environment, Python 3.12.7 | 368 | 368 | 0 | 0 |
| Clean staged copy, Python 3.12.7 with optional dependencies | 368 | 344 | 24 | 0 |
| Clean staged copy, Python 3.9.6 without optional dependencies | 368 | 320 | 48 | 0 |

Skipped tests identify missing private captures, acquired binaries/model assets, or optional packages. Portable tests retain native arithmetic and synthetic URL controls in `tests/fixtures/native/`; their manifest records source and fixture hashes. No native runtime or account credentials are included with those controls.

Navigation fixtures replace lab addresses with documentation addresses, replace correlation IDs and server contexts, normalize navigation timestamps, and omit feedback URLs. They retain schema behavior, not exact authenticated wire bytes. Image controls come from attributed public Microsoft images; they contain no text/EXIF metadata. The single allowed executable is generated from Python, has a pinned SHA256, and only exits with code 73.

## Local material excluded from Git

Raw captures and system inventory are retained privately, not erased. Loose originals moved into `local/private/`; cleanup backups and reports live in `local/commit-prep/`. Existing `analysis/`, `artifacts/`, `models/`, and virtual environments remain ignored. `.DS_Store` files were removed.

The root allowlist in `.gitignore` prevents new captures or request outputs from entering Git merely because they were created in the repository root. Only declared source/documentation roots are eligible. Nested rules also exclude OS/editor debris, caches, credentials, databases, network captures, downloaded assets, and native binaries. A narrow exception permits the reviewed executable fixture. When adding a new project root, deliberately update `.gitignore` and the staged-file audit's allowed paths.

## Review the exact staged content

```sh
git status --short
git diff --cached --check
git diff --cached --stat
python3 tools/audit_git.py
```

The audit reads Git's index rather than trusting the working files. It checks unexpected paths, symlinks, private/generated artifacts, oversized or unreviewed binaries, common token formats, user-home paths, JSON credential/device fields, image text/EXIF metadata, and bounded base64 strings. It prints only rule names and locations when something matches.

For machine-specific checks, create an **ignored** JSON array of private usernames, paths, addresses, or credential values and run:

```sh
python3 tools/audit_git.py --private-rules local/private-rules.json --output local/audit.json
```

Private rules are not embedded in the committed checker. These checks supplement manual review; they cannot prove the absence of every possible secret. Re-run after changing the index, then commit and push with Git. The audit utility does not create commits or publish files.
