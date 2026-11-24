# SmartScreen API research client

Standalone Python tools for SmartScreen reputation APIs, downloaded feeds, local caches, title scoring, and the extracted scareware image model. The core client uses the Python standard library. Optional image and signature features have separate requirements.

## Quick start

Python 3.9 or newer; Python 3.12 is used for the optional image tests. Run from the repository root:

```sh
python3 smartscreen.py --help
python3 smartscreen.py url https://example.com/
python3 smartscreen.py file ./sample.exe --source https://example.com/sample.exe
python3 smartscreen.py lists --download ./feeds --feed-cache ./feed_cache
python3 smartscreen.py offline-url https://example.com/ --feeds ./feeds
python3 -m smartscreen endpoints
```

`python3 smartscreen.py` and `python3 -m smartscreen` run the same CLI. Global options such as `-o`, `--identity`, and `--prepare` precede the subcommand. `file` sends metadata and hashes, not executable contents. Raw requests, responses, captures, and caller identity can contain private data; keep generated output in `local/` or the ignored research directories.

The [complete guide](docs/guide.md) covers every command, Python APIs, native evidence, supported formats, and remaining research gaps.

## Capabilities

- URL, download, file, shell, page-model follow-up, and legacy Appx/MSIX package reputation queries.
- Embedded Authenticode inspection and explicit Windows catalog/SIP trust checks.
- Feed discovery, conditional downloads, verified caching, offline membership, and observed-verdict export.
- Native HTTP/2 capture reconstruction, protocol inspection, and context correlation.
- UTF-8 title scoring and local B32 scareware image inference with preserved positive/negative controls.
- Candidate mapping, feed comparisons, batch queries, and SQLite history.

An HTTP success or feed match is not an enforcement verdict. The downloaded hashes and Bloom filters cannot expose a complete plaintext global blocklist. Current custom Bloom data, authenticated L14 assets, legacy-v1 scoring, and the final scareware-reporting path remain outside validated coverage. See [coverage and limits](docs/guide.md#coverage-and-remaining-useful-work).

## Optional image and signature support

```sh
python3.12 -m venv .venv-vision
.venv-vision/bin/python -m pip install -r requirements-vision.txt
.venv-vision/bin/python smartscreen.py vision-download models/scareware
.venv-vision/bin/python smartscreen.py score-image tests/fixtures/vision/scam.png --assets models/scareware
.venv-vision/bin/python tools/validate_vision.py --assets models/scareware --require-baseline
```

For certificate inspection alone, install `requirements-signatures.txt`. Windows catalog and registered-SIP trust paths require Windows. Downloaded models and native Microsoft binaries are not included in Git. Saved image fixtures retain their source attribution and expected hashes in [fixtures.json](tests/fixtures/vision/fixtures.json).

## Layout

```text
smartscreen.py              Source-checkout CLI launcher
smartscreen/               Client, parsers, models, and reusable Python modules
tests/                     Unit tests and sanitized portable fixtures
tools/                     Lab collection, validation, and staged-file audit
tools/ghidra/              Headless reverse-engineering scripts
examples/                  Synthetic identities and batch inputs
docs/guide.md              Full command reference and research findings
docs/development.md        Testing and commit preparation
local/                     Ignored private originals, reports, and history
analysis/                  Ignored raw research evidence and historical harnesses
artifacts/                 Ignored collected native binaries
models/                    Ignored downloaded model assets
```

Python imports now use package paths, for example `from smartscreen.vision import ScarewareClassifier` or `from smartscreen.data import inspect_data`. The core `from smartscreen import SmartScreenClient` interface remains available. The earlier flat `smartscreen_*.py` modules have moved into this package. Batch history defaults to `local/history.sqlite3`.

## Tests and commit checks

```sh
python3 -m unittest discover -s tests -t . -v
python3 tools/audit_git.py
```

The local research environment passed all 368 existing tests after the layout change. A clean checkout skips tests that explicitly require private captures, native binaries, downloaded models, or optional dependencies; the portable suite must still pass. Clean-checkout results and commit-preparation details are documented in [development.md](docs/development.md).

`.gitignore` permits only the reviewed project roots and excludes OS/editor files, environments, captures, credentials, generated outputs, and model assets. The audit checks the exact staged Git blobs, including fixture metadata and bounded base64 content, without printing matched private values. It supplements manual review and is not an exhaustive guarantee against arbitrary secrets. No commit or remote publication is performed by these tools.
