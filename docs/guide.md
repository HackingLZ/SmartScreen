# SmartScreen command and research guide

Run commands from the repository root. See the [README](../README.md) for setup and layout. Paths under `analysis/`, `artifacts/`, and `models/` describe optional local research evidence or acquired assets; those directories are excluded from Git. Shareable fixtures are sanitized schema examples, not byte-for-byte wire captures. Historical harness scripts may refer to the earlier flat module layout; current imports use `smartscreen.<module>`.

Standalone Python client for SmartScreen URL, page-model follow-up, download pre-check, browser file-metadata, shell-execution and package-install reputation APIs. It includes embedded, catalog and registered-SIP signature inspection, native network-capture and protocol parsing, offline URL membership, observed-verdict export, cache parsing, decision-path explanation, UTF-8 title scoring, local scareware image inference, candidate mapping, feed comparison and batch history. It builds fresh `SmartScreenHash` headers using the MD5 + CS64MAC implementation recovered from the lab's Microsoft DLL. Windows and an account ticket are not required for the tested HTTP interfaces; native catalog/SIP verification requires Windows.

## Run

Python 3.9 or newer. The core API/feed and network-capture tools require no pip packages. Embedded certificate inspection optionally uses `requirements-signatures.txt`; image inference uses `requirements-vision.txt`, which already includes that dependency. These optional features were tested in Python 3.12. The default HTTP transport uses `curl` when installed, with standard-library HTTPS as a fallback. Use `--transport urllib` or `--transport curl` to select one explicitly. TLS verification remains enabled.

```sh
cd smart

python3 smartscreen.py url https://example.com/
python3 smartscreen.py url https://nav.smartscreen.msft.net/other/malware.html
python3 smartscreen.py url https://nav.smartscreen.msft.net/phishingdemo.html --mode async
python3 smartscreen.py download https://example.com/sample.exe

python3 smartscreen.py file ./sample.exe --source https://example.com/sample.exe
python3 smartscreen.py file ./sample.exe --source https://example.com/sample.exe --surface shell
python3 smartscreen.py hash SHA256_HEX --size 12345 --name sample.exe --source https://example.com/sample.exe

python3 smartscreen.py lists
python3 smartscreen.py endpoints
python3 smartscreen.py -o feeds.json lists --download ./feeds
python3 -m smartscreen.data ./feeds/topTraffic.bin --kind topTraffic --export-records ./topTraffic.hex
python3 -m smartscreen.data ./feeds/synchronousLookupUris.bin
python3 smartscreen.py inspect-data ./feeds/topTraffic.bin --kind topTraffic --key www.google.com
python3 smartscreen.py inspect-data ./feeds/synchronousLookupUris.bin --key example.com
python3 smartscreen.py inspect-data ./feeds/topTraffic.bin --kind topTraffic --url https://www.example.com/docs/
python3 smartscreen.py inspect-data ./feeds/synchronousLookupUris.bin --url https://nav.smartscreen.msft.net/other/malware.html
python3 smartscreen.py inspect-model ./feeds/edgeSettings.bin --token microsoft
python3 smartscreen.py score-title ./feeds/edgeSettings.bin "Microsoft documentation"
python3 smartscreen.py -o settings_readable.json inspect-model ./feeds/edgeSettings.bin --full
python3 smartscreen.py -o feed_changes.json compare-feeds ./feeds_before ./feeds_after
python3 smartscreen.py offline-url https://example.com/ --feeds ./feeds
```

`file` calculates SHA-256 locally and sends metadata. The file body is not uploaded. `hash` requires the file's size, name, and source URL because these are part of the captured request format. `file --include-signatures` adds supported embedded-signature fields; the default and hash-only queries retain empty Authenticode context. Verdicts apply to the submitted context.

`url --mode async` selects `/navigate/3`, observed in interactive Edge 158; the default `sync` mode preserves `/navigate/3/sync`. An `evaluate` result requests further analysis and is not an allow verdict, even when its category says `Allowed`. The standalone URL query does not render a page or automatically invent its follow-up signals.

Output includes `http_status`, `http_ok`, an explicit `verdict` when present, `verdict_source`, `response_category`, raw `rating`, exact server JSON, response headers, byte count, and a response SHA-256. It preserves unknown fields and labels. The observed browser file endpoint's bare `rating:allow` and `rating:unknown` are recognized; other bare rating codes remain uninterpreted. Empty success responses and HTTP errors have a null derived verdict. Server reputation and the eventual Windows/Edge enforcement decision are separate things.

Shell replies use a top-level `$type` for the verdict and a separate opaque `rating` such as `ALLW:100` or `UNKN:100`. The client retains both. Optional server prompt HTML is kept as data, with a text-only `presentation` summary of its message and buttons. This does not establish which buttons a real Windows session would display or enable.

Global options go before the subcommand. `-o` saves a JSON response record. `--body-output` saves exact bytes. For an additional discovered interface:

```sh
python3 smartscreen.py -o response.json request https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3/sync --json request.json
python3 smartscreen.py --body-output settings.bin request https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/settings/3 --json identity-request.json
```

`request` uses POST when a JSON file is supplied and GET otherwise; `--method GET|POST` overrides the method. `--accept` and `--dataset-version` expose the native conditional-download headers in both live and prepared requests. Supply the ETag without quotes; the client quotes `If-None-Match` correctly. GET `SmartScreenPlain` authentication is live-validated: topTraffic returned its 460,992-byte body for version `0` and 304 for its current ETag; the public Bloom returned its 57-byte body. Omitting authentication returned 401; omitting the required ETag returned 400. GET on actions returned 405/Allow: POST. An empty 304 is not a new body; use `lists --feed-cache` for verified reuse. Requests accept identified Microsoft SmartScreen HTTPS hosts and do not automatically follow redirects.

```sh
python3 smartscreen.py --body-output topTraffic.bin request \
  https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/toptraffic/3 \
  --method GET --dataset-version 0 --accept 'application/octet-stream;'
python3 smartscreen.py --prepare ./prepared-get request \
  https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/bloomfilter/x/3 \
  --dataset-version 0
```

`endpoints` separates native capture, live validation, static evidence and unavailable bodies. Its `protocol` catalog includes conditional GET controls and the recovered scareware event. The package route is validated with the specific legacy reader and profile described below. GET evidence is in `analysis/protocol_expansion/get_controls/`.

`--identity identity.json` supplies the `user`, `device`, `caller`, and `client` identity object. Its client version also controls the HTTP User-Agent. `--client-version DECIMAL` explicitly overrides the packed protocol version in both the body and header. Defaults describe the lab's Windows/Edge environment and protocol client version `1.2.2312.1` found in the collected DLL. Dataset contents can depend on client identity/version. They should not be described as every dataset delivered to every current Edge installation. Shell queries are validated with this Edge-compatible profile; complete native-shell context has not been reproduced.

## Signing and publisher metadata

```sh
python3 -m pip install -r requirements-signatures.txt
python3 smartscreen.py inspect-signature ./sample.exe
python3 smartscreen.py file ./sample.exe --source https://example.com/sample.exe --include-signatures
# On Windows, explicitly request cached native trust verification:
python3 smartscreen.py inspect-signature ./sample.exe --windows-trust
python3 smartscreen.py file ./sample.exe --source https://example.com/sample.exe --include-signatures --signature-windows-trust
```

The parser inspects bounded PE certificate tables and CMS signers, certificate names/fingerprints, nested signatures and the signed image digest. It recomputes the Authenticode digest for supported PE layouts and refuses wire enrichment on a mismatch or ambiguous signer selection. This digest differs from the raw file SHA256. Publisher extraction alone does not validate a signature, certificate chain or timestamp. Portable inspection leaves trust unknown; Windows verification is explicit, uses cached trust information and does not execute the file.

The recovered native JSON fields include `hashAlgo`, `hash`, `valid`, `signer`, `issuer` and `signing`. Portable extraction supplies supported partial fields and leaves trust unknown. On a successful explicit Windows cached-trust check, the tool reads the selected signer and issuer-chain SHA1, SIP digest, full encoded signature message, verified countersigner timestamp and validity while the native trust state is open. It converts the timestamp to the native Unix-microsecond string format. This native path works with the standard library on Windows, including when `cryptography` is absent. The wire helper omits fields it cannot establish.

The service accepted the portable publisher fields and echoed their names/fingerprint in response metadata. A controlled comparison held the known Microsoft DLL, source URL, identity and other request fields constant: empty Authenticode and portable partial metadata each returned `unknown`; full native metadata returned `allow`, all with HTTP 200. This shows a whole-metadata-block effect in that observation, without isolating a particular field or demonstrating browser/shell enforcement. Exact contexts and replies are in `analysis/signatures/context_comparison.json`; native addresses and field parity are in `analysis/signatures/findings.json`.

Embedded signatures and catalog signing are separate. An absent embedded certificate is reported as absent embedded data, not proof that the file is unsigned. `--windows-catalog` enumerates local SHA256/SHA1 catalog memberships using a locked member handle and cached `WinVerifyTrust` catalog verification. It retains every matching catalog/algorithm observation. Enumeration alone does not choose a publisher: `--catalog-index N` explicitly selects one for wire metadata, preserving its catalog path, member digest, trust and signer provenance.

```sh
# Windows only; inspect all catalog observations before choosing an index.
python smartscreen.py inspect-signature C:\Windows\System32\smartscreen.exe --windows-catalog
python smartscreen.py inspect-signature C:\Windows\System32\smartscreen.exe --windows-catalog --catalog-index 0
python smartscreen.py file C:\Windows\System32\smartscreen.exe --source https://example.com/smartscreen.exe --include-signatures --signature-windows-catalog --signature-catalog-index 0
# Registered Windows SIP trust also supports inspected non-PE containers.
python smartscreen.py inspect-signature ./MicrosoftEdgeEnterpriseARM64.msi --windows-trust
```

Lab controls found two trusted catalog observations for `apprepapi.dll`, and four each for `smartscreen.exe` and `smartscreen.dll` (multiple catalogs/algorithms). The official Edge ARM64 MSI and installed Defender PowerShell module passed registered-SIP verification; an inert unsigned script returned `0x800b0100` and supplied no signature metadata. Catalog and SIP metadata queries returned HTTP 200 `allow` for the tested Microsoft controls. These are metadata/trust controls, not installer execution. The Python interface is `extract_signatures(path, verify_windows=False, lookup_catalog=False, catalog_index=None)` plus `authenticode_from_report(report)`. Evidence: `analysis/signature_catalog_expansion/`.

## Package reputation

`inspect-package` reads an Appx/MSIX ZIP or an installed package directory containing `AppxManifest.xml`, `AppxBlockMap.xml` and `AppxSignature.p7x`. `package` queries `/windows/shell/service/packageInstall/2`; it does not install the package. Windows derives the package full name through `PackageFullNameFromId`. Other platforms require `--full-name` and check manifest components, but cannot independently establish its publisher ID.

```sh
python3 smartscreen.py inspect-package ./example.msix --full-name FULL_PACKAGE_NAME
python3 smartscreen.py --prepare ./package-request package ./example.msix \
  --full-name FULL_PACKAGE_NAME --location https://example.com/example.msix
python3 smartscreen.py package ./example.msix --full-name FULL_PACKAGE_NAME \
  --location https://example.com/example.msix
```

The reader is explicitly named `smartscreen-1.2.2312.1-prefix4096`: recovered native code reads up to 4,096 bytes from each of the block-map and signature files. Its `hash` is base64 SHA256 of that prefix of **AppxBlockMap.xml**, and its `signature` is base64 of the prefix of **AppxSignature.p7x**. This is not the archive SHA256 or a complete package trust check. One benign installed Microsoft Notepad package returned HTTP 200 `allow / Allowed` using this reader and the default Edge-compatible auth/profile. Current native installer wire parity and installation enforcement remain unverified.

`--dependencies FILE` accepts a JSON list of explicit package metadata rows; `--config FILE`, `--ux-enabled`, and `--location-type uri|path` preserve those native inputs. The parser bounds input sizes and ZIP entries, rejects bundles, encrypted or ambiguous footprint entries and XML entity declarations, and protects source packages/dependencies/config from output overwrites. Python interfaces: `extract_package()` and `package_payload()` in `smartscreen/package.py`. Exact request/response evidence is in `analysis/signature_catalog_expansion/package_response.json`.

## Local scareware image model

The separate on-device visual detector described by [Microsoft](https://blogs.windows.com/msedgedev/2025/01/27/stand-up-to-scareware-with-scareware-blocker/) is extracted and runnable locally. It is distinct from the older title model in `edgeSettings`. Current Edge158 component registrations identify three separately signed packages: a B32 visual model, reference vectors, and a scareware allowlist.

```sh
python3.12 -m venv .venv-vision
.venv-vision/bin/python -m pip install -r requirements-vision.txt
.venv-vision/bin/python smartscreen.py vision-download models/scareware
.venv-vision/bin/python smartscreen.py inspect-vision models/scareware
.venv-vision/bin/python smartscreen.py -o image_result.json score-image screenshot.png --assets models/scareware
```

The verified bundle already saved in `models/scareware` contains model version **2025.10.7.5**, vectors **2026.2.23.1**, and allowlist **2026.11.20.1**. The model is `vti-b-p32-visual.quant.ort`, 176,781,560 bytes, SHA256 `2ffbab5d3623d5e0ccd00d5bf3f1f20a600ee0edc560790de680d7dc8cba02c8`. ONNX Runtime loads it directly; conversion or a Windows runtime is unnecessary. `vision-download` obtains current official update metadata and reuses only hash-matching cached packages. CRX signatures are checked against the full public-key hashes recovered from Edge, and bundle loading rechecks signed payload contents. The updater's CUP response signature is not implemented; package signature verification remains mandatory. Advertised package URLs can use HTTP, with independently checked package hashes and native-pinned signatures; HTTPS certificate checks are never bypassed.

Python use, retaining one model session across images:

```python
from smartscreen.vision import ScarewareClassifier, score_image

classifier = ScarewareClassifier.from_bundle("models/scareware")
result = classifier.score_image("screenshot.png")
print(result["analysis"]["classification"])
for tensor_set in result["analysis"]["tensor_sets"]:
    for pool in tensor_set["pools"]:
        print(pool["threshold"], pool["scores"], pool["labels"])

# Direct artifact paths are also accepted:
# result = score_image("screenshot.png", model="model.ort", vectors="vectors.json")
```

The pipeline crops/resizes to 224×224, normalizes RGB using recovered CLIP constants, runs the quantized model, normalizes its 512-value embedding, and compares that embedding with the supplied reference vectors. SoftMax weights over scam/benign labels produce each pool's 0–100 score; these are not calibrated probabilities that an image is malicious. The downloaded first tensor set has four pools with thresholds **95, 88, 85, 85**, and requires all four to agree. Its index 0 is the recovered native fallback selection. The second set has ten labels and nearest-neighbor data, including 1,416 scam and 1,416 benign probability vectors in its base dataset and three resolution-specific datasets. Both sets are reported; only the selected set controls `classification`. `--tensor-set-index` selects another explicitly. Full source training images and expanded text for abbreviated labels were not recovered.

`score-image` performs local inference without service requests. It returns per-pool label similarities/weights, scores, consensus, configuration assumptions, model/vector hashes and preprocessing metadata. `--include-embedding` also returns the normalized vector. `cloud_verdict` and `browser_decision` remain null: browser fullscreen triggers, effective feature flags, allowlists, policy and cloud reputation are separate. The extracted allowlist contains **67 URL entries and 160 domain entries**, readable in the JSON path listed in `assets.json`; it is not a malicious-URL blocklist and is not applied when classifying a standalone image.

Native default `ShortEdge` cropping is asymmetric: landscape screenshots are centered horizontally, while portrait screenshots use a top-aligned square. This adapter implements the recovered geometry and float32 RGB arithmetic. Alternative scaling modes and resizer validation limits are recorded in result metadata; it does not claim complete browser capture/color-management/UI parity. Component acquisition evidence is in `analysis/scareware_discovery/`, preprocessing evidence in `analysis/scareware_native/`, and scoring evidence in `analysis/scareware_scoring/`. SoftMax and KNN2 have 19 bounded original ARM64 arithmetic checks with explicit library/container shims.

Supported inputs are opaque, single-frame image files supported by Pillow, or PIL images through Python. EXIF orientation is applied; ICC/gamma conversion is not. Inputs are limited to 32 million pixels and 16,384 pixels per dimension. Transparent and animated images are rejected explicitly. `ShortEdge` is the default; `Resize` stretches to the model's square, and `CropCenter` uses a centered 224×224 source crop and requires both dimensions to be at least 224. `LongEdge` padding is not implemented. `--resize-method` accepts the recovered six native names; the default is `resize_lanczos3`. The implementation ports Chromium's 14-bit fixed-point filter/convolution rather than substituting Pillow Lanczos. `--threads` controls CPU inference threads, default 1. Only the recovered B32 512-output model is supported for image inference; the L14 path found in native code has not been acquired or validated.

The L14 investigation traced a real alternate local-load branch: enum 2 selects `vti-l-p14-visual.quant.ort`, a 224×224 input, 768-value output and tensor key `vti-l-p14-visual`. However, this build's component updater registers only enum 1/B32. No authenticated L14 model/vector bundle or alternate acquisition route was recovered. `inspect-vision` now exposes this distinction in `native_compatibility`; a public CLIP model is not substituted. Evidence: `analysis/model_completion/findings.json`.

### Saved positive and negative image controls

Both controls are preserved under `tests/fixtures/vision/`, independently of the ignored `analysis/` directory:

| File | Expected default result | Four pool scores | Thresholds |
|---|---|---|---|
| [`scam.png`](../tests/fixtures/vision/scam.png) | `scam` | 99, 98, 99, 98 | 95, 88, 85, 85 |
| [`not_scam.png`](../tests/fixtures/vision/not_scam.png) | `not_scam` | 97, 90, 76, 96 | 95, 88, 85, 85 |

The positive is the scam-page thumbnail from Microsoft's published warning screenshot, cropped once to isolate the pictured page, before classification. The original is preserved as `source_warning.png`. The negative is Microsoft's unmodified published Edge settings screenshot. Both use the same default model, vectors, crop mode and thresholds; no score settings were adjusted to obtain either result. The negative fails the third pool's threshold, demonstrating why a high individual pool score does not determine the final result.

[`fixtures.json`](../tests/fixtures/vision/fixtures.json) records source URLs, attribution, SHA256 hashes, the positive crop rectangle, expected classifications/scores and baseline model/vector/allowlist hashes. These are two smoke/regression controls, not a measurement of detection accuracy. No pictured website is loaded.

```sh
# Offline repeatable validation. Exit 0 means the expected classifications passed.
.venv-vision/bin/python tools/validate_vision.py --assets models/scareware -o validation.json

# Also require the exact saved model, vectors AND allowlist baseline.
.venv-vision/bin/python tools/validate_vision.py --assets models/scareware --require-baseline -o validation_strict.json

# Inspect a single preserved positive, including its 512-value normalized embedding.
.venv-vision/bin/python smartscreen.py -o scam_result.json score-image tests/fixtures/vision/scam.png --assets models/scareware --include-embedding
```

Validation checks fixture/source hashes and signed bundle contents before running inference. Reports include current asset hashes/versions, runtime version, scores, preprocessing and separate baseline-drift flags. The default validation permits updated signed assets if the classifications still pass; `--require-baseline` fails when any asset changes, including an allowlist-only update. Exit 1 means a failed classification/baseline check; exit 2 means invalid input, missing dependencies or another execution error. Save reports outside the managed asset and fixture directories. `score-image` returns a completed-analysis exit status independently of whether the classification is `scam`; inspect the JSON field for that result.

The original ARM64 checks matched 40 transform cases, 2,718 filters across 18 coefficient cases, nine scalar convolution fixtures and 19 scoring cases. Another 78 instructions executed directly on the ARM64 host confirmed conversion behavior used by the emulation harness. Selected library/container calls and unsupported emulator conversion instructions are explicitly modeled. This establishes bounded arithmetic parity, not exhaustive parity with Windows math libraries, native SIMD, browser capture or live enforcement.

## Offline URL analysis and blocklist limits

After a feed snapshot has been downloaded, `offline-url` performs no network requests. It checks the top-traffic records and public/custom lookup Bloom filters, verifies saved body hashes, and preserves collection timestamps and ETags. Missing, corrupt, or HTTP 304-only data stays unknown. Optionally add `--defaults ./native_defaults` to inspect the separately extracted DLL fallback; it is never substituted for current custom service contents.

```sh
python3 smartscreen.py offline-url https://www.example.com/docs/ --feeds ./feeds
python3 smartscreen.py offline-url https://example.com/ --feeds ./feeds --defaults ./native_defaults
```

This answers **whether a URL's candidates match the available local feeds**. Recovering every original plaintext is unnecessary for checking a supplied URL: its candidate hashes can be computed and compared directly. Local membership does not answer whether the current SmartScreen service would warn or block. A Bloom hit can be a false positive, and a miss is not a clean reputation verdict. The saved `example.com` control has a local Bloom hit and a cloud `allow` response, demonstrating why those outputs must remain separate. A previously recorded cloud response can be reviewed offline, but it remains a historical observation.

The observed APIs have not exposed a complete downloadable list of malicious URLs. Microsoft's [Edge privacy documentation](https://learn.microsoft.com/en-us/legal/microsoft-edge/privacy#smartscreen) describes periodically downloaded top-traffic and dangerous-site lists, alongside synchronous cloud checks. This warrants investigating local dangerous-site facilities; it does not establish that a complete global service database is downloaded. The current binary, local files, and bounded API probes described below have not established such a complete export. For an actual server response, use the online `url` or `batch` command; downloading these local feeds does not reproduce the whole service.

For wire inspection without a network request:

```sh
python3 smartscreen.py --prepare ./prepared url https://example.com/
curl -sS --config ./prepared/curl.conf
```

## Observed URL warnings and blocks

`export-verdicts` creates a locally readable corpus from batch JSONL or the SQLite history. It selects the latest successful explicit verdict **before** filtering: a later allow or unknown withdraws an earlier warning for the same exact request context. Separate profiles, policy context, navigation and download queries are not merged. Transport failures retain the previous historical observation and appear as the last attempted check.

```sh
python3 smartscreen.py -o observed_urls.json export-verdicts history.sqlite3
python3 smartscreen.py observed-url https://example.com/ --catalog observed_urls.json
```

The default selection is navigation `warn` and `block`; repeat `--verdict` or `--kind` to select other values. Exact raw response bytes, recorded digest, parsed result, request-context digest and submitted URL must agree. Invalid records are reported and cause a nonzero CLI exit. The export is historical, has no assumed expiry, preserves warning/block distinctions, and never turns absence into an allow verdict. It does not prove a browser enforced the server result. Only exact submitted URLs are matched; host-wide blocking is not inferred from a path verdict.

Three new benign controls returned `allow / Allowed` for example.com, `warn / Phishing` for Microsoft's phishing demo, and `warn / Malicious` for its malware demo. The two demo warnings are exported in `analysis/current_lab/wire_controls/observed_warnings.json` and explicitly labeled as Microsoft demonstrations. The queries sent URL strings to Microsoft; the reputation client did not navigate to those sites.

## Routing cache and native cache inspection

Server cache actions use `allow`, `evaluate`, and `call_server`. These route later checks; they are not a downloadable cache of `warn`/`block` URL verdicts. Import and look up those actions independently from the observed-verdict corpus:

```sh
python3 smartscreen.py -o routing_cache.json cache-import saved.response.json
python3 smartscreen.py cache-url https://example.com/docs --cache routing_cache.json --scope navigation
python3 smartscreen.py inspect-cache analysis/current_lab/snapshot/local/uriCache --url https://example.com/
```

Use `--at ISO_TIMESTAMP` for historical lookup. Response-cache imports select the native reader automatically for the two exact recorded SDK versions matched to the examined binaries. Without known version metadata, the report explicitly labels its Edge158 reader assumption. `--reader smartscreen_dll_1.0.0.79_arm64` selects the older behavior; a known version mismatch is rejected. Edge uses full SHA-256 keys with a legacy short-key fallback, multiple inheritance probes per URL candidate, and replacement on duplicate insertion. The older DLL uses the first 16 hex characters and retains an existing entry. Cache lifetime, URL candidate scope and precedence are interpreted according to the selected reader. Missing context, expiry and unsupported evidence remain explicit. A supplied `--context context.json` associates imports with an explicitly shared runtime/profile/policy context; different unassociated response origins are not silently combined. Receipt time is an approximation from recorded collection time unless `--received-at` is supplied. A sibling `.bin` is verified when present.

Wire lifetime units also differ: current Edge158 reads `maxAge` as **microseconds**; the legacy DLL reads **100-nanosecond ticks**. Fresh requests using both SDK profiles returned the same value, `100800000000`, which corresponds to 28 hours in the current reader and 2 hours 48 minutes in the legacy reader. This is a verified reader difference, not a demonstrated security defect. Requests now record the effective client version to keep the interpretation reviewable; evidence is in `analysis/current_lab/sdk_cache_comparison.json`.

The actual lab `uriCache_` and `downloadCache_` are version-1 JSON documents, with sibling pointer files `uriCache` and `downloadCache`. They contain hashed keys, numeric results, categories and expiry fields, not a plaintext global URL list. The persisted expiry uses Unix microseconds. The recovered lab entry has routing result `evaluate` despite category `Allowed`, and expired on 2026-11-12. `inspect-cache --url` checks a supplied candidate against this persisted format without claiming current reputation. Native evidence is in `analysis/cache_expansion/`. Testing 20,609 existing local hostname candidates did not identify that opaque cached URL; no candidate sites were contacted.

## Explain the decision path and prepare model requests

```sh
python3 smartscreen.py explain-url https://example.com/ --feeds ./feeds \
  --title "Microsoft documentation" --settings ./feeds/edgeSettings.bin \
  --cloud-response saved.response.json
```

The explanation combines supplied evidence with the recovered conditional stages: browser input/policy, custom lookup filter, top traffic, routing cache, page models, cloud actions/results, remembered overrides, and browser blocking-page dispatch. It marks runtime gates and final enforcement unknown. It is a static explanation, not a recorded browser execution trace. `--cache routing_cache.json` optionally supplies cache evidence, and `--navigation-type` distinguishes top/frame/subresource/download paths.

Interactive Edge 158 used `https://postnav-edge.smartscreen.microsoft.com/api/browser/edge/navigationcomplete/3` for the model follow-up. This corrects the earlier static `nav-edge` host assumption. The client can now send this request or prepare it without sending:

```sh
python3 smartscreen.py --prepare ./prepared_model navigation-complete \
  --context navigation_context.json --models model_results.json --signals page_signals.json
python3 smartscreen.py -o followup.json --body-output followup.bin navigation-complete \
  --context navigation_context.json --models model_results.json --signals page_signals.json
```

All three inputs are explicit JSON. Required context is `userAgent`, `correlationId`, `identity`, `destination` and `type`; `config` is optional and absent `referrer` becomes `{}`. The native controls used an empty userAgent, zero UUID, no config and no serverContext. A previous navigation response's serverContext is not automatically copied into the follow-up. Models contain explicit names/scores. Signals support the captured HTTP redirect chain, HTTPS certificate fields and null/empty defaults; unobserved redirect enum/shape combinations remain rejected. Python callers use `navigationcomplete_payload(context, models, signals)` in `smartscreen/decision.py`.

An isolated interactive Windows11 ARM profile supplied complete native requests and HTTP/200 replies. Microsoft’s [documented benign phishing and malware demos](https://demo.smartscreen.msft.net/) produced real red SmartScreen warning pages, saved as screenshots and DOM observations. A harmless local page titled `Windows Security Alert` scored **16.3673437735292**, received `evaluate`, triggered the follow-up, then received `allow`. A local HTTP 302 chain and an explicitly instrumented benign HTTPS title control also triggered accepted follow-ups. The negative title control rendered normally without an observed follow-up. A positive title score is a selection signal, not proof of a malicious page.

Seven native request bodies, with device tickets/identifiers removed and fresh authentication, returned the same explicit result/category on replay. Three native follow-up bodies also round-trip through the Python builder at the decoded JSON level. This validates these controls on one build; it does not establish every policy, frame, redirect, catalog or shell path. Source evidence is in `analysis/native_browser/`, with portable sanitized cases in `tests/fixtures/navigation/`. The earlier static chain remains documented in `analysis/decision_expansion/`.

Parse your own Chromium `Everything` netlog locally:

```sh
python3 smartscreen.py -o capture_report.json inspect-netlog netlog.json
```

`smartscreen/netlog.py` reassembles segmented HTTP/2 frames by socket and stream, links decoded headers to exact body bytes, checks completeness/lengths and reports navigation relationships. The default report redacts account/device identifiers, authorization and cookies; `--include-sensitive` explicitly exports exact local bytes. Raw captures can contain credentials even with a new browser profile. HTTP/1 and HTTP/3 bodies are outside this parser’s scope, and a network capture alone does not prove browser enforcement. Native captures also observed `/api/browser/edge/telemetry/3`; telemetry was preserved locally, not replayed.

## Native download and shell enforcement

The 2026-11-24 controls used an isolated interactive, limited-user Windows 11 ARM session through SSH and Python diagnostics. The unsigned fixture is a deterministic 2,048-byte ARM64 PE containing three instructions that call `ExitProcess(73)`; it has no file, registry or network behavior. Its SHA256 is `c7468594ebb904070d170f041a848d3ca5d51c42f58eabb84d544be8700bbf7d`. The signed control was the lab's unmodified `whoami.exe` (79,872 bytes), whose Windows catalog trust was valid.

| Surface/control | Captured service result | Observed local outcome |
|---|---|---|
| Edge download of `whoami.exe` | URL pre-check `allow`; file `rating:allow` | Completed file with ZoneId 3; normal Downloads entry |
| Edge download of unsigned fixture | URL pre-check `allow`; file `rating:unknown` | “isn't commonly downloaded” warning with Keep/Delete controls; retained as `.crdownload` pending a decision |
| Shell: signed system binary and identical ZoneId 3 copy | Native shell request not captured in this matrix | Both exited 0 |
| Shell: unsigned fixture without MOTW | No matched native cloud capture | Exited 73 |
| Shell: identical unsigned fixture with ZoneId 3 | Separate standalone query: `block / Untrusted / UNKN:100` | “Windows protected your PC”; SmartScreen said it prevented the unrecognized app from starting; ShellExecute remained pending during the 25-second observation |

All four browser request/response bodies were complete and HTTP 200. Both native file requests contained empty Authenticode metadata; their file hashes matched the saved downloads. Anonymized replays cleared account/device credentials, freshly signed the two file requests, and returned the same `allow`/`unknown` ratings. No Keep/Run-anyway controls were invoked. The shell query used a different explicit filename and default identity, so its agreement is directional, not proof of identical native context or a bypass. The successful unmarked-file control establishes that the unsigned executable itself works; it does not show failure of Internet-zone enforcement.

The Edge policy page showed only recommended `StartupBoostEnabled=false`; captured request configuration independently recorded reputation level `warn`, `enforcedByPolicy=false`, and application control `anywhere`. These are two benign files on one build/profile, not a complete policy/cache matrix. The browser was closed and all research scheduled tasks/processes were removed. Evidence and reproducible Python helpers are in `analysis/enforcement_expansion/`: `browser_findings.json`, `shell_findings.json`, `replay/comparison.json`, and the fixture generator/manifest. Browser downloads were not executed; the separate shell controls used copies with recorded hashes and ADS.

The unsigned fixture, deterministic Python generator, manifest and direct-execution control are also preserved under `tests/fixtures/enforcement/` for future validation. Reputation can change over time; the fixed binary hash and historical warning are recorded observations, not a promise that future service responses will remain identical.

## Protocol and telemetry inspection

```sh
python3 smartscreen.py inspect-protocol response.json
python3 smartscreen.py inspect-protocol telemetry.json --kind telemetry
python3 smartscreen.py -o parsed.json inspect-netlog netlog.json
python3 smartscreen.py correlate-contexts parsed.json
```

These commands operate locally and do not submit reports. `inspect-protocol` accepts a server response or tool response record, captured telemetry JSON, the recovered scareware envelope, or a parsed NetLog. `--kind` can select the format, and `--limit` bounds reported rows. It separates explicit decisions from opaque ratings and summarizes context structure without assigning meanings to its numeric fields. URLs and raw contexts are omitted by default; `--include-sensitive` includes those fields, but identity is always omitted by this inspector. Input size, depth and node count are bounded, and input/output aliases are rejected.

The protocol inspector and API client recognize `$type` decisions. For saved records with a successful HTTP status and the known browser file endpoint, both also recognize the observed `allow`/`unknown` rating labels. Bare documents without endpoint provenance and other rating codes remain uninterpreted.

Captured telemetry includes `scenario`, `serverCall`, `lookup` and `userAction` events. In the earlier native capture, 26 response context occurrences shared only four distinct values; four `serverCall` telemetry contexts exactly matched response values. Therefore `serverContext` is reusable state, not a unique request ID. `correlate-contexts` reports exact string matches without asserting timing or causality. Opaque `UNKN:100`/context numbers are not treated as calibrated confidence scores.

Static Edge analysis recovered the internal scareware event name `evaluateModel` and envelope `{"data":[{"name":"scareware","featureData":"<JSON string>"}]}`, where `featureData` carries `verdict:"block"` and a URL. The final HTTP route/envelope and effective consent/policy gates were not captured. The tool can inspect this envelope but does not invent or submit scareware reports. Addresses, captured telemetry summaries and correlation evidence are in `analysis/protocol_expansion/`.

## Persistent feed cache and current Edge inventory

```sh
python3 smartscreen.py lists --download ./snapshot_1 --feed-cache ./feed_cache
python3 smartscreen.py lists --download ./snapshot_2 --feed-cache ./feed_cache
python3 smartscreen.py offline-url https://example.com/ --feeds ./snapshot_2
```

The cache retains verified complete HTTP 200 bodies and resolves a 304 only against the matching identity, endpoint/query, method, auth scope and requested ETag. Explicit profile versions are preserved. Snapshots retain the actual 304 response and separate provenance for the original body. A bodyless 304 without a matching cache remains unknown. An omitted feed in a reused snapshot directory does not promote old leftover files into the new discovery result. Native builtins are not substituted into this HTTP cache.

The matching Edge 158 binary registers four remote feeds: `topTraffic`, `edgeSettings`, `customSynchronousLookupUris`, and `customSettings`. Its compiled SDK version is **1.2.2609.3**, packed `281483737628675`; this differs from the older standalone DLL's tested default profile. The historical public `synchronousLookupUris` feed is not registered by the examined current Edge factory. Existing general `lists` defaults retain compatibility with the earlier five-feed investigation; advertised presence alone does not establish current Edge usage.

A fresh anonymous probe using the binary-derived SDK version advertised those four datasets. It downloaded topTraffic (460,992 bytes) and edgeSettings (130,578 bytes); that earlier probe received bodyless304 responses from both custom routes. Current custom settings acquisition is now resolved: the actual native request starts with `customSettings=F95BA787499AB4FA9EFFF472CE383A14`, the built-in version. Submitting this version in `identity.client.data.customSettings` returned a **63-byte remote body**, `{"forceServiceDetermination":false,"inScopeProcessPatterns":[]}`, with ETag `3FA91A37E06EB3DAD5B57925CFD0BDB0`. It worked with anonymous identities on both tested SDK versions; no account ticket was needed.

`lists --download` retains version-zero discovery, then retries custom settings once with that verified native baseline only when its implicit initial request has an unavailable 304. Explicit caller versions and verified cached bodies take precedence. Both attempts and the retry reason are preserved in response metadata. A subsequent request using the remote ETag received 304 and correctly reused the saved 200 body. The downloaded 63-byte configuration remains separate from the native 35-byte fallback. Changing the conditional HTTP header alone did not solve acquisition; the request-body version mattered. A full CLI run on Windows Python 3.13 with standard-library HTTPS downloaded topTraffic, public Bloom, edgeSettings and remote customSettings successfully; its saved output is in `analysis/native_browser/feeds_cli/`.

The interactive capture also confirms the current custom Bloom initial wire version is **0**. That route still returned 304 without a body under native0 and historical sentinel probes, including requests without conditional headers. This is unavailable data, not proof of an empty filter. The current lab is not demonstrated to be an enrolled, policy-enabled enterprise configuration. Broader provider inspection found a manual download file-hash denylist flag and local caches, but no complete global URL-list provider. Evidence: `analysis/custom_feed_expansion/findings.json`, `analysis/native_browser/`, and the earlier `analysis/feed_discovery/`.

The follow-up also tried authenticated GET with the exact advertised query string and both starting versions; both returned empty 304. Read-only lab inspection found empty captured enterprise context, no targeted enterprise policy values, a stopped Sense service, and no demonstrated onboarding state. No enrollment was changed. A useful next acquisition needs an authorized device that actually receives this feed; fabricating a tenant identity would not establish that. Current evidence is in `analysis/protocol_expansion/findings.json`. There is still no recovered API or local dataset that yields Microsoft's complete global malicious-URL list.

## Verified results, 2026-11-23

Saved evidence is under `analysis/`.

| Query | Actual response | Evidence |
|---|---|---|
| `https://example.com/` | `result.$type=allow`, category `Allowed`, cache action and server context | `client_url_example.json` |
| Microsoft's benign malware demo URL | `result.$type=warn`, category `Malicious` | `client_url_demo.json` |
| Lab Microsoft `smartscreen.exe`, with example.com source context | `rating=allow` | `client_file_example_origin.json` |
| SHA-256 of a harmless text fixture, represented as `benign-probe.exe`, same source URL | `rating=unknown` | `client_file_unknown.json` |
| Dataset discovery | Four advertised data actions plus a ping action | `client_lists.json` |
| Download pre-check, example.com / benign Microsoft demo | `allow / Allowed` and `warn / Malicious` | `api_expansion/validation_summary.json` |
| Shell query, Microsoft binary / harmless fixture metadata | `allow / Allowed / ALLW:100` and `block / Untrusted / UNKN:100` | `api_expansion/validation_summary.json` |

The unknown fixture was the UTF-8 bytes `SmartScreen harmless research fixture. Not executable.\n` (55 bytes), SHA-256 `b62733c4b6ce27c4af3f34c8f1a7338c61405d82ce64b53ca2f6a29405e5bab9`. No executable was run for these tests.

Downloaded data for the tested client profile:

| Dataset | Result | Decoding status |
|---|---|---|
| `topTraffic` | 460,992 bytes; 28,812 distinct, sorted 16-byte records | First 16 bytes of SHA-256 over UTF-16LE candidate text; exact-key lookup, supported ASCII URL lookup, and hex export |
| `synchronousLookupUris` | 57-byte `murmur3` filter | Seed 10, 13 hash probes, 231 bits, least-significant-bit-first indexing; exact-key membership implemented and native hash validated; offset 24 remains unnamed |
| `edgeSettings`, format 2 | 130,578-byte JSON document | Model with 981 hashed token weights, title delimiters and length weight, plus geography maps and sampling settings; full JSON, token lookup and UTF-8 title scoring supported |
| `edgeSettings`, format 1 | 41,796-byte JSON document | Older `scamTitle` model with 387 weighted features; readable, but its token-hash/scoring semantics remain unverified |
| `customSynchronousLookupUris` | Historical nonzero advertisement and current native version 0; tested GET/POST return HTTP 304 without body | Native fallback filter extracted separately from DLL; no current custom-feed body obtained |
| `customSettings` | 63-byte HTTP/200 JSON, ETag `3FA91A37E06EB3DAD5B57925CFD0BDB0` | `forceServiceDetermination=false`, empty `inScopeProcessPatterns`; native-baseline retry and subsequent 304 cache reuse verified; configuration, not a URL list |

Feed versions affect discovery **and format selection**. `lists` now defaults `edgeSettings` to `2.0-0` to request the validated richer format, and other unspecified versions to `0`. Explicit `identity.client.data` versions are preserved. Reporting settings version `0` selects the older format even with the newer protocol-client version. Downloads send native full-body `Accept: application/octet-stream;` and a quoted `If-None-Match` dataset version.

An earlier discovery control omitted custom Bloom at version zero; the historical version `3155378975999999999-0` caused the server to advertise its `bloomfilter/e5/3` action. That sentinel is a probe input, not the current Edge initial default: the later native capture explicitly uses `0`. [examples/identity_custom_feeds.json](../examples/identity_custom_feeds.json) retains the earlier discovery control plus settings format 2:

```sh
python3 smartscreen.py --identity examples/identity_custom_feeds.json -o discovery.json lists --download ./feeds_custom
```

The earlier five-feed run downloaded three bodies and received 304 for both custom feeds. The later native-baseline fix retrieves remote custom settings; custom Bloom remains unavailable. The example identity above explicitly supplies versions, so the client preserves them rather than applying the implicit-version retry. Earlier evidence is in `analysis/custom_feeds/findings.json`; the resolved settings behavior is in `analysis/custom_feed_expansion/findings.json`. Other profiles and service revisions can differ.

Each downloaded snapshot also has `manifest.json` with collection time, client version, HTTP status, and file summaries. Use separate directories for snapshots you want to compare. `compare-feeds` reports record additions/removals, duplicate-count changes, model/feature-weight changes, compatible Bloom bit changes, and mismatches between response hashes and saved bodies. Model/weight ordering and JSON whitespace are distinguished from semantic changes. Detail arrays are bounded by `--limit`, with total counts retained. A missing HTTP 304 body stays uncomparable.

The exact-key top-traffic operation was independently checked against the saved feed using `www.google.com` and `www.example.com`. It hashes exactly the supplied text, without adding a scheme, changing case, or generating native URL candidates. A match is list membership only, not an overall reputation verdict. See `analysis/feed_expansion/verified_semantics.json` for native function references and evidence.

The Bloom operation uses MurmurHash3 x64-128 over UTF-16LE, uint64-wrapped double hashing, and LSB-first bit access. The original DLL's ARM64 hash instructions matched Python on **264 cases**, covering every tail length, multiple blocks, several seeds, and Unicode inputs. `example.com` and `demo.smartscreen.msft.net` are positive exact keys in the saved public filter. Bloom positives can be false positives; neither hashed records nor Bloom bits can be decoded into a complete plaintext URL list. Evidence: `analysis/feed_expansion/native_murmur_validation.json`; repeat the native comparison with `python3 tools/validate_native_murmur.py --ghidra /path/to/ghidra` when Ghidra and its analyzed project are available.

`inspect-data --url` now supports serialized HTTP(S) URLs with recursive percent escapes, component escaping, credentials, ports, short/decimal/octal/hex IPv4, IPv6, punycode and encoded UTF-8. **All 482 supported cases matched** the native parser's canonical text and candidate sequence. The recovered order of authority decoding, credential removal, path cleanup and query/fragment handling is preserved. Raw Unicode, IPv6 zones and malformed/native fallback cases remain explicit rejections. `--key` accepts exact candidate strings. Evidence and precise exclusions: `analysis/feed_expansion/uri_normalization_followup.json`.

The raw-Unicode boundary is now explained: the matching Edge browser passes `GURL::spec()` into its SmartScreen client. Chromium's [GURL contract](https://raw.githubusercontent.com/chromium/chromium/main/url/gurl.h) specifies an ASCII serialized URL, using escaped UTF-8 for non-ASCII components. The verified six-step Edge call chain is in `analysis/feed_expansion/edge_url_input_contract.json`. Supply browser-serialized punycode/percent-encoded URLs to the offline tool. Direct Unicode truncation seen inside the standalone core does not describe normal Edge navigation; a separate Python implementation of Chromium's full IDNA/UTS46 preprocessing has not been added.

The Bloom header's offset-24 field remains named `unknown_u32_at_24`. Original native instructions were exercised through **16 loader cases and 48 membership calls**, varying that field to its original value, zero, one and `0xffffffff`. Validation and membership stayed unchanged; all-zero/all-one bit controls changed membership as expected. The field fits a producer-side item/capacity-count formula, but the public PDB contains no member type information and the producer is unavailable, so that interpretation remains an inference. See `analysis/bloom_header/findings.json`.

For format-2 model terms, MD5 hashes of UTF-8 bytes with ASCII-only lowercase match the native default-locale helper; downloaded examples include `microsoft`, `windows`, and `welcome`. `inspect-model --token` reports the candidate hash and matching weights. `--full` exports all model data and the original decoded JSON, including unknown fields. The older format-1 feature pipeline is not assumed equivalent.

## Offline title scoring

`score-title` evaluates the native format-2 **UTF-8 title-only** model and explains bias, token matches, duplicate handling, byte-length and optional logarithmic-length contributions:

```sh
python3 smartscreen.py score-title ./feeds/edgeSettings.bin "Microsoft documentation"
```

The default is distinct token hashes; an explicit `useDistinctTokens:false` counts repetitions. The tokenizer emits empty tokens for leading/consecutive ASCII delimiters and omits an empty final tail. It lowercases ASCII bytes only, measures UTF-8 byte length, and performs no Unicode casefold or normalization. NBSP and EM SPACE are not ASCII delimiters; combining characters and emoji retain their original bytes. Log-length buckets count ASCII alphabetic bytes, take the natural logarithm, round to nearest with ties away from zero, add one, and cap to the final weight index. Unsupported legacy models, non-title feature terms, invalid surrogate text, duplicate weight keys, and non-finite arithmetic are rejected. The local title size bound is 16,384 bytes; this is a tool resource limit, not a claim about Edge's limit. Nondefault native C-runtime locales remain unvalidated.

The evaluator was recovered from the matching **Edge 158.0.4370.33 ARM64** binary; the collected standalone Windows DLL's evaluator was a stub. All **49 benign native-emulation cases** matched Python's exact binary64 score and token sequence, including six controls using the downloaded model. Original scoring/tokenization/log instructions ran under Ghidra with explicit standard-library shims. One Ghidra `FRINTA` instruction bug required a workaround; the correct rounding behavior was independently checked by executing that exact ARM64 opcode on the host CPU in **27 cases**. Evidence: `analysis/model_expansion/native_scores.json`, `score_cases.json`, `frinta_native_probe.json`, and the saved Edge function extracts.

The consolidated scoring evidence and emulator caveats are in `analysis/model_expansion/scoring_findings.md` and `score_parity.json`.

Additional default-locale checks cover all 256 sign-extended native byte inputs and 20 Unicode model cases. Six actual Edge page controls covered accented capitals, dotted/dotless I, emoji, combining marks, NBSP and EM SPACE. All six titles were preserved exactly, and all seven captured follow-up scores (one duplicate) equaled Python exactly. All seven follow-ups returned HTTP 200 `allow / Allowed`. This closes the earlier Unicode gap for the tested title path. Reports: `analysis/model_completion/browser_comparison.json`, `browser_documents.json` and `findings.json`.

Legacy v1 models remain inspection-only: both investigated native term evaluators reject their missing `terms` with `MalformedModel::MissingTerms`. Applying the v2 grammar would fabricate compatibility; the separate legacy feature evaluator has not been recovered.

`raw_score_positive` means strictly `raw_score > 0`, a native selection condition. Nonpositive results can also be selected through sampling, which this deterministic scorer does not run. A score is not a probability, a cloud reputation verdict, or proof that Edge would block a page. The benign control title `Microsoft documentation` scores `1.2496318738819348`; the tool preserves that result without labeling the page malicious.

## Native defaults

The collected DLL also contains a **35,302-byte fallback Bloom filter**, shared by the public/custom filter initializers, plus default custom settings `{"forceService":false}`. These are useful readable artifacts even when the service returns 304, but their provenance is the specific DLL snapshot, not a fresh server download.

```sh
python3 -m smartscreen.defaults artifacts/smartscreen.dll --output ./native_defaults
python3 smartscreen.py inspect-data ./native_defaults/builtin_customSynchronousLookupUris.bin --key example.com
```

The extractor verifies the known DLL fingerprint and PE section mapping. The fallback header contains 282,185 bits, seed 10, and 13 probes. It preserves the unnamed header field at offset 24 rather than assuming its meaning. Extraction metadata records source offsets and hashes. These files remain separate from downloaded snapshots.

## Matching plaintext candidates to hashes

`map-candidates` performs local exact hash comparisons against supplied word/domain lists. It reports matched and unmatched hash counts, source digests, and candidate associations. It accepts multiple input files; `--max-candidates` bounds their combined input count. Bloom filters are excluded from this mapping operation because their positives cannot enumerate exact stored records.

```sh
python3 smartscreen.py -o domain_matches.json map-candidates ./feeds/topTraffic.bin domains.txt --kind topTraffic --domain-variants
python3 smartscreen.py -o token_matches.json map-candidates ./feeds/edgeSettings.bin words.txt --kind model
```

For `rank,domain` CSV input, add `--input-format ranked-domains`. Without `--domain-variants`, topTraffic candidates are tested literally; with it, lowercase bare and `www.` hostname forms are tried. Model candidates use UTF-8 bytes with the verified ASCII-only lowercase rule. Non-supported candidate forms are counted explicitly.

The recorded experiment combined three public Tranco snapshots: [8PW6V](https://tranco-list.eu/list/8PW6V), [569WN with subdomains](https://tranco-list.eu/list/569WN), and [JXQWY from 2022-10-03](https://tranco-list.eu/list/JXQWY). It matched **20,609 of 28,812 topTraffic hashes (71.5%)**. A local dictionary matched **449 of 981 model token hashes**. No candidate domain was visited. Tranco attribution: Le Pochat et al., *Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation*, NDSS 2019, [doi:10.14722/ndss.2019.23386](https://doi.org/10.14722/ndss.2019.23386).

Mappings and provenance are in `analysis/candidate_mapping/`; `toptraffic_candidate_hosts.txt` is the readable partial host list. These associations do not prove unique original plaintexts, and the output is not a blocked-URL list. Unmatched records and current cloud reputation remain unknown.

## Batch queries and history

```sh
python3 smartscreen.py -o results.jsonl batch examples/jobs.jsonl --history history.sqlite3
python3 smartscreen.py history history.sqlite3 --limit 20
python3 smartscreen.py -o earlier_results.json history history.sqlite3 --query-key QUERY_SHA256
```

Input is one JSON object per line. [examples/jobs.jsonl](../examples/jobs.jsonl) contains benign URL, download, browser-hash, and shell-hash controls. File paths are relative to the JSONL file's directory. Supported forms include:

```jsonl
{"type":"url","url":"https://example.com/"}
{"type":"download","url":"https://example.com/sample.exe"}
{"type":"file","path":"sample.exe","source":"https://example.com/sample.exe","surface":"shell"}
```

`hash` jobs additionally require `sha256`, `size`, `name`, and `source`. File/hash `surface` defaults to `browser`; `shell` selects `beforeExecute/2`. Jobs can include an `id`, `referrer`, and `identity` override. Unknown fields are rejected to catch misspellings before querying.

The entire bounded input is validated before requests start. By default, at most 100 jobs are accepted, with one second between requests (`--max-jobs`, `--delay`). Results are flushed as JSONL and committed individually to SQLite. HTTP 429/503 stops the remaining queries and records them as not run, including `Retry-After`; there are no automatic retries. Exit status is nonzero for failed, inconclusive, or unqueried items. An explicit `unknown` reputation is a successful query result.

History stores full response records and exact raw response bytes. Request credential fields are redacted with digests. Query identities include endpoint, target metadata, effective profile, and authentication profile; random correlation IDs and job labels are excluded. Each record shows the previous observation, the previous successful explicit verdict, and verdict/category changes. A transport error does not replace the last known verdict. Ordinary one-off commands return JSON; batch commands add persistent history.

The integrated live example batch completed all four jobs, and a repeated URL query correctly linked to its prior unchanged verdict. Evidence is under `analysis/integration_expansion/`. Later feed/model evidence is under `analysis/decoder_integration/`, `analysis/custom_feeds/`, and `analysis/model_expansion/`.

## Authentication evidence

Collected file: `artifacts/smartscreen.dll`, version `1.0.0.79`, SHA-256 `561e2abcd612a85ce3ae2be9fc978fd2809614120154350fbb02bdc19783204c`.

Headless Ghidra analysis identified these functions (preferred image base `0x180000000`):

| Address | Observed role |
|---|---|
| `0x1800a7390` | Serializes `SmartScreenHash` / `SmartScreenPlain` Authorization values |
| `0x1800a5348` | Combines a 16-byte MD5 result and an eight-byte CS64MAC result |
| `0x180014258` | Constructs the MD5 hashing implementation |
| `0x1800a37b8` | Constructs the `CS64MAC` implementation |
| `0x1800a07d0` | XORs the WordSwap and Reversible results |
| `0x1800a47c0` | CS64 WordSwap chain |
| `0x1800a45d8` | CS64 Reversible chain |

The Python implementation matches both header components from the original, independently captured 1,359-byte download request. CS64 consumes complete eight-byte blocks; MD5 covers the entire serialized body. The header's `key` is body-derived, not an account secret. These observations support protocol interoperability, not a claim of an authentication vulnerability.

Supporting files: `analysis/auth_functions.json`, `hash_constructors.json`, `cs64mac.json`, `cs64_algorithms.json`, `cs64_constants.json`, and `smartscreen.dll.surface.json`. Reusable headless extraction scripts are Python files under `tools/ghidra/`. `tools/binary_strings.py` extracts offset-tagged ASCII and UTF-16 strings.

## Coverage and remaining useful work

This is a tested research client, not a complete reconstruction of SmartScreen. Automated tests validate supported behavior and specific native comparisons; they do not establish exhaustive API, client-build, policy or server-side coverage.

| Area | Implemented | Material gap |
|---|---|---|
| Online reputation and enforcement | Sync/async and page-model queries; native navigation/download/shell warnings; matching anonymous replays; embedded/catalog/SIP publisher metadata; legacy package query | Broader policy/cache/build coverage, complete native shell context, current installer wire parity and package enforcement |
| Downloaded data and caches | Acquired top-traffic/Bloom/settings formats, remote custom settings, native caches, conditional updates, membership and comparisons | Current remote custom Bloom body remains unavailable; local hashes/filters are not a complete plaintext global blocklist |
| Local models | V2 UTF-8 title scoring with six live browser controls; extracted B32 visual model, vectors, scores and saved image controls; traced L14 local-load branch | Legacy v1 and non-title features, authenticated L14 assets, other native locales, effective browser feature state and complete capture/runtime parity |
| API coverage | Tested core routes, native `postnav`, bounded package validation, GET authentication/conditional headers, captured redirect/TLS context, protocol/context inspector | Unobserved redirect variants, opaque rating/context numeric semantics, final scareware reporting route and consent/policy gates |
| Integrity and compatibility | Versioned reader evidence and pinned signatures for visual assets | Updater CUP response verification and coverage across additional current builds/architectures |

The five follow-up areas were investigated: native download/shell enforcement, catalog/non-PE/package metadata, current custom Bloom acquisition, remaining protocol surfaces, and model compatibility. Implemented paths have saved controls; unavailable assets and unobserved behavior remain explicit. The next useful external inputs are a successful custom-Bloom capture from an authorized configured device, authenticated L14 assets, and additional builds/policy states. Further RE could target the legacy evaluator, updater CUP verification and final scareware-reporting interface. The operationally unused Bloom header field remains unnamed. Neither client RE nor these local datasets exposes Microsoft's full cloud decision rules, reputation history or global URL database. MAPS remains outside this pass. Current evidence: `analysis/enforcement_expansion/`, `analysis/signature_catalog_expansion/`, `analysis/protocol_expansion/` and `analysis/model_completion/`.

## Relationship to your GitHub research

The review covered 39 accessible HackingLZ repositories, searches of their default-branch contents, and a SmartScreen issue search. It did not establish absence across every historic branch, gist, or inaccessible repository.

- [maps_scanner](https://github.com/HackingLZ/maps_scanner) implements Defender MAPS/Bond reporting and cloud response parsing. Its `SMART_SCREEN=480` / `"Warn"` field is MAPS report metadata. The reviewed implementation did not provide these Edge JSON reputation and dataset APIs.
- [defender_overview](https://github.com/HackingLZ/defender_overview) documents the Defender engine, MAPS, and verdict-resolution pipeline. It is useful background for the separate SmartScreen HTTP surface.
- `maps_scanner`'s response interpreter sets `clean=True` when no malicious result or sample request is found. Its saved EICAR hash-only result illustrates why that label should not be carried into this client as proof of positive reputation. This is a tool-interpretation issue, not a demonstrated Microsoft defect. See [client.py](https://github.com/HackingLZ/maps_scanner/blob/main/client.py) and [live results](https://github.com/HackingLZ/maps_scanner/blob/main/docs/MAPS_LIVE_TEST_RESULTS.md).

A fresh source review on 2026-11-23 identified concrete reuse and limits:

- MAPS already defines URL determination, confidence and TTL fields, plus certificate-result structures. Its Bond codec and parser could support a separate comparison backend. The saved `example.com` response shows only generic revision/sample-rate metadata, however; it does not demonstrate an explicit `UrlResult`. Protocol declarations and HTTP/200 alone do not validate URL reputation semantics.
- MAPS file analysis supplies useful basic hashes, PE version data, import hashes and section hashes. Although its `FileInfo` declares a `signer` field, the inspected `analyze_file()` never populates it. The SmartScreen signature implementation added here instead uses its own recovered native schema and Windows comparisons. MAPS certificate fields cannot be copied directly into this different JSON protocol.
- The Defender [MAPS](https://github.com/HackingLZ/defender_overview/blob/main/md/12_maps_cloud_lookup.md) and [verdict-resolution](https://github.com/HackingLZ/defender_overview/blob/main/md/13_verdict_resolution.md) writeups offer hypotheses and instrumentation leads for cloud requests, policy, cache state and final actions. Their addresses target an older x86 `mpengine.dll`; they must be checked against the component/build being studied here.
- The additional [SigTree model](https://github.com/HackingLZ/defender_overview/blob/main/md/14_sigtree_ml_model.md) and [standalone work log](https://github.com/HackingLZ/defender_overview/blob/main/md/15_sigtree_standalone.md) describe separate Defender VDM/attribute-tree work, with incomplete feature mapping and evaluation explicitly documented. They offer a useful native-feature validation approach, but no demonstrated replacement for SmartScreen URL feeds or the extracted visual model.

The audited file paths and GitHub blob hashes are recorded in `analysis/coverage_audit/findings.json`. This comparison added documentation; it did not merge MAPS protocol code, alter your GitHub repositories, or submit new cloud reports.

Public prior art already includes SmartScreen data/settings/Bloom-filter endpoints in [Trinity College Dublin's browser-privacy supplementary material](https://www.scss.tcd.ie/doug.leith/pubs/additional_material.pdf), and native file-trust queries in [Elastic's reputation research](https://github.com/joe-desimone/rep-research/blob/main/rep-check/rep-check.cpp). The client and saved live evidence here extend your reviewed repositories; this work has not established a novel vulnerability.

## Tests and other files

The complete suite passed **368 tests with no failures or skips** on Python **3.12.7**. It includes image acquisition/inference, native HTTP/2 reconstruction, captured request schemas, embedded/catalog/SIP extraction, package footprint/CLI behavior, conditional GET headers, protocol inspection, Unicode browser score controls, feed retries and output preservation. The package/CLI checks also passed on Python 3.9.6; earlier navigation/feed/parser checks passed there too. Image inference runs on macOS ARM64 with ONNX Runtime **1.32.0**, NumPy **2.5.5**, Pillow **13.0.0** and the CPU provider. Both saved image controls remain part of validation. Earlier image evidence is in `analysis/scareware/test_validation.json` and `analysis/scareware/fixture_validation.json`; this pass’s full test log and summary are in `analysis/completion_pass/test_validation.json` and `test_validation.log`.

The earlier API/feed suite passed 229 tests, with no skips, on Python 3.9 and Python 3.15. Its live controls, actual lab files, current-SDK feeds and successful cached-body revalidation are verified by `analysis/current_lab/verify_expansion.py`, with results in `analysis/current_lab/expansion_verification.json`. Cache reader and decision-path evidence is in `analysis/cache_expansion/` and `analysis/decision_expansion/`. Earlier feed/model/hash controls remain documented in `analysis/decoder_integration/verification_summary.json` and `analysis/candidate_mapping/verification_summary.json`.

```sh
.venv-vision/bin/python -m unittest discover -s tests -t . -v
.venv-vision/bin/python tools/validate_vision.py --assets models/scareware --require-baseline
# Optional historical native harnesses require the ignored local research archive.
```

Without optional vision dependencies or locally acquired analysis artifacts, related integration/native-evidence tests may skip; the core API/feed tools still run with the standard library. The independent-capture authentication test reads the original local endpoint note if present and otherwise skips. It does not transmit the captured ticket. `smartscreen/audit.py` is an optional offline HAR reviewer. `tools/lab.py` collects Windows inventory or explicit analysis files over verified SSH; `--password` prompts and uses sshpass. Original captures and inventory are retained only in ignored `local/private/` storage and are not distributed.
