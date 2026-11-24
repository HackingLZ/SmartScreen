#!/usr/bin/env python3
"""Validate Python hashing against the DLL's ARM64 instructions in Ghidra.

Uses the existing analyzed project read-only, without Windows imports or network
access. Ghidra and Java are research dependencies, not client dependencies.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import subprocess
import tempfile

DLL_SHA256 = '561e2abcd612a85ce3ae2be9fc978fd2809614120154350fbb02bdc19783204c'
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True, help="Ghidra installation directory")
    parser.add_argument('--java', default='java')
    parser.add_argument('--output', type=Path, default=ROOT / 'analysis/feed_expansion/native_murmur_validation.json')
    args = parser.parse_args()
    from smartscreen.data import murmur3_x64_128
    binary = ROOT / 'artifacts/smartscreen.dll'
    if hashlib.sha256(binary.read_bytes()).hexdigest() != DLL_SHA256:
        raise ValueError('This harness only supports the fingerprinted lab DLL')
    inputs = [bytes((i * 73 + 19) & 255 for i in range(length)) for length in range(80)]
    inputs += [text.encode('utf-16le') for text in (
        'example.com', 'demo.smartscreen.msft.net', 'www.google.com', 'www.example.com',
        'https://example.com/a?b=c', 'xn--bcher-kva.example', 'Bücher.example', '😀.example')]
    cases = [{'input_hex': data.hex(), 'seed': seed,
              'python_digest_hex': murmur3_x64_128(data, seed).hex()}
             for data in inputs for seed in (0, 10, 0xFFFFFFFF)]
    document = {'binary_sha256': DLL_SHA256, 'native_function': '0x1800149d8',
                'scope': 'Hash primitive only; URL preparation and Windows enforcement are outside this test',
                'cases': cases}
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    vectors = args.output.with_name('native_murmur_inputs.json')
    vectors.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    with tempfile.TemporaryDirectory(prefix='native-murmur-', dir=args.output.parent) as temporary:
        pending = Path(temporary) / 'result.json'
        subprocess.run([
        args.java, '-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Djava.awt.headless=true',
        '-Dapplication.settingsdir=' + str(ROOT / 'analysis/native_ghidra_settings'),
        '-Dapplication.cachedir=' + str(ROOT / 'analysis/native_ghidra_cache'), '-Xmx2G',
        '-cp', str(args.ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar'),
        'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
        str(ROOT / 'analysis'), 'smartscreen', '-process', 'smartscreen.dll', '-noanalysis', '-readOnly',
        '-scriptPath', str(ROOT / 'tools/ghidra'), '-postScript', 'ValidateNativeMurmur.py',
        str(vectors), str(pending)], check=True, cwd=ROOT, timeout=180)
        result = json.loads(pending.read_text(encoding='utf-8'))
        if result.get('case_count') != len(cases) or result.get('binary_sha256') != DLL_SHA256:
            raise RuntimeError('Native validation output does not match its input cases')
        pending.replace(args.output)
    print(json.dumps({k: v for k, v in result.items() if k != 'cases'}, indent=2))
    return int(result['mismatch_count'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
