#!/usr/bin/env python3
"""Extract offset-tagged ASCII/UTF-16 strings from analysis files."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def extract(path, pattern=None):
    raw = path.read_bytes()
    matches = []
    for encoding, regex in [('ascii', rb'[\x20-\x7e]{5,}'),
                            ('utf-16le', rb'(?:[\x20-\x7e]\x00){5,}')]:
        for match in re.finditer(regex, raw):
            value = match.group().decode(encoding)
            if pattern is None or re.search(pattern, value, re.I):
                matches.append({'offset': hex(match.start()), 'encoding': encoding, 'value': value})
    return {'file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
            'strings': sorted(matches, key=lambda item: int(item['offset'], 16))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--match')
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(extract(args.file, args.match), indent=2) + '\n'
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end='')
