#!/usr/bin/env python3
"""Check exact staged Git blobs for private data without printing matched values.

This local check is intentionally bounded; it is not exhaustive secret detection.
Use --private-rules with an ignored JSON array of additional private strings.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {'.gitignore', '.gitattributes', 'README.md', 'smartscreen.py',
              'requirements-signatures.txt', 'requirements-vision.txt', 'LICENSE', 'LICENSE.md'}
ROOT_DIRS = {'smartscreen', 'tests', 'tools', 'examples', 'docs'}
PRIVATE_DIRS = {'local', 'analysis', 'artifacts', 'models', 'captures', '.ssh', '.aws', '__pycache__'}
FIXTURE_EXE = 'tests/fixtures/enforcement/smartscreen-benign-exit73-arm64.exe'
FIXTURE_HASH = 'c7468594ebb904070d170f041a848d3ca5d51c42f58eabb84d544be8700bbf7d'
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'aws-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'slack-token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'unix-home-path': re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+(?:/|\b)'),
    'windows-user-path': re.compile(r'[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|Default\b)[A-Za-z0-9_.-]+', re.I),
    'captured-smartscreen-auth': re.compile(r'SmartScreen(?:Hash|Plain) [A-Za-z0-9+/=]{40,}'),
    'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b'),
}
TOKEN_FIELDS = {'onlineidticket', 'accesstoken', 'refreshtoken', 'clientsecret', 'password', 'authorization', 'cookie', 'setcookie'}
SAFE_VALUES = {'', 'redacted', '[redacted]', '<redacted>', 'synthetic', 'test', 'secret', 'ticket', 'dummy', 'fixture'}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def text_findings(text, private_literals=(), depth=0):
    findings = []
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({'rule': rule, 'line': text.count('\n', 0, match.start()) + 1})
    for index, literal in enumerate(private_literals):
        if literal and literal.casefold() in text.casefold():
            findings.append({'rule': 'private-literal-' + str(index + 1)})
    if depth < 2:
        for match in re.finditer(r'(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{24,}={0,2}(?![A-Za-z0-9_+/=-])', text):
            value = match.group()
            if len(value) > 1024 * 1024:
                continue
            try:
                decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                continue
            if decoded != value and any(c.isalpha() for c in decoded):
                for row in text_findings(decoded, private_literals, depth + 1):
                    findings.append({'rule': 'encoded-' + row['rule'], 'line': text.count('\n', 0, match.start()) + 1})
    return findings


def json_findings(value, path='$'):
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r'[^a-z]', '', key.lower())
            if path.endswith('.device') and normalized in {'id', 'customid'} and item:
                result.append({'rule': 'nonempty-device-identifier', 'json_path': path + '.' + key})
            if normalized in TOKEN_FIELDS and item is not None and item is not False:
                if not isinstance(item, str) or item.lower() not in SAFE_VALUES:
                    result.append({'rule': 'nonempty-credential-field', 'json_path': path + '.' + key})
            result.extend(json_findings(item, path + '.' + key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            result.extend(json_findings(item, path + '[' + str(i) + ']'))
    return result


def inspect_blob(path, mode, data, private_literals=()):
    rows = []
    relative = PurePosixPath(path)
    if relative.parts[0] not in ROOT_DIRS and path not in ROOT_FILES:
        rows.append({'rule': 'unexpected-project-path'})
    if (any(part in PRIVATE_DIRS or part.startswith('.venv') for part in relative.parts)
            or relative.name in {'.DS_Store', 'Thumbs.db', 'Desktop.ini'}
            or relative.name.startswith(('.env', '._', 'id_rsa', 'id_ed25519', 'credentials', 'secrets', 'known_hosts'))
            or relative.suffix.lower() in {'.har', '.pcap', '.pcapng', '.pem', '.key', '.pfx', '.p12', '.sqlite', '.sqlite3', '.db', '.log', '.pyc'}):
        rows.append({'rule': 'private-or-generated-artifact'})
    if mode not in ('100644', '100755'):
        return rows + [{'rule': 'symlink-or-nonregular-index-entry'}]
    if len(data) > 5 * 1024 * 1024:
        rows.append({'rule': 'oversized-file'})
    if path == FIXTURE_EXE:
        if hashlib.sha256(data).hexdigest() != FIXTURE_HASH:
            rows.append({'rule': 'executable-fixture-hash-mismatch'})
        return rows
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        if not path.startswith('tests/fixtures/vision/'):
            rows.append({'rule': 'unexpected-image'})
        offset = 8
        while offset + 12 <= len(data):
            size = struct.unpack_from('>I', data, offset)[0]
            kind = data[offset + 4:offset + 8]
            if size > len(data) - offset - 12:
                rows.append({'rule': 'malformed-png'})
                break
            if kind in (b'tEXt', b'zTXt', b'iTXt', b'eXIf'):
                rows.append({'rule': 'image-text-or-exif-metadata'})
            offset += 12 + size
        return rows
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        return rows + [{'rule': 'unreviewed-binary'}]
    if '\0' in text:
        rows.append({'rule': 'binary-nul-in-text'})
    rows += text_findings(text, private_literals)
    if relative.suffix in {'.json', '.jsonl'}:
        documents = [text] if relative.suffix == '.json' else [line for line in text.splitlines() if line.strip()]
        for document in documents:
            try:
                decoded = json.loads(document)
                rows += json_findings(decoded)
                # Decode JSON escapes as well as base64 wrappers before checking
                # private literals and path/token signatures.
                rows += text_findings(json.dumps(decoded, ensure_ascii=False), private_literals)
            except ValueError:
                rows.append({'rule': 'invalid-json'})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-rules', type=Path, help='Ignored JSON array of additional literal strings to reject')
    parser.add_argument('--output', type=Path, help='Optional report in an ignored local directory')
    args = parser.parse_args()
    literals = json.loads(args.private_rules.read_text()) if args.private_rules else []
    if not isinstance(literals, list) or not all(isinstance(x, str) and x for x in literals):
        parser.error('Private rules must be a JSON array of nonempty strings')
    findings, files, total = [], [], 0
    for record in git('ls-files', '--stage', '-z').split(b'\0'):
        if not record:
            continue
        info, raw_path = record.split(b'\t', 1)
        mode, oid, stage = info.decode().split()
        path = raw_path.decode('utf-8')
        data = git('cat-file', 'blob', oid)
        rows = inspect_blob(path, mode, data, literals)
        if stage != '0':
            rows.append({'rule': 'unmerged-index-entry'})
        findings += [dict(row, file=path) for row in rows]
        files.append({'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        total += len(data)
    report = {'scope': 'Exact staged Git blobs; ignored local research files are excluded', 'files_checked': len(files),
              'bytes_checked': total, 'passed': bool(files) and not findings, 'findings': findings, 'files': files,
              'limits': 'Pattern, JSON credential, image metadata and binary checks are not exhaustive secret detection.'}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
