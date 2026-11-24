"""Extract the identified native fallback filter; never label it a downloaded feed.

Offsets are specific to the lab DLL SHA-256 below. Other builds require a new RE
pass; this script deliberately refuses them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from smartscreen.data import inspect_data

EXPECTED_DLL_SHA256 = '561e2abcd612a85ce3ae2be9fc978fd2809614120154350fbb02bdc19783204c'
EXPECTED_FILTER_SHA256 = 'f2658b1c913a96e75b45e6adb464c8d796b34ac43baf1635aa32e16d1752971c'
FILTER_RVA = 0x31e1d0
FILTER_SIZE = 0x89e6


def section_offset(raw, rva, size):
    """Map an RVA span to actual file bytes, rejecting virtual-only memory."""
    if raw[:2] != b'MZ':
        raise ValueError('Expected a PE image')
    pe = struct.unpack_from('<I', raw, 60)[0]
    if raw[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Expected the PE signature')
    count = struct.unpack_from('<H', raw, pe + 6)[0]
    optional_size = struct.unpack_from('<H', raw, pe + 20)[0]
    table = pe + 24 + optional_size
    for index in range(count):
        location = table + 40 * index
        name = raw[location:location + 8].split(b'\0', 1)[0].decode('ascii')
        virtual_size, address, raw_size, offset = struct.unpack_from('<IIII', raw, location + 8)
        relative = rva - address
        if 0 <= relative and relative + size <= raw_size:
            file_offset = offset + relative
            if file_offset + size > len(raw):
                raise ValueError('Section extends beyond the PE file')
            return name, file_offset
    raise ValueError('RVA span has no complete file-backed section')


def extract(binary, output):
    raw = Path(binary).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_DLL_SHA256:
        raise ValueError('Unrecognized DLL build; refusing to apply build-specific offsets')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    section, offset = section_offset(raw, FILTER_RVA, FILTER_SIZE)
    data = raw[offset:offset + FILTER_SIZE]
    if hashlib.sha256(data).hexdigest() != EXPECTED_FILTER_SHA256:
        raise ValueError('Identified builtin filter does not match its verified SHA-256')
    path = output / 'builtin_customSynchronousLookupUris.bin'
    path.write_bytes(data)
    decoded = inspect_data(data, 'customSynchronousLookupUris')
    if not decoded.get('filter', {}).get('valid'):
        raise ValueError('Native builtin filter failed the recovered header constraints')
    settings_path = output / 'builtin_customSettings.reconstructed.json'
    settings_path.write_bytes(b'{"forceService":false}')
    result = {
        'schema_version': 1,
        'source': {'file': str(binary), 'sha256': digest, 'version': '1.0.0.79'},
        'customSynchronousLookupUris': {
            'origin': 'Bytes extracted from the native DLL fallback buffer, not an HTTP response.',
            'body': str(path), 'rva': hex(FILTER_RVA), 'section': section,
            'file_offset': hex(offset), 'native_initial_version': '0',
            'summary': decoded,
            'evidence': ['analysis/custom_feeds/builtin_filter.json: FUN_1800b8eb0 defines start RVA, size, and end pointer.',
                         'analysis/custom_feeds/custom_filter_init.json: FUN_180097138 passes the builtin buffer and version 0.',
                         'analysis/custom_feeds/builtin_filter.json: FUN_180096ee8 passes bytes/version into the remote-data holder.'],
            'note': 'The same builtin buffer also initializes the public synchronous filter. Its bytes do not establish current server custom-feed contents or tenant policy.',
        },
        'customSettings': {
            'origin': 'JSON reconstructed from the native default constructor and serializer; not a file byte extraction or an HTTP response.',
            'body': str(settings_path), 'content': {'forceService': False},
            'native_initial_version': 'F95BA787499AB4FA9EFFF472CE383A14',
            'evidence': ['analysis/custom_feeds/custom_defaults.json: FUN_180032640 zero-initializes the settings object.',
                         'analysis/custom_feeds/custom_wire.json: FUN_1800356d0 serializes its boolean as forceService.',
                         'analysis/custom_feeds/custom_defaults.json: FUN_18002c570 supplies the builtin version to the customSettings holder.'],
            'note': 'The static settings value is from this DLL build. Server-side settings remain unavailable in the tested profile.',
        },
    }
    (output / 'builtin_report.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', help='Native DLL from the identified lab build')
    parser.add_argument('--output', required=True, help='Directory for extracted defaults and their provenance report')
    arguments = parser.parse_args(argv)
    try:
        result = extract(arguments.binary, arguments.output)
    except (OSError, ValueError, struct.error) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
