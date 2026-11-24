#!/usr/bin/env python3
"""Generate a deterministic, unsigned ARM64 PE that only calls ExitProcess(73).

There are exactly three ARM64 instructions and one imported function. There are
no file, network, registry, child-process, persistence, or payload-loading actions.
The generator is Python stdlib only and has no configurable program behavior.
"""
import hashlib
import json
from pathlib import Path
import struct


BASE = Path(__file__).resolve().parent
NAME = 'smartscreen-benign-exit73-arm64.exe'
EXIT_CODE = 73


def build():
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    # ARM64, three sections, timestamp=0, no symbols, PE32+ header, executable/LAA.
    struct.pack_into('<HHIIIHH', data, 0x84, 0xaa64, 3, 0, 0, 0, 0xf0, 0x22)
    optional = 0x98
    struct.pack_into('<HBBIIIII', data, optional, 0x20b, 0, 0, 0x200, 0x400, 0, 0x1000, 0x1000)
    struct.pack_into('<QII', data, optional + 24, 0x140000000, 0x1000, 0x200)
    # OS10.0, image1.0, subsystem6.2, reserved zero.
    struct.pack_into('<HHHHHHI', data, optional + 40, 10, 0, 1, 0, 6, 2, 0)
    # Three mapped pages plus headers, CUI; high-entropy ASLR, dynamic-base, DEP.
    struct.pack_into('<IIIHH', data, optional + 56, 0x4000, 0x200, 0, 3, 0x160)
    struct.pack_into('<QQQQII', data, optional + 72, 0x100000, 0x10000, 0x100000, 0x10000, 0, 16)
    directories = optional + 112
    struct.pack_into('<II', data, directories + 1 * 8, 0x2000, 40)   # Imports.
    struct.pack_into('<II', data, directories + 5 * 8, 0x3000, 12)   # Base-relocation padding block.
    struct.pack_into('<II', data, directories + 12 * 8, 0x2080, 16)  # IAT.
    section_table = optional + 0xf0
    for index, (name, virtual_size, rva, offset, flags) in enumerate([
            (b'.text', 12, 0x1000, 0x200, 0x60000020),
            (b'.idata', 0xa0, 0x2000, 0x400, 0xc0000040),
            (b'.reloc', 12, 0x3000, 0x600, 0x42000040)]):
        struct.pack_into('<8sIIIIIIHHI', data, section_table + index * 40,
                         name, virtual_size, rva, 0x200, offset, 0, 0, 0, 0, flags)
    # MOV W0,#73: first Windows ARM64 integer argument = fixed exit code.
    # LDR X16,PC+0x107c: load the loader-resolved ExitProcess pointer from IAT.
    # BR X16: tail-call the sole imported function; it does not return.
    instructions = [0x52800000 | (EXIT_CODE << 5),
                    0x58000010 | (((0x2080 - 0x1004) // 4) << 5),
                    0xd61f0200]
    struct.pack_into('<III', data, 0x200, *instructions)
    struct.pack_into('<IIIII', data, 0x400, 0x2040, 0, 0, 0x2060, 0x2080)
    struct.pack_into('<QQ', data, 0x440, 0x2090, 0)
    data[0x460:0x46d] = b'KERNEL32.dll\0'
    struct.pack_into('<QQ', data, 0x480, 0x2090, 0)
    data[0x490:0x49e] = b'\0\0ExitProcess\0'
    # IMAGE_REL_BASED_ABSOLUTE entries are padding. All code addresses are PC
    # relative; imports contain RVAs, so no absolute image addresses need fixing.
    struct.pack_into('<IIHH', data, 0x600, 0x1000, 12, 0, 0)
    assert len(data) == 0x800
    return bytes(data)


def main():
    raw = build()
    path = BASE / NAME
    path.write_bytes(raw)
    manifest = {
        'file': NAME, 'format': 'PE32+', 'architecture': 'ARM64', 'machine': '0xaa64',
        'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'authenticode_signature': 'absent', 'timestamp': 0,
        'entry_point_rva': '0x1000', 'expected_exit_code': EXIT_CODE,
        'instructions': [
            {'rva': '0x1000', 'word': '0x52800920', 'assembly': 'mov w0, #73'},
            {'rva': '0x1004', 'word': '0x580083f0', 'assembly': 'ldr x16, [pc, #0x107c] ; IAT RVA0x2080'},
            {'rva': '0x1008', 'word': '0xd61f0200', 'assembly': 'br x16 ; KERNEL32!ExitProcess'}],
        'imports': [{'dll': 'KERNEL32.dll', 'name': 'ExitProcess'}],
        'behavior': 'Terminate this process with exit code73. No other application behavior.',
        'source': Path(__file__).name,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'reproducibility': 'No build timestamps, randomness, external compiler, or embedded mutable content.',
        'references': ['https://learn.microsoft.com/en-us/windows/win32/debug/pe-format',
                       'https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess'],
        'validation': 'Direct Windows process execution recorded separately in lab_validation.json.'}
    (BASE / 'fixture_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'path': str(path), 'sha256': manifest['sha256'], 'size': len(raw)}))


if __name__ == '__main__':
    main()
