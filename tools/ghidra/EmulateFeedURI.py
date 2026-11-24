# Exercise native URI canonicalization and candidate iteration in p-code.
# Allocation/free are emulated; URI parsing and normalization execute DLL code.
# @category SmartScreen
import io
import json
import struct
from ghidra.app.emulator import EmulatorHelper
from jarray import array

args = getScriptArgs()
with io.open(args[0], 'r', encoding='utf-8') as source:
    cases = json.load(source)
emulator = EmulatorHelper(currentProgram)
stop = 0x40030000
allocations = {}
heap = [0x41000000]
prefetch_hints = set([0x180234690, 0x1802346f0, 0x180234714, 0x180234718,
                     0x180234748, 0x18023474c, 0x1802347e4, 0x180234850,
                     0x18023487c, 0x180234880, 0x1802348b8, 0x1802348bc])

def write(address, value):
    emulator.writeMemory(toAddr(address), array([x if x < 128 else x - 256 for x in bytearray(value)], 'b'))

def read(address, size):
    if not size:
        return bytearray()
    return bytearray((int(x) & 255) for x in emulator.readMemory(toAddr(address), size))

def integer(address):
    return struct.unpack('<Q', bytes(read(address, 8)))[0]

def call(address, values):
    for index, value in enumerate(values):
        emulator.writeRegister('x%d' % index, long(value))
    emulator.writeRegister('sp', long(0x4003f000))
    emulator.writeRegister('x30', long(stop))
    pc = address
    for event in range(256):
        ok = emulator.run(toAddr(pc), None, monitor)
        pc = emulator.getExecutionAddress().getOffset()
        if not ok:
            raise RuntimeError('At %x: %s' % (pc, emulator.getLastError()))
        if pc == stop:
            return long(emulator.readRegister('x0'))
        if pc in prefetch_hints:
            # ARM PRFM is a performance hint with no architectural result.
            pc += 4
            continue
        if pc == 0x18015bc70:
            old = long(emulator.readRegister('x0'))
            size = long(emulator.readRegister('x1'))
            if size < 0 or size > 0x100000:
                raise RuntimeError('Unexpected native allocation size %d' % size)
            result = heap[0]
            heap[0] += ((size + 0xff) & ~0xff) + 0x100
            write(result, b'\0' * max(1, size))
            if old:
                write(result, read(old, min(allocations.get(old, 0), size)))
            allocations[result] = size
            emulator.writeRegister('x0', long(result))
        elif pc != 0x18013d470:
            raise RuntimeError('Unexpected emulation stop %x' % pc)
        pc = long(emulator.readRegister('x30'))
    raise RuntimeError('Native call exceeded allocator-event limit')

results = []
try:
    for index in range(31):
        emulator.writeRegister('x%d' % index, long(0))
    write(0x40030000, b'\0' * 0x10000)
    for address in (stop, 0x18015bc70, 0x18013d470):
        emulator.setBreakpoint(toAddr(address))
    for address in prefetch_hints:
        emulator.setBreakpoint(toAddr(address))
    write(0x1803b9900, b'\0' * 0x900)
    for address in [0x180003c40, 0x180003c80, 0x180003cc0, 0x180003d00] + list(range(0x180003d40, 0x180003fe1, 0x30)):
        call(address, [])
    for value in cases:
        result = {'input': value}
        try:
            data = value.encode('utf-8')
            write(0x40000000, data + b'\0')
            write(0x40010000, struct.pack('<QQ', 0x40000000, 0x40000000 + len(data)))
            write(0x40020000, b'\0' * 0x200)
            status = call(0x1800e5d80, [0x40010000, 0, 0, 0, 0, 0x40020000, 1000])
            result['status'] = status
            if status & 0x80000000:
                raise RuntimeError('Native parse error %x' % status)
            parsed = 0x40020018
            start, end = integer(parsed), integer(parsed + 8)
            result['host_type'] = struct.unpack('<I', bytes(read(parsed + 0x84, 4)))[0]
            result['canonical_hex'] = ''.join('%02x' % x for x in read(start, end - start))
            result['canonical'] = bytes(read(start, end - start)).decode('utf-8')
            result['ranges'] = {}
            for name, offset in [('host', 0x30), ('path', 0x50), ('query', 0x60), ('fragment', 0x70)]:
                first, last = integer(parsed + offset), integer(parsed + offset + 8)
                result['ranges'][name] = bytes(read(first, last - first)).decode('utf-8') if first else None
            write(0x40021000, b'\0' * 16)
            write(0x40022000, b'\0')
            candidates = []
            for count in range(128):
                if not call(0x1800e6a50, [0x40022000, parsed, 0x40021000]):
                    break
                first, last = integer(0x40021000), integer(0x40021008)
                if last < first or last - first > 16384:
                    raise RuntimeError('Invalid native candidate range')
                candidates.append(bytes(read(first, last - first)).decode('utf-8'))
            result['candidates'] = candidates
        except Exception as error:
            result['error'] = str(error)
        results.append(result)
finally:
    emulator.dispose()
with io.open(args[1], 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps({'method': 'Original ARM64 URI functions with allocator/free emulation', 'cases': results}, indent=2)) + '\n')
print('Native URI cases: %d' % len(results))
