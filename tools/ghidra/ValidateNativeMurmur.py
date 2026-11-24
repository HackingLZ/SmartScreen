# Emulate the collected DLL's standalone ARM64 hash routine on test vectors.
# @category SmartScreen
import io
import json
import time
from ghidra.app.emulator import EmulatorHelper
from jarray import array

args = getScriptArgs()
with io.open(args[0], 'r', encoding='utf-8') as source:
    document = json.load(source)
emulator = EmulatorHelper(currentProgram)
results = []
try:
    data_address = 0x40000000
    output_address = 0x40020000
    stop_address = 0x40030000
    emulator.setBreakpoint(toAddr(stop_address))
    for case in document['cases']:
        data = bytearray.fromhex(str(case['input_hex']))
        emulator.writeMemory(toAddr(data_address), array([x if x < 128 else x - 256 for x in (data or bytearray([0]))], 'b'))
        emulator.writeMemory(toAddr(output_address), array([0] * 16, 'b'))
        for name, value in [('x0', data_address), ('x1', len(data)),
                            ('x2', case['seed']), ('x3', output_address),
                            ('sp', 0x4003f000), ('x30', stop_address)]:
            emulator.writeRegister(name, long(value))
        success = emulator.run(toAddr('1800149d8'), None, monitor)
        if not success or emulator.getExecutionAddress() != toAddr(stop_address):
            raise RuntimeError('Native hash emulation failed: ' + str(emulator.getLastError()))
        actual = ''.join('%02x' % (int(value) & 255) for value in emulator.readMemory(toAddr(output_address), 16))
        result = dict(case)
        result['native_digest_hex'] = actual
        result['match'] = actual == case['python_digest_hex']
        results.append(result)
finally:
    emulator.dispose()
document['cases'] = results
document['case_count'] = len(results)
document['mismatch_count'] = sum(not value['match'] for value in results)
document['method'] = 'Ghidra p-code emulation of original ARM64 machine instructions'
with io.open(args[1], 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps(document, indent=2)) + '\n')
print('Native Murmur cases: %d; mismatches: %d' % (len(results), document['mismatch_count']))
