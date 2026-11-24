# Locate URI character-class table initialization without changing the project.
# @category SmartScreen
import io
import json
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
functions = {}
refs = []
fm = currentProgram.getFunctionManager()
for value in list(range(0x1803b3500, 0x1803b3a00)) + list(range(0x1803b9900, 0x1803ba100)):
    for ref in getReferencesTo(toAddr(value)):
        function = fm.getFunctionContaining(ref.getFromAddress())
        if function and function.getEntryPoint().getOffset() < 0x180010000:
            address = str(function.getEntryPoint())
            functions[address] = function
            refs.append({'from': str(ref.getFromAddress()), 'to': hex(value), 'function': address})
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
results = []
for address, function in sorted(functions.items()):
    result = decompiler.decompileFunction(function, 60, monitor)
    c = result.getDecompiledFunction()
    results.append({'address': address, 'c': c.getC() if c else None, 'error': result.getErrorMessage()})
decompiler.dispose()
with io.open(args[0], 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps({'references': refs, 'functions': results}, indent=2)))
print('Recorded %d table initializer functions' % len(results))
