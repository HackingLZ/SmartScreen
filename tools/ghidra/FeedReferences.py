# Read-only caller and reference inventory for feed reverse engineering.
# @category SmartScreen
import io
import json
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
fm = currentProgram.getFunctionManager()
functions = {}
references = {}
for value in args[1:]:
    address = toAddr(value)
    refs = []
    for ref in getReferencesTo(address):
        function = fm.getFunctionContaining(ref.getFromAddress())
        refs.append({'from': str(ref.getFromAddress()), 'type': str(ref.getReferenceType()),
                     'function': str(function.getEntryPoint()) if function else None})
        if function:
            functions[str(function.getEntryPoint())] = function
    references[value] = refs
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
results = []
for address, function in sorted(functions.items()):
    result = decompiler.decompileFunction(function, 60, monitor)
    c = result.getDecompiledFunction()
    results.append({'address': address, 'name': function.getName(),
                    'c': c.getC() if c else None, 'error': result.getErrorMessage()})
decompiler.dispose()
with io.open(args[0], 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps({'references': references, 'functions': results}, indent=2)))
print('Recorded %d caller functions' % len(results))
