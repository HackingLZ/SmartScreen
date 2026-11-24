# Decompile specific functions or the functions referencing a data address.
# @category SmartScreen
import io
import json
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
fm = currentProgram.getFunctionManager()
functions = {}
for value in args[1:]:
    address = toAddr(value)
    function = fm.getFunctionContaining(address)
    if function:
        functions[str(function.getEntryPoint())] = function
    else:
        for ref in getReferencesTo(address):
            function = fm.getFunctionContaining(ref.getFromAddress())
            if function:
                functions[str(function.getEntryPoint())] = function
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
results = []
for address, function in sorted(functions.items()):
    result = decompiler.decompileFunction(function, 60, monitor)
    c = result.getDecompiledFunction()
    results.append({'address': address, 'name': function.getName(),
                    'c': c.getC() if c else None, 'error': result.getErrorMessage(),
                    'calls': [{'address': str(f.getEntryPoint()), 'name': f.getName()}
                              for f in function.getCalledFunctions(monitor)]})
decompiler.dispose()
with io.open(args[0], 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps(results, indent=2)))
print('Decompiled %d functions' % len(results))
