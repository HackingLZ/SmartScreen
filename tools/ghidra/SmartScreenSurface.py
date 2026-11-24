# Extract SmartScreen API strings, references, exports and selected decompilation.
# @category SmartScreen
import io
import json
import os
import re
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
outdir = args[0]
if not os.path.isdir(outdir):
    os.makedirs(outdir)
pattern = re.compile(r'SmartScreenHash|authId|beforeExecute|/api/|/data/|siphash|bloomfilter|synchronousLookup|topTraffic|downloadcomplete', re.I)
records = []
selected = {}
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
for data in listing.getDefinedData(True):
    value = unicode(data.getValue())
    if not pattern.search(value):
        continue
    refs = []
    for ref in getReferencesTo(data.getAddress()):
        fn = fm.getFunctionContaining(ref.getFromAddress())
        if fn is not None:
            key = str(fn.getEntryPoint())
            selected[key] = fn
            refs.append({'function': fn.getName(), 'entry': key, 'from': str(ref.getFromAddress())})
    records.append({'address': str(data.getAddress()), 'value': value, 'references': refs})
exports = []
for address in currentProgram.getSymbolTable().getExternalEntryPointIterator():
    fn = fm.getFunctionAt(address)
    exports.append({'address': str(address), 'name': str(getSymbolAt(address))})
    if fn is not None:
        selected[str(address)] = fn
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
decompiled = []
for address in sorted(selected)[:100]:
    fn = selected[address]
    result = decompiler.decompileFunction(fn, 45, monitor)
    c = result.getDecompiledFunction()
    decompiled.append({'address': address, 'name': fn.getName(),
                       'completed': result.decompileCompleted(),
                       'error': result.getErrorMessage(), 'c': c.getC() if c else None})
decompiler.dispose()
report = {'program': currentProgram.getName(), 'language': str(currentProgram.getLanguageID()),
          'image_base': str(currentProgram.getImageBase()), 'strings': records,
          'exports': exports, 'decompiled': decompiled}
with io.open(os.path.join(outdir, currentProgram.getName() + '.surface.json'), 'w', encoding='utf-8') as output:
    output.write(unicode(json.dumps(report, indent=2)))
print('Wrote surface report: %d strings, %d functions' % (len(records), len(decompiled)))
