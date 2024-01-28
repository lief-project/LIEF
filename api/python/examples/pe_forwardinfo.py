import lief
import sys

pe = lief.PE.parse(sys.argv[1])
exports = pe.get_export()

for e in filter(lambda e: e.is_forwarded, exports.entries):
    fwd = e.forward_information
    print(f"{e.name:<35} -> {fwd.library}.{fwd.function}")
