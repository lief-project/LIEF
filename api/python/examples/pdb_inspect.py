import lief
import sys

pdb = lief.pdb.load(sys.argv[0])

print("arg={}, guid={}", pdb.age, pdb.guid)

for sym in pdb.public_symbols:
    print("name={}, section={}, RVA={}",
          sym.name, sym.section_name, sym.RVA)

for ty in pdb.types:
    if isinstance(ty, lief.pdb.types.Class):
        print("Class[name]={}", ty.name)

for cu in pdb.compilation_units:
    print("module={}", cu.module_name)
    for src in cu.sources:
        print("  - {}", src)

    for func in cu.functions:
        print("name={}, section={}, RVA={}, code_size={}",
              func.name, func.section_name, func.RVA, func.code_size)
