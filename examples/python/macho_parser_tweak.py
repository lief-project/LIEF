import lief
import sys
import time

# Do not parse dyld info
config = lief.MachO.ParserConfig()
config.parse_dyld_bindings = False
config.parse_dyld_exports  = False
config.parse_dyld_rebases  = False

t1 = time.time()
lief.MachO.parse(sys.argv[1], config)
t2 = time.time()
print(f"Done in {t2 - t1}s")


# Parse the dyld information
config.full_dyldinfo(True)

t1 = time.time()
lief.MachO.parse(sys.argv[1], config)
t2 = time.time()
print(f"Done in {t2 - t1}s")
