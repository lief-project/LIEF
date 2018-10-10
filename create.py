import lief

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.DEBUG)

b = lief.ELF.Binary.create_lief_dyn(lief.ELF.ARCH.x86_64)
print(b)

for i in range(3):
    s = lief.ELF.Section(f".foo{i}")
    s.content = [i & 0xFF for x in range(0x1000)]
    b.add(s, True)

print(b)
b.write("/tmp/out")


b = lief.ELF.Binary.create_lief_dyn(lief.ELF.ARCH.x86_64)
print(b)


for i in range(3):
    s = lief.ELF.Segment()
    s.type = lief.ELF.SEGMENT_TYPES.LOAD
    s.content = [i & 0xFF for x in range(0x1000)]
    b.add(s)

for i in range(10):
    s = lief.ELF.Section(f".foo{i}")
    b.add(s, False)

print(b)
b.write("/tmp/out2")
