import lief
from lief.ELF import Section

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

ls   = lief.parse("/home/romain/dev/LIEF/lief-samples/ELF/ELF64_x86-64_binary_static-binary.bin")
stub = lief.parse("hello_lief.bin")

#section            = Section()
#section.name       = "test"
#section.type       = lief.ELF.SECTION_TYPES.PROGBITS
#section.content    = stub.segments[0].content # First LOAD segment which holds payload (bytes)
#section = ls.add(section, loaded=True)
#ls.header.entrypoint = section.virtual_address + stub.header.entrypoint
#
#ep = ls.header.entrypoint

for i in range(10):
    segment                 = stub.segments[0]
    original_va             = segment.virtual_address
    segment.virtual_address = 0
    segment                 = ls.add(segment)
    new_ep                  = (stub.header.entrypoint - original_va) + segment.virtual_address

    ls.header.entrypoint = new_ep

ls.write("lst.section")

#print(hex(ep))
