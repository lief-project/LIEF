import lief
from lief.ELF import Section

ls   = lief.parse("/bin/clang")
stub = lief.parse("hello_lief.bin")

section            = Section()
section.name       = "test"
section.type       = lief.ELF.SECTION_TYPES.PROGBITS
section.content    = stub.segments[0].data # First LOAD segment which holds payload
section.entry_size = 0
section.alignment  = 8
section = ls.add_section(section, True)

ls.header.entrypoint = section.virtual_address + stub.header.entrypoint

ls.write("lst.section")
# Have fun !
