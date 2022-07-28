import lief
from utils import get_sample, is_64bits_platform

winhello64 = lief.parse(get_sample('PE/PE64_x86-64_binary_winhello64-mingw.exe'))
atapi      = lief.parse(get_sample('PE/PE64_x86-64_atapi.sys'))

def test_dos_header():
    dos_header: lief.PE.DosHeader = atapi.dos_header

    assert dos_header.addressof_new_exeheader == 0xd8
    assert dos_header.addressof_relocation_table == 0x40
    assert dos_header.checksum == 0x0
    assert dos_header.file_size_in_pages == 0x3
    assert dos_header.header_size_in_paragraphs == 0x4
    assert dos_header.initial_ip == 0x0
    assert dos_header.initial_relative_cs == 0x0
    assert dos_header.initial_relative_ss == 0x0
    assert dos_header.initial_sp == 0xb8
    assert dos_header.magic == 0x5a4d
    assert dos_header.maximum_extra_paragraphs == 0xffff
    assert dos_header.minimum_extra_paragraphs == 0x0
    assert dos_header.numberof_relocation == 0x0
    assert dos_header.oem_id == 0x0
    assert dos_header.oem_info == 0x0
    assert dos_header.overlay_number == 0x0
    assert dos_header.used_bytes_in_the_last_page == 0x90

def test_header():
    header: lief.PE.Header = atapi.header

    assert header.numberof_sections == 0x6
    assert header.numberof_symbols == 0x0
    assert header.pointerto_symbol_table == 0x0
    assert header.signature == [80, 69, 0, 0]
    assert header.sizeof_optional_header == 0xf0
    assert header.time_date_stamps == 0x4a5bc113
    assert header.machine == lief.PE.MACHINE_TYPES.AMD64
    assert header.characteristics_list == {lief.PE.HEADER_CHARACTERISTICS.LARGE_ADDRESS_AWARE, lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE}


def test_optional_header():
    header: lief.PE.OptionalHeader = atapi.optional_header

    assert header.addressof_entrypoint == 0x7064
    assert header.baseof_code == 0x1000
    assert header.checksum == 0x65bb
    assert header.dll_characteristics == 0x0
    assert header.file_alignment == 0x200
    assert header.imagebase == 0x10000
    assert header.loader_flags == 0x0
    assert header.magic == lief.PE.PE_TYPE.PE32_PLUS
    assert header.major_image_version == 0x6
    assert header.major_linker_version == 0x9
    assert header.major_operating_system_version == 0x6
    assert header.major_subsystem_version == 0x6
    assert header.minor_image_version == 0x1
    assert header.minor_linker_version == 0x0
    assert header.minor_operating_system_version == 0x1
    assert header.minor_subsystem_version == 0x1
    assert header.numberof_rva_and_size == 0x10
    assert header.section_alignment == 0x1000
    assert header.sizeof_code == 0x3200
    assert header.sizeof_headers == 0x400
    assert header.sizeof_heap_commit == 0x1000
    assert header.sizeof_heap_reserve == 0x100000
    assert header.sizeof_image == 0x9000
    assert header.sizeof_initialized_data == 0xc00
    assert header.sizeof_stack_commit == 0x1000
    assert header.sizeof_stack_reserve == 0x40000
    assert header.sizeof_uninitialized_data == 0x0
    assert header.subsystem == lief.PE.SUBSYSTEM.NATIVE
    assert header.win32_version_value == 0x0


def test_data_directories():
    dirs = atapi.data_directories

    assert dirs[0].rva == 0x0
    assert dirs[0].size == 0x0
    assert not dirs[0].has_section

    assert dirs[1].rva == 0x7084
    assert dirs[1].size == 0x3c
    assert dirs[1].has_section
    assert dirs[1].section.name == "INIT"

    assert dirs[2].rva == 0x8000
    assert dirs[2].size == 0x3f0
    assert dirs[2].has_section
    assert dirs[2].section.name == ".rsrc"

    assert dirs[3].rva == 0x6000
    assert dirs[3].size == 0x1e0
    assert dirs[3].has_section
    assert dirs[3].section.name == ".pdata"

    assert dirs[4].rva == 0x4200
    assert dirs[4].size == 0x1c40
    assert dirs[4].has_section
    assert dirs[4].section.name == ".rdata"

    assert dirs[5].rva == 0x0
    assert dirs[5].size == 0x0
    assert not dirs[5].has_section

    assert dirs[6].rva == 0x40d0
    assert dirs[6].size == 0x1c
    assert dirs[6].has_section
    assert dirs[6].section.name == ".rdata"

    assert dirs[7].rva == 0x0
    assert dirs[7].size == 0x0
    assert not dirs[7].has_section

    assert dirs[8].rva == 0x0
    assert dirs[8].size == 0x0
    assert not dirs[8].has_section

    assert dirs[9].rva == 0x0
    assert dirs[9].size == 0x0
    assert not dirs[9].has_section

    assert dirs[10].rva == 0x0
    assert dirs[10].size == 0x0
    assert not dirs[10].has_section

    assert dirs[11].rva == 0x0
    assert dirs[11].size == 0x0
    assert not dirs[11].has_section

    assert dirs[12].rva == 0x4000
    assert dirs[12].size == 0xd0
    assert dirs[12].has_section
    assert dirs[12].section.name == ".rdata"

    assert dirs[13].rva == 0x0
    assert dirs[13].size == 0x0
    assert not dirs[13].has_section

    assert dirs[14].rva == 0x0
    assert dirs[14].size == 0x0
    assert not dirs[14].has_section

    assert dirs[15].rva == 0x0
    assert dirs[15].size == 0x0
    assert not dirs[15].has_section

def test_sections():
    sections = winhello64.sections

    assert len(sections) == 17

    section = sections[4]

    assert section.name == ".xdata"
    assert section.offset == 0x3200
    assert section.size == 0x400
    assert section.virtual_address == 0x6000
    assert section.virtual_size == 0x204
    assert section.characteristics == 0x40300040

    sections = atapi.sections
    assert sections[0].name == ".text"
    assert sections[0].virtual_size == 0x2be4
    assert sections[0].virtual_address == 0x1000
    assert sections[0].sizeof_raw_data == 0x2c00
    assert sections[0].pointerto_raw_data == 0x400
    assert sections[0].pointerto_relocation == 0x0
    assert sections[0].pointerto_line_numbers == 0x0
    assert sections[0].numberof_relocations == 0x0
    assert sections[0].numberof_line_numbers == 0x0
    assert int(sections[0].characteristics) == 0x68000020
    if is_64bits_platform():
        assert lief.hash(list(sections[0].padding)) == 16581494691545067240
        assert lief.hash(list(sections[0].content)) == 12119947047017266734

    assert sections[1].name == ".rdata"
    assert sections[1].virtual_size == 0x2b4
    assert sections[1].virtual_address == 0x4000
    assert sections[1].sizeof_raw_data == 0x400
    assert sections[1].pointerto_raw_data == 0x3000
    assert sections[1].pointerto_relocation == 0x0
    assert sections[1].pointerto_line_numbers == 0x0
    assert sections[1].numberof_relocations == 0x0
    assert sections[1].numberof_line_numbers == 0x0
    assert int(sections[1].characteristics) == 0x48000040

    if is_64bits_platform():
        assert lief.hash(list(sections[1].padding)) == 13095545801059734885
        assert lief.hash(list(sections[1].content)) == 6944188420063945945

    assert sections[2].name == ".data"
    assert sections[2].virtual_size == 0x114
    assert sections[2].virtual_address == 0x5000
    assert sections[2].sizeof_raw_data == 0x200
    assert sections[2].pointerto_raw_data == 0x3400
    assert sections[2].pointerto_relocation == 0x0
    assert sections[2].pointerto_line_numbers == 0x0
    assert sections[2].numberof_relocations == 0x0
    assert sections[2].numberof_line_numbers == 0x0
    assert int(sections[2].characteristics) == 0xc8000040

    if is_64bits_platform():
        assert lief.hash(list(sections[2].padding)) == 16286773346125632144
        assert lief.hash(list(sections[2].content)) == 7978755463523708033

    assert sections[3].name == ".pdata"
    assert sections[3].virtual_size == 0x1e0
    assert sections[3].virtual_address == 0x6000
    assert sections[3].sizeof_raw_data == 0x200
    assert sections[3].pointerto_raw_data == 0x3600
    assert sections[3].pointerto_relocation == 0x0
    assert sections[3].pointerto_line_numbers == 0x0
    assert sections[3].numberof_relocations == 0x0
    assert sections[3].numberof_line_numbers == 0x0
    assert int(sections[3].characteristics) == 0x48000040

    if is_64bits_platform():
        assert lief.hash(list(sections[3].padding)) == 10388213471796734245
        assert lief.hash(list(sections[3].content)) == 2565729174231943742

    assert sections[4].name == "INIT"
    assert sections[4].virtual_size == 0x42a
    assert sections[4].virtual_address == 0x7000
    assert sections[4].sizeof_raw_data == 0x600
    assert sections[4].pointerto_raw_data == 0x3800
    assert sections[4].pointerto_relocation == 0x0
    assert sections[4].pointerto_line_numbers == 0x0
    assert sections[4].numberof_relocations == 0x0
    assert sections[4].numberof_line_numbers == 0x0
    assert int(sections[4].characteristics) == 0xe2000020

    if is_64bits_platform():
        assert lief.hash(list(sections[4].padding)) == 6267801405663681729
        assert lief.hash(list(sections[4].content)) == 9792162199629343627

    assert sections[5].name == ".rsrc"
    assert sections[5].virtual_size == 0x3f0
    assert sections[5].virtual_address == 0x8000
    assert sections[5].sizeof_raw_data == 0x400
    assert sections[5].pointerto_raw_data == 0x3e00
    assert sections[5].pointerto_relocation == 0x0
    assert sections[5].pointerto_line_numbers == 0x0
    assert sections[5].numberof_relocations == 0x0
    assert sections[5].numberof_line_numbers == 0x0
    assert int(sections[5].characteristics) == 0x42000040

    if is_64bits_platform():
        assert lief.hash(list(sections[5].padding)) == 2694043916712032187
        assert lief.hash(list(sections[5].content)) == 17560174430803761296

def test_tls():
    assert winhello64.has_tls

    tls = winhello64.tls

    assert tls.addressof_callbacks == 0x409040
    assert tls.callbacks, [0x4019c0 == 0x401990]
    assert tls.addressof_index == 0x4075fc
    assert tls.sizeof_zero_fill == 0
    assert tls.characteristics == 0
    assert tls.addressof_raw_data, (0x40a000 == 0x40a060)
    assert tls.section.name == ".tls"

def test_imports():
    imports  = winhello64.imports

    assert len(imports) == 2

    kernel32 = imports[0]
    assert kernel32.name == "KERNEL32.dll"
    assert kernel32.import_address_table_rva == 0x81fc
    assert kernel32.import_lookup_table_rva == 0x803C
    assert len(kernel32.entries) == 25

    entry_12 = kernel32.entries[12]
    assert entry_12.name == "LeaveCriticalSection"
    assert entry_12.data == 0x84ba
    assert entry_12.hint == 0x34b
    assert entry_12.iat_value == 0x84ba
    assert entry_12.iat_address == 0x825c

    msvcrt = imports[1]
    assert msvcrt.name == "msvcrt.dll"
    assert msvcrt.import_address_table_rva == 0x82cc
    assert msvcrt.import_lookup_table_rva == 0x810c
    assert len(msvcrt.entries) == 29

    entry_0 = msvcrt.entries[0]
    assert entry_0.name == "__C_specific_handler"
    assert entry_0.data == 0x85ca
    assert entry_0.hint == 55
    assert entry_0.iat_value == 0x85ca
    assert entry_0.iat_address == 0x82cc

def test_issue_imports():
    pe: lief.PE.Binary = lief.parse(get_sample("PE/abdce8577b46e4e23346f06ba8b9ab05cf47e92aec7e615c04436301355cd86d.pe"))
    imports = pe.imports

    assert len(imports) == 9
    entry_7 = imports[8]
    assert len(entry_7.entries) == 6
    assert entry_7.entries[0].name == "GetModuleHandleA"
    assert entry_7.entries[5].name == "ExitProcess"

def test_issue_exports():
    pe: lief.PE.Binary = lief.parse(get_sample("PE/24e3ea78835748c9995e0d0c64f4f6bd3a0ca1b495b61a601703eb19b8c27f95.pe"))
    exports = pe.get_export()

    assert exports.name == "Uniscribe.dll"
    assert exports.export_flags == 0
    assert exports.timestamp == 1446632214
    assert exports.major_version == 0
    assert exports.minor_version == 0
    assert exports.ordinal_base == 1
    assert len(exports.entries) == 7

    assert exports.entries[0].name == "GetModuleFileNameDll"
    assert exports.entries[0].ordinal == 1
    assert exports.entries[0].address == 0x15bd0
    assert not exports.entries[0].is_extern
    assert exports.entries[0].function_rva == 0x15bd0

    assert exports.entries[6].name == "ncProxyXll"
    assert exports.entries[6].ordinal == 7
    assert exports.entries[6].address == 0x203a0
    assert not exports.entries[6].is_extern
    assert exports.entries[6].function_rva == 0x203a0

def test_issue_685():
    """
    https://github.com/lief-project/LIEF/issues/685
    """

    pe: lief.PE.Binary = lief.parse(get_sample("PE/2420feb9d03efc1aa07b4117390c29cd8fee826ea1b48fee89660d65a3a8ba2b.neut"))

    exports = pe.get_export()

    assert exports.name == "nmv.ocx"
    assert exports.entries[0].name == "oplk"

def test_rich_header():
    rheader = atapi.rich_header
    assert rheader.key == 0xa476a6e3

    entries = rheader.entries

    assert len(entries) == 7
    entry_4 = entries[4]

    assert entry_4.id == 0x95
    assert entry_4.build_id == 0x7809
    assert entry_4.count == 1
    hex_val = bytes(rheader.raw(rheader.key)).hex()
    assert hex_val == "a7c718f7e3a676a4e3a676a4e3a676a4" \
                      "eadee5a4e6a676a4e3a677a4fba676a4" \
                      "eadee3a4e2a676a4eadef5a4e0a676a4" \
                      "eadeffa4e1a676a4eadee2a4e2a676a4" \
                      "eadee7a4e2a676a452696368e3a676a4"

    sha256 = bytes(rheader.hash(lief.PE.ALGORITHMS.SHA_256, rheader.key)).hex()
    assert sha256 == "1bda7d55023ff27b0ea1c9f56d53ca77ca4264ac58fdee8daac58cdc060bf2da"



def test_relocations():
    pe: lief.PE.Binary = lief.parse(get_sample("PE/PE64_x86-64_binary_mfc-application.exe"))
    relocations = pe.relocations
    assert relocations[0].virtual_address == 0xd000
    assert relocations[0].block_size == 0xb8
    assert len(relocations[0].entries) == 88
    relocation = relocations[0]

    assert relocation.entries[46].data == 0xaeb8
    assert relocation.entries[46].position == 0xeb8
    assert relocation.entries[46].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[25].data == 0xae10
    assert relocation.entries[25].position == 0xe10
    assert relocation.entries[25].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[56].data == 0xaf08
    assert relocation.entries[56].position == 0xf08
    assert relocation.entries[56].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[75].data == 0xafa0
    assert relocation.entries[75].position == 0xfa0
    assert relocation.entries[75].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64

    assert relocations[8].virtual_address == 0x15000
    assert relocations[8].block_size == 0xc0
    assert len(relocations[8].entries) == 92
    relocation = relocations[8]
    assert relocation.entries[87].data == 0xa9f8
    assert relocation.entries[87].position == 0x9f8
    assert relocation.entries[87].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[24].data == 0xa0c0
    assert relocation.entries[24].position == 0xc0
    assert relocation.entries[24].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[67].data == 0xa218
    assert relocation.entries[67].position == 0x218
    assert relocation.entries[67].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[54].data == 0xa1b0
    assert relocation.entries[54].position == 0x1b0
    assert relocation.entries[54].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64

    assert relocations[9].virtual_address == 0x1c000
    assert relocations[9].block_size == 0x80
    assert len(relocations[9].entries) == 60
    relocation = relocations[9]
    assert relocation.entries[40].data == 0xa628
    assert relocation.entries[40].position == 0x628
    assert relocation.entries[40].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[17].data == 0xa2d8
    assert relocation.entries[17].position == 0x2d8
    assert relocation.entries[17].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[36].data == 0xa5a0
    assert relocation.entries[36].position == 0x5a0
    assert relocation.entries[36].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64
    assert relocation.entries[52].data == 0xa7f8
    assert relocation.entries[52].position == 0x7f8
    assert relocation.entries[52].type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64


def test_symbols():

    symbols = winhello64.symbols
    assert len(symbols) == 1097

    symbol = symbols[1]
    assert symbol.name == "__mingw_invalidParameterHandler"
    assert symbol.value == 0
    assert symbol.section_number == 1
    assert symbol.type == 32


def test_checksum():
    assert atapi.optional_header.computed_checksum      == atapi.optional_header.checksum
    assert winhello64.optional_header.computed_checksum == winhello64.optional_header.checksum
