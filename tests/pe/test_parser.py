import hashlib
import subprocess
import sys
from hashlib import md5
from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import get_sample, is_64bits_platform, lru_cache, parse_pe


@lru_cache(maxsize=1)
def _winhello64() -> lief.PE.Binary:
    return parse_pe("PE/PE64_x86-64_binary_winhello64-mingw.exe")


@lru_cache(maxsize=1)
def _atapi() -> lief.PE.Binary:
    return parse_pe("PE/PE64_x86-64_atapi.sys")


def test_dos_header():
    atapi = _atapi()
    dos_header = atapi.dos_header

    assert dos_header.copy() == dos_header

    assert dos_header.addressof_new_exeheader == 0xD8
    assert dos_header.addressof_relocation_table == 0x40
    assert dos_header.checksum == 0x0
    assert dos_header.file_size_in_pages == 0x3
    assert dos_header.header_size_in_paragraphs == 0x4
    assert dos_header.initial_ip == 0x0
    assert dos_header.initial_relative_cs == 0x0
    assert dos_header.initial_relative_ss == 0x0
    assert dos_header.initial_sp == 0xB8
    assert dos_header.magic == 0x5A4D
    assert dos_header.maximum_extra_paragraphs == 0xFFFF
    assert dos_header.minimum_extra_paragraphs == 0x0
    assert dos_header.numberof_relocation == 0x0
    assert dos_header.oem_id == 0x0
    assert dos_header.oem_info == 0x0
    assert dos_header.overlay_number == 0x0
    assert dos_header.used_bytes_in_last_page == 0x90

    assert (
        hashlib.sha256(atapi.dos_stub).hexdigest()
        == "2e6296653faf1fd51d875fab7e08c38f06f9a7eccb718c569dee5e3041075a6a"
    )
    lief.logging.info(dos_header)


def test_header():
    atapi = _atapi()
    header = atapi.header

    assert header.copy() == header
    assert header.numberof_sections == 0x6
    assert header.numberof_symbols == 0x0
    assert header.pointerto_symbol_table == 0x0
    assert header.signature == [80, 69, 0, 0]
    assert header.sizeof_optional_header == 0xF0
    assert header.time_date_stamps == 0x4A5BC113
    assert header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
    assert header.characteristics_list == [
        lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE,
        lief.PE.Header.CHARACTERISTICS.LARGE_ADDRESS_AWARE,
    ]
    lief.logging.info(header)
    assert header.copy() == header


def test_optional_header():
    atapi = _atapi()
    header = atapi.optional_header
    lief.logging.info(header)

    assert header.copy() == header

    assert header.addressof_entrypoint == 0x7064
    assert header.baseof_code == 0x1000
    assert header.baseof_data == 0
    assert header.checksum == 0x65BB
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
    assert header.sizeof_initialized_data == 0xC00
    assert header.sizeof_stack_commit == 0x1000
    assert header.sizeof_stack_reserve == 0x40000
    assert header.sizeof_uninitialized_data == 0x0
    assert header.subsystem == lief.PE.OptionalHeader.SUBSYSTEM.NATIVE
    assert header.win32_version_value == 0x0
    assert header.dll_characteristics_lists == []


def test_data_directories():
    atapi = _atapi()
    dirs = atapi.data_directories

    assert dirs[0].rva == 0x0
    assert dirs[0].size == 0x0
    assert not dirs[0].has_section
    export_dir = atapi.export_dir
    assert export_dir is not None
    assert export_dir.section is None
    assert len(export_dir.content) == 0

    assert dirs[1].rva == 0x7084
    assert dirs[1].size == 0x3C
    assert dirs[1].has_section
    dirs1_sec = dirs[1].section
    assert dirs1_sec is not None
    assert dirs1_sec.name == "INIT"

    import_dir = atapi.import_dir
    assert import_dir is not None
    import_dir_sec = import_dir.section
    assert import_dir_sec is not None
    assert import_dir_sec.name == "INIT"
    assert md5(import_dir.content).hexdigest() == "5306ea0dad00863a03848629a835e3d3"

    # Coverage: str()/hash() on DataDirectory
    output = str(dirs[1])
    assert len(output) > 0
    assert hash(dirs[1]) != 0

    assert dirs[2].rva == 0x8000
    assert dirs[2].size == 0x3F0
    assert dirs[2].has_section
    dirs2_sec = dirs[2].section
    assert dirs2_sec is not None
    assert dirs2_sec.name == ".rsrc"

    rsrc_dir = atapi.rsrc_dir
    assert rsrc_dir is not None
    rsrc_dir_sec = rsrc_dir.section
    assert rsrc_dir_sec is not None
    assert rsrc_dir_sec.name == ".rsrc"
    assert md5(rsrc_dir.content).hexdigest() == "1b3742663d5767289e49e90596221bdb"

    assert dirs[3].rva == 0x6000
    assert dirs[3].size == 0x1E0
    assert dirs[3].has_section
    dirs3_sec = dirs[3].section
    assert dirs3_sec is not None
    assert dirs3_sec.name == ".pdata"

    exceptions_dir = atapi.exceptions_dir
    assert exceptions_dir is not None
    exceptions_dir_sec = exceptions_dir.section
    assert exceptions_dir_sec is not None
    assert exceptions_dir_sec.name == ".pdata"
    assert md5(exceptions_dir.content).hexdigest() == "8bb93cd186e1457855901a8f0f2fc43b"

    assert dirs[4].rva == 0x4200
    assert dirs[4].size == 0x1C40
    assert dirs[4].has_section
    dirs4_sec = dirs[4].section
    assert dirs4_sec is not None
    assert dirs4_sec.name == ".rdata"

    cert_dir = atapi.cert_dir
    assert cert_dir is not None
    cert_dir_sec = cert_dir.section
    assert cert_dir_sec is not None
    assert cert_dir_sec.name == ".rdata"
    assert md5(cert_dir.content).hexdigest() == "d41d8cd98f00b204e9800998ecf8427e"

    assert dirs[5].rva == 0x0
    assert dirs[5].size == 0x0
    assert not dirs[5].has_section

    relocation_dir = atapi.relocation_dir
    assert relocation_dir is not None
    assert relocation_dir.section is None
    assert len(relocation_dir.content) == 0

    assert dirs[6].rva == 0x40D0
    assert dirs[6].size == 0x1C
    assert dirs[6].has_section
    dirs6_sec = dirs[6].section
    assert dirs6_sec is not None
    assert dirs6_sec.name == ".rdata"

    debug_dir = atapi.debug_dir
    assert debug_dir is not None
    debug_dir_sec = debug_dir.section
    assert debug_dir_sec is not None
    assert debug_dir_sec.name == ".rdata"
    assert md5(debug_dir.content).hexdigest() == "2f88ed87466be93a75658cb122e42430"

    assert dirs[7].rva == 0x0
    assert dirs[7].size == 0x0
    assert not dirs[7].has_section

    assert dirs[8].rva == 0x0
    assert dirs[8].size == 0x0
    assert not dirs[8].has_section

    assert dirs[9].rva == 0x0
    assert dirs[9].size == 0x0
    assert not dirs[9].has_section

    tls_dir = atapi.tls_dir
    assert tls_dir is not None
    assert tls_dir.section is None
    assert len(tls_dir.content) == 0

    assert dirs[10].rva == 0x0
    assert dirs[10].size == 0x0
    assert not dirs[10].has_section

    load_config_dir = atapi.load_config_dir
    assert load_config_dir is not None
    assert load_config_dir.section is None
    assert len(load_config_dir.content) == 0

    assert dirs[11].rva == 0x0
    assert dirs[11].size == 0x0
    assert not dirs[11].has_section

    assert dirs[12].rva == 0x4000
    assert dirs[12].size == 0xD0
    assert dirs[12].has_section
    dirs12_sec = dirs[12].section
    assert dirs12_sec is not None
    assert dirs12_sec.name == ".rdata"

    iat_dir = atapi.iat_dir
    assert iat_dir is not None
    iat_dir_sec = iat_dir.section
    assert iat_dir_sec is not None
    assert iat_dir_sec.name == ".rdata"
    assert md5(iat_dir.content).hexdigest() == "c84142a5e1179115100f642dde18ee75"

    assert dirs[13].rva == 0x0
    assert dirs[13].size == 0x0
    assert not dirs[13].has_section

    assert dirs[14].rva == 0x0
    assert dirs[14].size == 0x0
    assert not dirs[14].has_section

    assert dirs[15].rva == 0x0
    assert dirs[15].size == 0x0
    assert not dirs[15].has_section

    assert dirs[1].copy() == dirs[1]
    lief.logging.info(dirs[1])


def test_sections():
    winhello64 = _winhello64()
    atapi = _atapi()
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
    assert sections[0].virtual_size == 0x2BE4
    assert sections[0].virtual_address == 0x1000
    assert sections[0].sizeof_raw_data == 0x2C00
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
    assert sections[1].virtual_size == 0x2B4
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
    assert int(sections[2].characteristics) == 0xC8000040

    if is_64bits_platform():
        assert lief.hash(list(sections[2].padding)) == 16286773346125632144
        assert lief.hash(list(sections[2].content)) == 7978755463523708033

    assert sections[3].name == ".pdata"
    assert sections[3].virtual_size == 0x1E0
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
    assert sections[4].virtual_size == 0x42A
    assert sections[4].virtual_address == 0x7000
    assert sections[4].sizeof_raw_data == 0x600
    assert sections[4].pointerto_raw_data == 0x3800
    assert sections[4].pointerto_relocation == 0x0
    assert sections[4].pointerto_line_numbers == 0x0
    assert sections[4].numberof_relocations == 0x0
    assert sections[4].numberof_line_numbers == 0x0
    assert int(sections[4].characteristics) == 0xE2000020

    if is_64bits_platform():
        assert lief.hash(list(sections[4].padding)) == 6267801405663681729
        assert lief.hash(list(sections[4].content)) == 9792162199629343627

    assert sections[5].copy() == sections[5]
    assert sections[5].name == ".rsrc"
    assert sections[5].virtual_size == 0x3F0
    assert sections[5].virtual_address == 0x8000
    assert sections[5].sizeof_raw_data == 0x400
    assert sections[5].pointerto_raw_data == 0x3E00
    assert sections[5].pointerto_relocation == 0x0
    assert sections[5].pointerto_line_numbers == 0x0
    assert sections[5].numberof_relocations == 0x0
    assert sections[5].numberof_line_numbers == 0x0
    assert int(sections[5].characteristics) == 0x42000040

    # make sure we can't write more than the size of a name
    custom_section = lief.PE.Section(".test")
    custom_section.name = "a" * 30
    custom_section.content = [1] * 10
    assert custom_section.content[0] == 1
    assert custom_section.name == ".test"

    if is_64bits_platform():
        assert lief.hash(list(sections[5].padding)) == 2694043916712032187
        assert lief.hash(list(sections[5].content)) == 17560174430803761296


def test_tls():
    winhello64 = _winhello64()
    assert winhello64.has_tls

    tls = winhello64.tls

    assert tls.addressof_callbacks == 0x409040
    assert tls.callbacks == [0x4019C0, 0x401990]
    assert tls.addressof_index == 0x4075FC
    assert tls.sizeof_zero_fill == 0
    assert tls.characteristics == 0
    assert tls.addressof_raw_data == (0x40A000, 0x40A060)
    assert tls.section.name == ".tls"
    assert tls.copy() == tls
    lief.logging.info(tls)

    assert tls.directory is not None
    assert tls.directory.type == lief.PE.DataDirectory.TYPES.TLS_TABLE
    assert (
        hashlib.sha256(tls.data_template).hexdigest()
        == "ffb6b993bf4ae7ec095d4aeba45ac7e9973e16c17077058260f3f4eb0487d07e"
    )


def test_imports():
    winhello64 = _winhello64()
    imports = winhello64.imports

    assert len(imports) == 2

    kernel32 = imports[0]
    assert kernel32.name == "KERNEL32.dll"
    assert kernel32.import_address_table_rva == 0x81FC
    assert kernel32.import_lookup_table_rva == 0x803C
    assert len(kernel32.entries) == 25

    entry_12 = kernel32.entries[12]
    assert entry_12.name == "LeaveCriticalSection"
    assert entry_12.data == 0x84BA
    assert entry_12.hint == 0x34B
    assert entry_12.iat_value == 0x84BA
    assert entry_12.iat_address == 0x825C
    assert kernel32.get_entry("DoesNotExist") is None
    assert kernel32.get_entry("LeaveCriticalSection") == entry_12
    assert kernel32.get_entry("LeaveCriticalSection") != kernel32.entries[11].copy()
    assert kernel32.get_function_rva_from_iat("LeaveCriticalSection") == 96

    # Coverage: str()/hash() on Import and ImportEntry
    output = str(kernel32)
    assert "KERNEL32" in output
    assert hash(kernel32) != 0
    entry_str = str(entry_12)
    assert "LeaveCriticalSection" in entry_str
    assert hash(entry_12) != 0
    # Coverage: demangled_name (may be empty without extended LIEF)
    _ = entry_12.demangled_name

    msvcrt = imports[1]
    assert msvcrt.name == "msvcrt.dll"
    assert msvcrt.import_address_table_rva == 0x82CC
    assert msvcrt.import_lookup_table_rva == 0x810C
    assert len(msvcrt.entries) == 29

    entry_0 = msvcrt.entries[0]
    assert entry_0.name == "__C_specific_handler"
    assert entry_0.data == 0x85CA
    assert entry_0.hint == 55
    assert entry_0.iat_value == 0x85CA
    assert entry_0.iat_address == 0x82CC

    assert msvcrt.directory == winhello64.data_directory(
        lief.PE.DataDirectory.TYPES.IMPORT_TABLE
    )
    assert msvcrt.iat_directory == winhello64.data_directory(
        lief.PE.DataDirectory.TYPES.IAT
    )
    assert msvcrt.get_function_rva_from_iat("") == lief.lief_errors.not_found
    assert msvcrt.get_function_rva_from_iat("__C_specific_handler") == 0


def test_import_remove_entry_ordinal():
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None
    oleaut32 = pe.get_import("OLEAUT32.dll")
    assert oleaut32 is not None

    # Find the ordinal import
    ordinal_entry = None
    for entry in oleaut32.entries:
        if entry.is_ordinal:
            ordinal_entry = entry
            break
    assert ordinal_entry is not None
    ordinal_val = ordinal_entry.ordinal

    nb_before = len(oleaut32.entries)
    assert oleaut32.remove_entry(ordinal_val)
    assert len(oleaut32.entries) == nb_before - 1

    # Try removing a non-existent ordinal
    assert not oleaut32.remove_entry(0xDEAD)


def test_issue_imports():
    pe = parse_pe(
        "PE/abdce8577b46e4e23346f06ba8b9ab05cf47e92aec7e615c04436301355cd86d.pe"
    )
    imports = pe.imports

    assert len(imports) == 9
    entry_7 = imports[8]
    assert len(entry_7.entries) == 6
    assert entry_7.entries[0].name == "GetModuleHandleA"
    assert entry_7.entries[5].name == "ExitProcess"


def test_issue_exports():
    pe = parse_pe(
        "PE/24e3ea78835748c9995e0d0c64f4f6bd3a0ca1b495b61a601703eb19b8c27f95.pe"
    )
    exports = pe.get_export()
    assert exports is not None

    assert exports.name == "Uniscribe.dll"
    assert exports.export_flags == 0
    assert exports.timestamp == 1446632214
    assert exports.major_version == 0
    assert exports.minor_version == 0
    assert exports.ordinal_base == 1
    assert len(exports.entries) == 7

    assert exports.entries[0].name == "GetModuleFileNameDll"
    assert exports.entries[0].ordinal == 1
    assert exports.entries[0].address == 0x15BD0
    assert not exports.entries[0].is_extern
    assert exports.entries[0].function_rva == 0x15BD0

    assert exports.entries[6].name == "ncProxyXll"
    assert exports.entries[6].ordinal == 7
    assert exports.entries[6].address == 0x203A0
    assert not exports.entries[6].is_extern
    assert exports.entries[6].function_rva == 0x203A0

    assert exports.entries[6].value == 0x203A0

    entry = exports.entries[6]
    assert not entry.is_forwarded
    assert entry.forward_information.function == ""
    assert entry.forward_information.library == ""

    assert exports.copy() == exports

    # Coverage: str()/hash() on Export and ExportEntry
    output = str(exports)
    assert "Uniscribe" in output
    assert hash(exports) != 0
    entry_str = str(entry)
    assert len(entry_str) > 0
    assert hash(entry) != 0
    # Coverage: demangled_name (may be empty without extended LIEF)
    _ = entry.demangled_name

    # Coverage: find_entry by ordinal and by RVA
    found = exports.find_entry(7)
    assert found is not None
    assert found.name == "ncProxyXll"

    found_rva = exports.find_entry_at(0x203A0)
    assert found_rva is not None
    assert found_rva.name == "ncProxyXll"

    assert exports.find_entry(9999) is None
    assert exports.find_entry_at(0xDEAD) is None


def test_issue_685():
    """
    https://github.com/lief-project/LIEF/issues/685
    """

    pe = parse_pe(
        "PE/2420feb9d03efc1aa07b4117390c29cd8fee826ea1b48fee89660d65a3a8ba2b.neut"
    )

    exports = pe.get_export()
    assert exports is not None

    assert exports.name == "nmv.ocx"
    assert exports.entries[0].name == "oplk"

    entry = exports.entries[0]
    assert entry is not None


def test_rich_header():
    atapi = _atapi()
    rheader = atapi.rich_header
    assert rheader is not None
    assert rheader.key == 0xA476A6E3

    entries = rheader.entries

    assert len(entries) == 7
    entry_4 = entries[4]

    assert entry_4.id == 0x95
    assert entry_4.build_id == 0x7809
    assert entry_4.count == 1
    hex_val = bytes(rheader.raw(rheader.key)).hex()
    assert hex_val == (
        "a7c718f7e3a676a4e3a676a4e3a676a4"
        "eadee5a4e6a676a4e3a677a4fba676a4"
        "eadee3a4e2a676a4eadef5a4e0a676a4"
        "eadeffa4e1a676a4eadee2a4e2a676a4"
        "eadee7a4e2a676a452696368e3a676a4"
    )

    sha256 = bytes(rheader.hash(lief.PE.ALGORITHMS.SHA_256, rheader.key)).hex()
    assert sha256 == "1bda7d55023ff27b0ea1c9f56d53ca77ca4264ac58fdee8daac58cdc060bf2da"

    assert rheader.copy() == rheader
    lief.logging.info(rheader)
    new_entry = lief.PE.RichEntry(1, 2, 3)
    lief.logging.info(new_entry)
    rheader.add_entry(new_entry)
    assert rheader.entries[-1] == new_entry
    assert rheader.entries[-1].copy() == new_entry
    assert lief.PE.RichEntry() == lief.PE.RichEntry(0, 0, 0)


def test_relocations():
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    relocations = pe.relocations
    assert relocations[0].virtual_address == 0xD000
    assert relocations[0].block_size == 0xB8
    assert len(relocations[0].entries) == 88
    relocation = relocations[0]

    assert relocation.entries[46].size == 64
    assert relocation.entries[46].address == 0xDEB8
    assert relocation.entries[46].data == 0xAEB8
    assert relocation.entries[46].position == 0xEB8
    assert relocation.entries[46].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[25].data == 0xAE10
    assert relocation.entries[25].position == 0xE10
    assert relocation.entries[25].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[56].data == 0xAF08
    assert relocation.entries[56].position == 0xF08
    assert relocation.entries[56].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[75].data == 0xAFA0
    assert relocation.entries[75].position == 0xFA0
    assert relocation.entries[75].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64

    assert relocations[8].virtual_address == 0x15000
    assert relocations[8].block_size == 0xC0
    assert len(relocations[8].entries) == 92
    relocation = relocations[8]
    assert relocation.entries[87].data == 0xA9F8
    assert relocation.entries[87].position == 0x9F8
    assert relocation.entries[87].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[24].data == 0xA0C0
    assert relocation.entries[24].position == 0xC0
    assert relocation.entries[24].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[67].data == 0xA218
    assert relocation.entries[67].position == 0x218
    assert relocation.entries[67].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[54].data == 0xA1B0
    assert relocation.entries[54].position == 0x1B0
    assert relocation.entries[54].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64

    assert relocations[9].virtual_address == 0x1C000
    assert relocations[9].block_size == 0x80
    assert len(relocations[9].entries) == 60
    relocation = relocations[9]
    assert relocation.entries[40].data == 0xA628
    assert relocation.entries[40].position == 0x628
    assert relocation.entries[40].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[17].data == 0xA2D8
    assert relocation.entries[17].position == 0x2D8
    assert relocation.entries[17].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[36].data == 0xA5A0
    assert relocation.entries[36].position == 0x5A0
    assert relocation.entries[36].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64
    assert relocation.entries[52].data == 0xA7F8
    assert relocation.entries[52].position == 0x7F8
    assert relocation.entries[52].type == lief.PE.RelocationEntry.BASE_TYPES.DIR64

    r1 = lief.PE.RelocationEntry()
    r1.position = 0x123
    r1.type = lief.PE.RelocationEntry.BASE_TYPES.LOW

    assert r1.address == r1.position
    assert r1.size == 16

    r2 = lief.PE.RelocationEntry()
    r2.type = lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW
    assert r2.size == 32

    r3 = lief.PE.RelocationEntry()
    r3.type = lief.PE.RelocationEntry.BASE_TYPES.ABS
    assert r3.size == 0

    assert relocation.copy() == relocation

    # Coverage: str()/hash() on Relocation and RelocationEntry
    output = str(relocations[0])
    assert len(output) > 0
    assert hash(relocations[0]) != 0
    entry_str = str(relocations[0].entries[0])
    assert len(entry_str) > 0
    assert hash(relocations[0].entries[0]) != 0


def test_symbols():
    input_path = get_sample("PE/PE64_x86-64_binary_winhello64-mingw.exe")
    pe = lief.PE.parse(input_path)
    assert pe is not None
    symbols = pe.symbols
    assert len(symbols) == 1097

    assert symbols[0].name == ".file"
    assert symbols[0].value == 102
    assert symbols[0].section_idx == -2
    assert symbols[0].storage_class == lief.COFF.Symbol.STORAGE_CLASS.FILE
    assert len(symbols[0].auxiliary_symbols) == 1
    aux_sym = symbols[0].auxiliary_symbols[0]
    assert isinstance(aux_sym, lief.COFF.AuxiliaryFile)
    assert aux_sym.filename == "crtexe.c"

    assert len(symbols[0].auxiliary_symbols) == 1

    assert symbols[1].name == "__mingw_invalidParameterHandler"
    assert symbols[1].value == 0
    assert symbols[1].section_idx == 1
    assert symbols[1].storage_class == lief.COFF.Symbol.STORAGE_CLASS.STATIC
    assert symbols[1].complex_type == lief.COFF.Symbol.COMPLEX_TYPE.FUNCTION
    assert len(symbols[1].auxiliary_symbols) == 1
    aux_sym_1 = symbols[1].auxiliary_symbols[0]
    assert isinstance(aux_sym_1, lief.COFF.AuxiliarySectionDefinition)
    assert aux_sym_1.length == 0
    assert aux_sym_1.nb_relocs == 0
    assert aux_sym_1.nb_line_numbers == 0
    assert aux_sym_1.checksum == 0
    assert aux_sym_1.section_idx == 0
    assert (
        aux_sym_1.selection
        == lief.COFF.AuxiliarySectionDefinition.COMDAT_SELECTION.NONE
    )
    assert str(symbols[1]) == dedent("""\
    Symbol {
      Name: __mingw_invalidParameterHandler
      Value: 0
      Section index: 1
      Base type: NULL (0)
      Complex type: FUNCTION (2)
      Storage class: STATIC (3)
      Nb auxiliary symbols: 1
      AuxiliarySectionDefinition {
        Length: 0x000000
        Number of relocations: 0
        Number of line numbers: 0
        Checksum: 0x00000000
        Section index: 0
        Selection: NONE
        Reserved: 0
      }

    }
    """)

    assert symbols[3].name == ".rdata$.refptr.mingw_initltsdrot_force"
    aux_sym_3 = symbols[3].auxiliary_symbols[0]
    assert isinstance(aux_sym_3, lief.COFF.AuxiliarySectionDefinition)
    assert (
        aux_sym_3.selection == lief.COFF.AuxiliarySectionDefinition.COMDAT_SELECTION.ANY
    )

    assert symbols[317].name == "__mingw_SEH_error_handler"
    assert symbols[317].value == 4240
    assert symbols[317].section_idx == 1
    assert symbols[317].storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL
    assert symbols[317].complex_type == lief.COFF.Symbol.COMPLEX_TYPE.FUNCTION
    assert len(symbols[317].auxiliary_symbols) == 1
    assert isinstance(
        symbols[317].auxiliary_symbols[0], lief.COFF.AuxiliaryFunctionDefinition
    )
    assert symbols[317].auxiliary_symbols[0].tag_index == 0
    assert symbols[317].auxiliary_symbols[0].total_size == 0
    assert symbols[317].auxiliary_symbols[0].ptr_to_line_number == 0
    assert symbols[317].auxiliary_symbols[0].ptr_to_next_func == 0
    assert symbols[317].auxiliary_symbols[0].padding == 0
    assert str(symbols[317]) == dedent("""\
    Symbol {
      Name: __mingw_SEH_error_handler
      Value: 4240
      Section index: 1
      Base type: NULL (0)
      Complex type: FUNCTION (2)
      Storage class: EXTERNAL (2)
      Nb auxiliary symbols: 1
      AuxiliaryFunctionDefinition {
        Tag index: 0x000000
        Total size: 0x000000
        Pointer to line number: 0x000000
        Pointer to next function: 0
      }

    }
    """)

    assert symbols[1087].name == "_Jv_RegisterClasses"
    assert len(symbols[1087].auxiliary_symbols) == 1
    assert isinstance(
        symbols[1087].auxiliary_symbols[0], lief.COFF.AuxiliaryWeakExternal
    )
    assert symbols[1087].auxiliary_symbols[0].sym_idx == 21
    assert (
        symbols[1087].auxiliary_symbols[0].characteristics
        == lief.COFF.AuxiliaryWeakExternal.CHARACTERISTICS.SEARCH_NOLIBRARY
    )

    assert str(symbols[1087]) == dedent("""\
    Symbol {
      Name: _Jv_RegisterClasses
      Value: 0
      Section index: 0
      Base type: NULL (0)
      Complex type: FUNCTION (2)
      Storage class: EXTERNAL (2)
      Nb auxiliary symbols: 1
      AuxiliaryWeakExternal {
        Symbol index: 21
        Characteristics: SEARCH_NOLIBRARY (1)
      }

    }
    """)

    assert symbols[1096].name == "__security_cookie"
    assert symbols[1096].value == 128
    assert symbols[1096].section_idx == 2
    assert symbols[1096].storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL

    assert str(symbols[1096]) == dedent("""\
    Symbol {
      Name: __security_cookie
      Value: 128
      Section index: 2
      Base type: NULL (0)
      Complex type: NULL (0)
      Storage class: EXTERNAL (2)
      Nb auxiliary symbols: 0
    }
    """)


def test_coff_string_table():
    input_path = Path(get_sample("PE/PE64_x86-64_library_libLIEF.dll"))
    pe = lief.PE.parse(input_path)
    assert pe is not None

    assert len(pe.coff_string_table) == 24336
    assert pe.coff_string_table[0].offset == 4
    assert pe.coff_string_table[0].string == ".debug_aranges"

    assert pe.coff_string_table[24335].offset == 1516905
    assert pe.coff_string_table[24335].string == "_ZTISt9basic_iosIwSt11char_traitsIwEE"

    coff_str = pe.find_coff_string(1516905)
    assert coff_str is not None
    assert coff_str.string == "_ZTISt9basic_iosIwSt11char_traitsIwEE"

    assert pe.sections[0].coff_string is None
    coff_str_11 = pe.sections[11].coff_string
    assert coff_str_11 is not None
    assert coff_str_11.offset == 4
    assert coff_str_11.string == ".debug_aranges"


@pytest.mark.parametrize(
    "input_file",
    [
        "PE/PE64_x86-64_binary_winhello64-mingw.exe",
        "PE/PE32_x86_binary_KMSpico_setup_MALWARE.exe",
        "PE/PE64_x86-64_atapi.sys",
        "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
    ],
)
def test_checksum(input_file: str):
    pe = lief.PE.parse(get_sample(input_file))
    assert pe is not None
    assert pe.compute_checksum() == pe.optional_header.checksum


def test_config():
    config = lief.PE.ParserConfig()
    config.parse_signature = False
    config.parse_imports = False
    config.parse_rsrc = False
    config.parse_reloc = False

    fpath = get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe")
    avast = lief.PE.parse(fpath, config)
    assert avast is not None

    assert len(avast.imports) == 0
    assert len(avast.relocations) == 0
    assert len(avast.signatures) == 0
    assert avast.resources is None

    # Coverage: str() on ParserConfig
    output = str(config)
    assert len(output) > 0


def test_overlay():
    pe = parse_pe("PE/PE32_x86_binary_KMSpico_setup_MALWARE.exe")
    assert len(pe.overlay) == 3073728
    assert (
        hashlib.sha256(pe.overlay).hexdigest()
        == "01c0472ead112b44dca6996c9fae47e0d6870e61792ef606ea47067932115d01"
    )


def test_path_like():
    assert (
        lief.PE.parse(
            Path(
                get_sample(
                    "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"
                )
            )
        )
        is not None
    )


def test_issue_1049():
    pe = parse_pe("PE/issue_1049.exe")
    assert pe is not None


def test_xbox_file():
    pe = parse_pe("PE/backcompat.exe")
    assert pe.header.machine == lief.PE.Header.MACHINE_TYPES.POWERPCBE


def test_issue_1115():
    """
    Infinite loop in PE resource tree
    """
    pe = parse_pe("PE/issue_1115.pe")
    assert pe is not None


def test_large_ordinal():
    """
    Issue coming from Goblin project: goblin/issues/428
    """
    pe = parse_pe("PE/special_import_forwarder_tls.exe.bin")
    imp = pe.imports[0]
    assert imp.name == "abcd.dll"

    assert imp.entries[0].ordinal == 0xC8C6


def test_exceptions_x64():
    input_path = Path(get_sample("PE/LIEF-win64.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe is not None

    assert len(pe.exceptions) == 7066

    assert len(list(pe.exceptions)) == 7066

    for e in pe.exceptions:
        str(e)

    func: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x003B60)  # type: ignore

    info = func.unwind_info
    assert info is not None
    opcodes = info.opcodes
    assert len(opcodes) == 13

    op0 = opcodes[0]
    assert op0 is not None
    assert op0.opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.SAVE_XMM128
    assert isinstance(op0, lief.PE.unwind_x64.SaveXMM128)
    assert op0.num == 9
    assert op0.offset == 0xB0


def test_exceptions_x64_v2():
    """
    Some of these entries are using the v2 format
    """
    input_path = Path(get_sample("PE/hostfxr.dll"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe is not None

    assert len(pe.exceptions) == 1010

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x3A4C0)  # type: ignore
    assert v2 is not None
    assert isinstance(v2, lief.PE.RuntimeFunctionX64)

    assert v2.rva_start == 0x3A4C0
    assert v2.rva_end == 0x3A4D0
    assert v2.unwind_rva == 0x54700
    assert v2.size == 16

    info = v2.unwind_info
    assert info is not None
    assert info.version == 2
    assert info.flags == 0
    assert info.sizeof_prologue == 2
    assert info.count_opcodes == 4
    assert info.handler is None
    assert info.chained is None

    opcodes = info.opcodes
    assert len(opcodes) == 3

    assert opcodes[0].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.EPILOG
    assert isinstance(opcodes[0], lief.PE.unwind_x64.Epilog)
    assert opcodes[0].flags == 1
    assert opcodes[0].size == 3

    assert opcodes[1].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.PUSH_NONVOL
    assert isinstance(opcodes[1], lief.PE.unwind_x64.PushNonVol)
    assert opcodes[1].reg == lief.PE.RuntimeFunctionX64.UNWIND_REG.RSI

    assert opcodes[2].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.PUSH_NONVOL
    assert isinstance(opcodes[2], lief.PE.unwind_x64.PushNonVol)
    assert opcodes[2].reg == lief.PE.RuntimeFunctionX64.UNWIND_REG.RDI

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x3B814)  # type: ignore[no-redef]

    assert v2.unwind_info.version == 1
    opcodes = v2.unwind_info.opcodes
    assert len(opcodes) == 9
    assert v2.unwind_info.flags == 3
    assert v2.unwind_info.has(lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.EXCEPTION_HANDLER)
    assert v2.unwind_info.has(lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.TERMINATE_HANDLER)
    assert v2.unwind_info.has(
        lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.TERMINATE_HANDLER
        | lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.TERMINATE_HANDLER
    )

    assert v2.unwind_info.handler == 0x00039298

    assert opcodes[0].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.ALLOC_LARGE
    assert isinstance(opcodes[0], lief.PE.unwind_x64.Alloc)
    assert opcodes[0].size == 0x188

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x3C140)  # type: ignore[no-redef]

    opcodes = v2.unwind_info.opcodes

    assert opcodes[0].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.SAVE_NONVOL
    assert isinstance(opcodes[0], lief.PE.unwind_x64.SaveNonVolatile)
    assert opcodes[0].reg == lief.PE.RuntimeFunctionX64.UNWIND_REG.RDI
    assert opcodes[0].offset == 0x48

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x1000)  # type: ignore[no-redef]

    opcodes = v2.unwind_info.opcodes

    assert opcodes[0].opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.ALLOC_SMALL
    assert isinstance(opcodes[0], lief.PE.unwind_x64.Alloc)
    assert opcodes[0].size == 0x28

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x38450)  # type: ignore[no-redef]
    assert v2.unwind_info.frame_reg == lief.PE.RuntimeFunctionX64.UNWIND_REG.RBP.value

    v2: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x2E8E)  # type: ignore[no-redef]
    assert v2.unwind_info.chained is not None
    assert v2.unwind_info.has(lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.CHAIN_INFO)
    assert v2.unwind_info.chained.rva_start == 0x2E70
    assert v2.unwind_info.chained.rva_end == 0x2E8E
    assert v2.unwind_info.chained.unwind_rva == 0x4F3D0

    assert v2.unwind_info.opcodes[0].offset == 0x30


@pytest.mark.private
def test_exceptions_x64_llvm():
    input_path = Path(get_sample("private/PE/lief-ld-link.pyd"))

    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe is not None

    func: lief.PE.RuntimeFunctionX64 = pe.exceptions[0]  # type: ignore
    assert func.rva_start == 0x001000

    func_info = func.unwind_info
    assert func_info is not None
    func_op0 = func_info.opcodes[0]
    assert func_op0 is not None
    assert func_op0.opcode == lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.SET_FPREG
    assert isinstance(func_op0, lief.PE.unwind_x64.SetFPReg)
    assert func_op0.reg == lief.PE.RuntimeFunctionX64.UNWIND_REG.RBP


@pytest.mark.private
def test_exceptions_x64_corrupted():
    input_path = Path(get_sample("private/PE/vgc.exe"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe is not None
    assert len(pe.exceptions) == 15426

    for e in pe.exceptions:
        assert str(e)


def test_exceptions_ahead_chained():
    input_path = Path(get_sample("PE/ntoskrnl.exe"))
    pe = lief.PE.parse(input_path, lief.PE.ParserConfig.all)
    assert pe is not None

    assert len(pe.exceptions) == 38926

    func: lief.PE.RuntimeFunctionX64 = pe.find_exception_at(0x20FCB4)  # type: ignore
    func_info = func.unwind_info
    assert func_info is not None
    assert func_info.chained is not None
    assert func_info.chained.rva_start == 0x20FD87


def test_exceptions_arm64x():
    input_path = Path(
        get_sample("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll")
    )
    pe = lief.PE.parse(input_path)
    assert pe is not None
    assert pe.is_arm64x


def test_chpe_x86():
    input_path = Path(get_sample("PE/Windows.Media.dll"))
    pe = lief.PE.parse(input_path)

    metadata: lief.PE.CHPEMetadataX86 = pe.load_configuration.chpe_metadata  # type: ignore
    assert metadata is not None
    assert isinstance(metadata, lief.PE.CHPEMetadataX86)
    assert metadata.chpe_code_address_range_offset == 0x10C8F0
    assert metadata.chpe_code_address_range_count == 4
    assert metadata.wowa64_exception_handler_function_pointer == 0x73A00C
    assert metadata.wowa64_dispatch_call_function_pointer == 0x73A000
    assert metadata.wowa64_dispatch_indirect_call_function_pointer == 0x73A004
    assert metadata.wowa64_dispatch_indirect_call_cfg_function_pointer == 0x73A008
    assert metadata.wowa64_dispatch_ret_function_pointer == 0x73A010
    assert metadata.wowa64_dispatch_ret_leaf_function_pointer == 0x73A014
    assert metadata.wowa64_dispatch_jump_function_pointer == 0x73A018
    assert metadata.compiler_iat_pointer is None
    assert metadata.wowa64_rdtsc_function_pointer is None

    assert (
        str(metadata)
        == """\
                  4 Version
           0x73a00c WowA64 exception handler function pointer
           0x73a000 WowA64 dispatch call function pointer
           0x73a004 WowA64 dispatch indirect call function pointer
           0x73a008 WowA64 dispatch indirect call function pointer (with CFG check)
           0x73a010 WowA64 dispatch return function pointer
           0x73a014 WowA64 dispatch leaf return function pointer
           0x73a018 WowA64 dispatch jump function pointer
      0x10c8f0[0x4] Hybrid code address range"""
    )


@pytest.mark.private
@pytest.mark.slow
def test_issue_iat_hang():
    target_pe = Path(get_sample("private/PE/lief_hang_poc.exe")).resolve().absolute()

    subprocess.check_call(
        [sys.executable, "-c", f'import lief; lief.parse("{target_pe}")'], timeout=10.0
    )
