# -*- coding: utf-8 -*-
import ctypes
import json
import os
import stat
from pathlib import Path

import lief
import pytest
from utils import get_sample, is_windows, parse_pe, win_exec

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)  # type: ignore


def test_remove_section(tmp_path: Path):
    path = get_sample("PE/PE64_x86-64_remove_section.exe")
    sample = lief.parse(path)
    assert isinstance(sample, lief.PE.Binary)

    output = tmp_path / "section_removed.exe"

    sample.remove_section("lief")
    sample.write(output)

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output, gui=False):
        ret_code, stdout = ret
        assert "Hello World" in stdout


def test_unwind():

    path = get_sample("PE/PE64_x86-64_binary_cmd.exe")
    sample = lief.PE.parse(path, lief.PE.ParserConfig.all)
    assert sample is not None

    assert sample.original_size == Path(path).stat().st_size

    functions = sorted(sample.functions, key=lambda f: f.address)

    assert len(functions) == 829

    assert functions[0].address == 4160
    assert functions[0].size == 107
    assert functions[0].name == ""

    assert functions[-1].address == 163896
    assert functions[-1].size == 54
    assert functions[-1].name == ""


def test_sections():
    path = get_sample("PE/PE32_x86_binary_PGO-LTCG.exe")
    pe = lief.parse(path)
    assert isinstance(pe, lief.PE.Binary)
    assert pe.get_section(".text") is not None
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].fullname == b".text\x00\x00\x00"
    text = pe.sections[0]
    assert isinstance(text, lief.PE.Section)
    assert text.copy() == text
    text.name = ".foo"
    assert text.name == ".foo"
    lief.logging.info(text)


def test_utils():
    assert (
        lief.PE.get_type(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"))
        == lief.PE.PE_TYPE.PE32
    )
    assert (
        lief.PE.get_type(get_sample("ELF/ELF_Core_issue_808.core"))
        == lief.lief_errors.file_format_error
    )

    with open(get_sample("PE/PE32_x86_binary_PGO-LTCG.exe"), "rb") as f:
        buffer = list(f.read())
        assert lief.PE.get_type(buffer) == lief.PE.PE_TYPE.PE32


@pytest.mark.parametrize(
    "pe_file",
    [
        "PE/AcRes.dll",
        "PE/test.delay.exe",
        "PE/AppVClient.exe",
    ],
)
def test_json(pe_file):
    pe = lief.PE.parse(get_sample(pe_file))
    assert pe is not None
    out = lief.to_json(pe)
    assert out is not None
    assert len(out) > 0
    assert json.loads(out) is not None


def test_resolve_function():
    config = lief.PE.ParserConfig()
    config.parse_arm64x_binary = True
    pe = parse_pe("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll", config)
    assert pe is not None
    assert pe.get_function_address("BootstrapReleaseUnusedResources") == 0x00155C70

    nested = pe.nested_pe_binary
    assert nested is not None
    assert nested.get_function_address("BootstrapReleaseUnusedResources") == 0x00002000

    pe = parse_pe("PE/PE32_x86_binary_winhello-mingw.exe")
    assert pe.get_function_address("WinMainCRTStartup") == 0x4C0


def test_code_integrity_str():
    pe = parse_pe("PE/PE64_x86-64_binary_WinApp.exe")
    assert pe is not None
    assert pe.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF)
    load_config = pe.load_configuration
    assert load_config is not None
    ci = load_config.code_integrity
    assert ci is not None
    output = str(ci)
    assert len(output) > 0


def test_debug_entries_str():
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None
    for entry in pe.debug:
        output = str(entry)
        assert len(output) > 0
        assert hash(entry) != 0


def test_header_str():
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None
    output = str(pe.header)
    assert len(output) > 0
    assert hash(pe.header) != 0
    output = str(pe.optional_header)
    assert len(output) > 0
    assert hash(pe.optional_header) != 0


def test_binary_print():
    """Call str() on full PE binaries to cover Binary::print() branches."""
    # Binary with imports, relocations, debug, resources
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None
    output = str(pe)
    assert "DOS Header" in output
    assert "Header" in output
    assert "Section" in output
    assert "Import" in output

    # Binary with exports
    pe2 = parse_pe(
        "PE/24e3ea78835748c9995e0d0c64f4f6bd3a0ca1b495b61a601703eb19b8c27f95.pe"
    )
    assert pe2 is not None
    output2 = str(pe2)
    assert len(output2) > 0

    # Binary with delay imports
    pe3 = parse_pe("PE/test.delay.exe")
    assert pe3 is not None
    output3 = str(pe3)
    assert "Delay" in output3

    # Binary with TLS
    pe4 = parse_pe("PE/PE64_x86-64_binary_winhello64-mingw.exe")
    assert pe4 is not None
    output4 = str(pe4)
    assert "TLS" in output4

    # Binary with signatures
    pe5 = parse_pe("PE/PE32_x86_binary_KMSpico_setup_MALWARE.exe")
    assert pe5 is not None
    output5 = str(pe5)
    assert "Signature" in output5

    # Binary with COFF symbols
    pe6 = parse_pe("PE/PE64_x86-64_binary_winhello64-mingw.exe")
    assert pe6 is not None
    output6 = str(pe6)
    assert "Symbol" in output6

    # Binary with exceptions/unwind info
    exc_config = lief.PE.ParserConfig()
    exc_config.parse_exceptions = True
    pe7 = parse_pe("PE/PE64_x86-64_binary_ConsoleApplication1.exe", exc_config)
    assert pe7 is not None
    output7 = str(pe7)
    assert "Unwind" in output7

    # Binary with nested PE (arm64x)
    config = lief.PE.ParserConfig()
    config.parse_arm64x_binary = True
    pe8 = parse_pe("PE/win11_arm64x_Windows.Media.Protection.PlayReady.dll", config)
    assert pe8 is not None
    output8 = str(pe8)
    assert "Nested" in output8


def test_binary_misc_methods():
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None

    # verify_signature on unsigned binary
    flags = pe.verify_signature()
    assert flags == lief.PE.Signature.VERIFICATION_FLAGS.NO_SIGNATURE

    # remove_import on non-existent import
    assert not pe.remove_import("DOES_NOT_EXIST.dll")

    # remove_section on non-existent section
    pe.remove_section("DOES_NOT_EXIST")

    # find_exception_at with non-existent RVA
    assert pe.find_exception_at(0xDEADBEEF) is None

    # get_delay_import on non-existent import
    assert pe.get_delay_import("DOES_NOT_EXIST.dll") is None

    # remove_all_relocations
    nb_relocs_before = len(pe.relocations)

    assert nb_relocs_before > 0

    pe.remove_all_relocations()
    assert len(pe.relocations) == 0

    # patch_address with various sizes
    text = pe.get_section(".text")
    if text is not None and text.virtual_size > 16:
        rva = text.virtual_address
        pe.patch_address(rva, 0x42, 1)
        pe.patch_address(rva, 0x4242, 2)
        pe.patch_address(rva, 0x42424242, 4)
        pe.patch_address(rva, 0x4242424242424242, 8)

    # rich_header setter
    rh = pe.rich_header
    if rh is not None:
        pe.rich_header = rh


def test_header_setters():
    """Exercise setter methods on PE headers to cover inline setters."""
    pe = parse_pe("PE/PE64_x86-64_binary_mfc-application.exe")
    assert pe is not None

    # DosHeader setters
    dos = pe.dos_header
    dos.numberof_relocation = dos.numberof_relocation
    dos.minimum_extra_paragraphs = dos.minimum_extra_paragraphs
    dos.maximum_extra_paragraphs = dos.maximum_extra_paragraphs
    dos.initial_relative_ss = dos.initial_relative_ss
    dos.initial_sp = dos.initial_sp
    dos.checksum = dos.checksum
    dos.initial_ip = dos.initial_ip
    dos.initial_relative_cs = dos.initial_relative_cs
    dos.addressof_relocation_table = dos.addressof_relocation_table
    dos.overlay_number = dos.overlay_number
    dos.oem_id = dos.oem_id
    dos.oem_info = dos.oem_info

    # Header setters
    hdr = pe.header
    hdr.machine = hdr.machine
    hdr.numberof_sections = hdr.numberof_sections
    hdr.time_date_stamps = hdr.time_date_stamps
    hdr.pointerto_symbol_table = hdr.pointerto_symbol_table
    hdr.numberof_symbols = hdr.numberof_symbols
    hdr.sizeof_optional_header = hdr.sizeof_optional_header
    hdr.characteristics = hdr.characteristics

    # OptionalHeader setters
    opt = pe.optional_header
    opt.magic = opt.magic
    opt.major_linker_version = opt.major_linker_version
    opt.minor_linker_version = opt.minor_linker_version
    opt.sizeof_code = opt.sizeof_code
    opt.sizeof_initialized_data = opt.sizeof_initialized_data
    opt.sizeof_uninitialized_data = opt.sizeof_uninitialized_data
    opt.addressof_entrypoint = opt.addressof_entrypoint
    opt.baseof_code = opt.baseof_code
    opt.imagebase = opt.imagebase
    opt.section_alignment = opt.section_alignment
    opt.file_alignment = opt.file_alignment
    opt.major_operating_system_version = opt.major_operating_system_version
    opt.minor_operating_system_version = opt.minor_operating_system_version
    opt.major_image_version = opt.major_image_version
    opt.minor_image_version = opt.minor_image_version
    opt.major_subsystem_version = opt.major_subsystem_version
    opt.minor_subsystem_version = opt.minor_subsystem_version
    opt.win32_version_value = opt.win32_version_value
    opt.sizeof_image = opt.sizeof_image
    opt.sizeof_headers = opt.sizeof_headers
    opt.checksum = opt.checksum
    opt.subsystem = opt.subsystem
    opt.dll_characteristics = opt.dll_characteristics
    opt.sizeof_stack_reserve = opt.sizeof_stack_reserve
    opt.sizeof_stack_commit = opt.sizeof_stack_commit
    opt.sizeof_heap_reserve = opt.sizeof_heap_reserve
    opt.sizeof_heap_commit = opt.sizeof_heap_commit
    opt.loader_flags = opt.loader_flags
    opt.numberof_rva_and_size = opt.numberof_rva_and_size


def test_export_setters():
    """Exercise setter methods on Export/ExportEntry."""
    pe = parse_pe(
        "PE/24e3ea78835748c9995e0d0c64f4f6bd3a0ca1b495b61a601703eb19b8c27f95.pe"
    )
    assert pe is not None
    exports = pe.get_export()
    assert exports is not None

    exports.export_flags = exports.export_flags
    exports.timestamp = exports.timestamp
    exports.major_version = exports.major_version
    exports.minor_version = exports.minor_version
    exports.ordinal_base = exports.ordinal_base
    exports.name = str(exports.name)

    entry = exports.entries[0]
    entry.name = str(entry.name)
    entry.ordinal = entry.ordinal
    entry.address = entry.address


def test_delay_import_setters():
    """Exercise setter methods on DelayImport."""
    pe = parse_pe("PE/test.delay.exe")
    assert pe is not None
    assert pe.has_delay_imports
    di = pe.delay_imports[0]

    di.attribute = di.attribute
    di.name = str(di.name)
    di.handle = di.handle
    di.iat = di.iat
    di.names_table = di.names_table
    di.biat = di.biat
    di.uiat = di.uiat
    di.timestamp = di.timestamp
