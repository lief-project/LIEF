import os
import pathlib
import random
import re
import shutil
import subprocess
from pathlib import Path
from subprocess import Popen
from typing import Any, cast

import lief
import pytest
from utils import (
    chmod_exe,
    get_sample,
    is_apple_m1,
    is_github_ci,
    is_osx,
    is_x86_64,
    parse_macho,
    sign,
)


def align_to(value, alignment):
    # llvm::alignTo
    assert (alignment & (alignment - 1)) == 0  # is power of two
    return (value + alignment - 1) & ~(alignment - 1)


def dyld_check(path: Path):
    dyld_info_path = Path("/usr/bin/dyld_info")
    if not dyld_info_path.exists():
        dyld_info_path = shutil.which("dyld_info")

    if dyld_info_path is None:
        return

    cmd = [str(dyld_info_path), "-validate_only", str(path)]
    kwargs: dict[str, Any] = {
        "universal_newlines": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
    }
    lief.logging.info("Running {}".format(" ".join(cmd)))
    with Popen(cmd, **kwargs) as proc:
        assert proc.stdout is not None
        lief.logging.info(proc.stdout.read())
        proc.poll()
        assert proc.returncode == 0, f"Return code: {proc.returncode}"


def run_program(path: Path, args=None):
    if is_apple_m1():
        sign(path)

    # Make sure the program has exec permission
    chmod_exe(path)
    dyld_check(path)

    env = os.environ
    env["DYLD_PRINT_APIS"] = "1"
    env["DYLD_PRINT_WARNINGS"] = "1"

    kwargs: dict[str, Any] = {
        "universal_newlines": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "env": env,
    }

    prog_args = path if args is None else [path] + args
    with Popen(prog_args, **kwargs) as proc:
        proc.poll()
        lief.logging.info(f"{path} exited with {proc.returncode}")
        assert proc.stdout is not None
        return proc.stdout.read()


def test_id(tmp_path: Path):
    original = parse_macho("MachO/MachO64_x86-64_binary_id.bin").at(0)
    assert original is not None
    output = tmp_path / "test_id.bin"
    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    modified = fat.at(0)
    assert modified is not None

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err


def test_add_command(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None

    output = tmp_path / "test_add_command.id.bin"

    LIB_NAME = "/usr/lib/libSystem.B.dylib"

    dylib_1 = lief.MachO.DylibCommand.lazy_load_dylib(LIB_NAME)
    dylib_2 = lief.MachO.DylibCommand.weak_lib(LIB_NAME)

    original.add(dylib_1)
    original.add(dylib_2, 0)

    original.remove_signature()

    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert len([lib for lib in new.libraries if lib.name == LIB_NAME]) > 0

    if is_osx() and is_x86_64():
        assert run_program(bin_path)

        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"uid=", stdout) is not None


def test_remove_cmd(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None

    output = tmp_path / "test_remove_cmd.id.bin"

    uuid_cmd = original[lief.MachO.LoadCommand.TYPE.UUID]
    assert uuid_cmd is not None
    original.remove(uuid_cmd)
    original.remove_command(len(original.commands) - 1)

    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert lief.MachO.LoadCommand.TYPE.UUID not in new
    assert lief.MachO.LoadCommand.TYPE.CODE_SIGNATURE not in new

    if is_osx() and is_x86_64():
        assert run_program(bin_path)

        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"uid=", stdout) is not None


def test_extend_cmd(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None

    output = tmp_path / "test_extend_cmd.id.bin"

    # Extend UUID
    uuid_cmd = original[lief.MachO.LoadCommand.TYPE.UUID]
    assert uuid_cmd is not None
    original_size = uuid_cmd.size
    original.extend(uuid_cmd, 0x4000)

    original.remove_signature()
    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    uuid_cmd_new = new[lief.MachO.LoadCommand.TYPE.UUID]
    assert uuid_cmd_new is not None
    assert uuid_cmd_new.size == original_size + 0x4000


def test_add_section_id(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_add_section_id.id.bin"

    checked, err = lief.MachO.check_layout(original)
    assert checked, err

    # Add 50 sections
    for i in range(50):
        section = lief.MachO.Section.create(f"__lief_{i}", [0x90] * 0x100)
        assert section is not None
        original.add_section(section)

    assert original.virtual_size % original.page_size == 0

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"uid=", stdout) is not None


def test_extend_section_1(tmp_path: Path):
    """This test calls add_section followed by extend_section repeatedly."""
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_extend_section.bin"

    text_segment = original.get_segment("__TEXT")
    assert text_segment is not None

    for i in range(9, -1, -1):
        section = lief.MachO.Section.create(f"__lief_{i}")
        assert section is not None
        section.alignment = i
        section = original.add_section(text_segment, section)
        assert section is not None
        assert original.extend_section(section, 1 << section.alignment)

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err


def test_extend_section_2(tmp_path: Path):
    """This test makes multiple calls to add_section, and then it
    extends each added section using extend_section.
    """
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_extend_section.bin"

    text_segment = original.get_segment("__TEXT")
    assert text_segment is not None

    sections = []
    for i in range(3):
        section = lief.MachO.Section.create(f"__lief_{i}")
        assert section is not None
        section.alignment = 2  # 2^2 == 4 bytes
        sections.append(original.add_section(text_segment, section))

    for section in sections:
        assert original.extend_section(section, 1000)

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err


@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_add_section_ssh(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_add_section_sshd.sshd.bin"
    page_size = original.page_size

    # Add 3 section into __TEXT
    __text = original.get_segment("__TEXT")
    assert __text is not None
    for i in range(3):
        section = lief.MachO.Section.create(f"__text_{i}")
        assert section is not None
        section.content = [0xC3] * 0x100  # type: ignore[assignment]
        original.add_section(__text, section)

    assert original.virtual_size % page_size == 0
    assert __text.virtual_size % page_size == 0

    original.remove_signature()
    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx() and is_x86_64():
        assert run_program(bin_path, args=["--help"])
        stdout = run_program(output, args=["--help"])

        lief.logging.info(stdout)
        assert re.search(r"OpenSSH_6.9p1, LibreSSL 2.1.8", stdout) is not None


def test_add_segment_nm(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_nm.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_add_segment_nm.nm.bin"

    # Add segment without section
    segment = lief.MachO.SegmentCommand("__LIEF", [0x60] * 0x100)
    original.add(segment)

    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output, ["-version"])
        lief.logging.info(stdout)
        assert re.search(r"Default target:", stdout) is not None


def test_add_segment_all(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "test_add_segment_all.all.bin"

    # Add segment with sections
    segment = lief.MachO.SegmentCommand("__LIEF_2")
    for i in range(5):
        section = lief.MachO.Section.create(f"__lief_2_{i}", [i] * 0x100)
        assert section is not None
        segment.add_section(section)
    original.add(segment)

    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output)
        lief.logging.info(stdout)
        assert re.search(r"Hello World: 1", stdout) is not None


@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_ssh_segments(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / "ssh_with_segments.bin"

    # Add segment with sections
    for i in range(10):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        original.add(segment)

    original.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert len(new.segments) == len(original.segments)

    if is_osx() and is_x86_64():
        assert run_program(bin_path, args=["--help"])
        stdout = run_program(output, args=["--help"])

        lief.logging.info(stdout)
        assert re.search(r"OpenSSH_6.9p1, LibreSSL 2.1.8", stdout) is not None


def test_remove_section(tmp_path: Path):
    bin_path = pathlib.Path(
        get_sample("MachO/MachO64_x86-64_binary_section_to_remove.bin")
    )
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name

    original.remove_section("__to_remove")

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_section("__to_remove") is None

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Hello World", stdout) is not None


def test_remove_section_with_segment_name(tmp_path: Path):
    bin_path = pathlib.Path(
        get_sample("MachO/MachO64_x86-64_binary_section_to_remove.bin")
    )
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name

    original.remove_section("__DATA", "__to_remove")

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_section("__DATA", "__to_remove") is None

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Hello World", stdout) is not None


def test_objc_arm64(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/test_objc_arm64.macho"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name

    for i in range(50):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        original.add(segment)

    # Extend the symbols table
    for i in range(10):
        sym = f"_foooo_{i}"
        original.add_exported_function(original.imagebase + i * 8, sym)

        sym = f"_foooo2_{i}"
        original.add_local_symbol(original.entrypoint + i * 8, sym)

    fstarts = original.function_starts
    assert fstarts is not None
    functions = fstarts.functions
    functions *= 2
    sorted(functions)
    fstarts.functions = functions

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Printing Process Completed", stdout) is not None


def test_objc_x86_64(tmp_path: Path):
    bin_path = pathlib.Path(get_sample("MachO/test_objc_x86_64.macho"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    original = fat.at(0)
    assert original is not None
    output = tmp_path / bin_path.name

    for i in range(50):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        original.add(segment)

    # Extend the symbols table
    for i in range(10):
        sym = f"_foooo_{i}"
        original.add_exported_function(original.imagebase + i * 8, sym)

        sym = f"_foooo2_{i}"
        original.add_local_symbol(original.entrypoint + i * 8, sym)

    fstarts = original.function_starts
    assert fstarts is not None
    functions = fstarts.functions
    functions *= 2
    sorted(functions)
    fstarts.functions = functions

    original.write(output)
    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx() and is_x86_64():
        assert run_program(bin_path)
        stdout = run_program(output)

        lief.logging.info(stdout)
        assert re.search(r"Printing Process Completed", stdout) is not None


def test_break(tmp_path: Path):
    FILES = ["MachO/mbedtls_selftest_arm64.bin", "MachO/mbedtls_selftest_x86_64.bin"]

    def swap(target: lief.MachO.Binary, lhs: str, rhs: str):
        lhs_sec = target.get_section(lhs)
        if lhs_sec is None:
            lief.logging.info(f"Can't find section '{lhs_sec}'")
            return
        rhs_sec = target.get_section(rhs)
        if rhs_sec is None:
            lief.logging.info(f"Can't find section '{rhs_sec}'")
            return

        tmp = cast(str, lhs_sec.name)
        rhs_sec.name = tmp

    def shuffle(target: lief.MachO.Binary, name: str):
        section = target.get_section(name)
        if section is None:
            return
        lief.logging.info(f"[+] Shuffling '{name}'")
        section_content = list(section.content)
        random.shuffle(section_content)
        section.content = section_content  # type: ignore[assignment]

    def corrupt_function_starts(target: lief.MachO.Binary):
        fstart = target[lief.MachO.LoadCommand.TYPE.FUNCTION_STARTS]
        assert isinstance(fstart, lief.MachO.FunctionStarts)
        if fstart is None:
            return
        fstart.functions = [f + 5 for f in fstart.functions]

    def process_exports(target: lief.MachO.Binary, sym: lief.MachO.Symbol):
        # print(sym.export_info.address)
        export_info = sym.export_info
        assert export_info is not None
        export_sym = export_info.symbol
        assert export_sym is not None
        original_name = export_sym.name
        assert isinstance(original_name, str)
        name = list(original_name)
        random.shuffle(name)
        new_name = "_" + "".join(name)
        address = export_info.address
        target.add_local_symbol(address, new_name)

    def process_imports(target: lief.MachO.Binary, sym: lief.MachO.Symbol):
        binding_info = sym.binding_info
        assert binding_info is not None
        binding_sym = binding_info.symbol
        assert binding_sym is not None
        original_name = binding_sym.name
        assert isinstance(original_name, str)
        name = list(original_name)
        random.shuffle(name)
        new_name = "_" + "".join(name)
        address = binding_info.address - target.imagebase
        target.add_local_symbol(address, new_name)

    def process_local_symbol(target: lief.MachO.Binary, sym: lief.MachO.Symbol):
        original_name = sym.name
        assert isinstance(original_name, str)
        name = list(sym.name)
        random.shuffle(name)
        sym.name = "_" + "".join(name)
        sym.raw_type = 0xF
        sym.description = 0x300
        sym.numberof_sections = 1
        sym.value += 2

    def process_symbols(target: lief.MachO.Binary):
        exports = []
        imports = []
        for sym in target.symbols:
            if sym.has_export_info:
                # print(f"[EXPORT]: {sym.name}")
                exports.append(sym)
            elif sym.has_binding_info:
                # print(f"[IMPORT]: {sym.name}")
                imports.append(sym)
            else:
                # "classical" symbol
                process_local_symbol(target, sym)

        for sym in exports:
            process_exports(target, sym)

        for sym in imports:
            process_imports(target, sym)

    def fake_objc(target: lief.MachO.Binary):
        segment = lief.MachO.SegmentCommand("__DATA_LIEF")

        __objc_classlist = lief.MachO.Section.create(
            "__objc_classlist", [random.randint(0, 255) for _ in range(0x100)]
        )
        assert __objc_classlist is not None
        __objc_const = lief.MachO.Section.create(
            "__objc_const", [random.randint(0, 255) for _ in range(0x100)]
        )
        assert __objc_const is not None
        __objc_classrefs = lief.MachO.Section.create(
            "__objc_classrefs", [random.randint(0, 255) for _ in range(0x100)]
        )
        assert __objc_classrefs is not None

        __objc_classlist = segment.add_section(__objc_classlist)
        __objc_const = segment.add_section(__objc_const)
        __objc_classrefs = segment.add_section(__objc_classrefs)

        objc_section = [__objc_classlist, __objc_const, __objc_classrefs]
        for section in objc_section:
            section.type = lief.MachO.Section.TYPE.REGULAR
            section.flags = int(lief.MachO.Section.FLAGS.NO_DEAD_STRIP)
            section.alignment = 0x3

        __data_lief = cast(lief.MachO.SegmentCommand, target.add(segment))
        __data_lief.init_protection = 3
        __data_lief.max_protection = 3

    for file in FILES:
        bin_path = pathlib.Path(get_sample(file))
        fat = lief.MachO.parse(bin_path)
        assert fat is not None
        original = fat.at(0)
        assert original is not None
        output = tmp_path / bin_path.name

        SWAP_LIST = [
            ("__text", "__stubs"),
            ("__cstring", "__unwind_info"),
        ]
        for lhs, rhs in SWAP_LIST:
            swap(original, lhs, rhs)

        process_symbols(original)
        fake_objc(original)
        corrupt_function_starts(original)

        original.write(output)
        fat = lief.MachO.parse(output)
        assert fat is not None
        new = fat.at(0)
        assert new is not None

        checked, err = lief.MachO.check_layout(new)
        assert checked, err
        should_run = (
            original.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64 and is_osx()
        ) or (
            original.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64
            and is_apple_m1()
        )

        if should_run:
            assert run_program(bin_path)
            stdout = run_program(output)

            lief.logging.info(stdout)
            assert re.search(r"All tests PASS", stdout) is not None


def test_issue_726(tmp_path: Path):
    for filename in (
        "MachO/mbedtls_selftest_arm64.bin",
        "MachO/mbedtls_selftest_x86_64.bin",
    ):
        bin_path = pathlib.Path(get_sample(filename))
        fat = lief.MachO.parse(bin_path)
        assert fat is not None
        original = fat.at(0)
        assert original is not None
        output = tmp_path / bin_path.name

        original.write(output)
        fat = lief.MachO.parse(output)
        assert fat is not None
        new = fat.at(0)
        assert new is not None

        for parsed in (original, new):
            linkedit = parsed.get_segment("__LINKEDIT")
            assert linkedit is not None
            assert linkedit.virtual_size % parsed.page_size == 0


def test_rpath(tmp_path: Path):
    # c.f. https://github.com/lief-project/LIEF/issues/1074
    macho = parse_macho("MachO/rpath_291.bin").at(0)
    assert macho is not None
    rpaths = list(macho.rpaths)

    assert rpaths[0].path == "/tmp"
    assert rpaths[1].path == "/var"

    rpaths[0].path = "/foo"
    rpaths[1].path = "/bar"

    output = tmp_path / "rpath.bin"

    macho.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None

    new_rpaths = list(new.rpaths)
    assert new_rpaths[0].path == "/foo"
    assert new_rpaths[1].path == "/bar"


def test_encryption_info(tmp_path: Path):
    # c.f. https://github.com/lief-project/LIEF/issues/1173
    macho = parse_macho("MachO/RNCryptor.bin").at(0)
    assert macho is not None
    enc_info = macho.encryption_info
    assert enc_info is not None
    assert enc_info.crypt_offset != 0
    enc_info.crypt_offset = 0
    enc_info.crypt_size = 0
    enc_info.crypt_id = 0

    output = tmp_path / "new.macho"
    macho.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    new_enc_info = new.encryption_info
    assert new_enc_info is not None
    assert new_enc_info.crypt_id == 0
    assert new_enc_info.crypt_size == 0
    assert new_enc_info.crypt_offset == 0


def test_issue_1206(tmp_path: Path):
    # c.f. https://github.com/lief-project/LIEF/issues/1206
    # c.f. https://github.com/lief-project/LIEF/issues/1173
    macho = parse_macho("MachO/issue_1206.bin").at(0)
    assert macho is not None

    output = tmp_path / "new.macho"
    macho.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    assert lief.MachO.check_layout(new)[0]


def test_issue_1204(tmp_path: Path):
    macho = parse_macho("MachO/lief-dwarf-plugin-darwin-arm64.dylib").at(0)
    assert macho is not None
    rpath_cmd = macho.rpath
    assert rpath_cmd is not None
    rpath_cmd.path += "/a/very/long/path/that/needs/expansion"
    out = tmp_path / "out.macho"
    macho.write(out)

    fat = lief.MachO.parse(out)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    lief.MachO.check_layout(new)
    new_rpath = new.rpath
    assert new_rpath is not None
    assert new_rpath.path == "@loader_path/../a/very/long/path/that/needs/expansion"

    macho = parse_macho("MachO/lief-dwarf-plugin-darwin-arm64.dylib").at(0)
    assert macho is not None
    rpath_cmd = macho.rpath
    assert rpath_cmd is not None
    rpath_cmd.path += "/a/very/long/path/that/needs/expansion/" + "a" * (
        macho.available_command_space + 10
    )
    rpath = rpath_cmd.path
    out = tmp_path / "out2.macho"
    macho.write(out)

    fat = lief.MachO.parse(out)
    assert fat is not None
    new = fat.at(0)
    assert new is not None
    lief.MachO.check_layout(new)
    new_rpath = new.rpath
    assert new_rpath is not None
    assert new_rpath.path == rpath


def test_issue_1236(tmp_path: Path):
    macho = parse_macho("MachO/libmamba.4.0.1.dylib").at(0)
    assert macho is not None

    checked, err = lief.MachO.check_layout(macho)
    assert checked, err

    for cmd in macho.commands:
        if isinstance(cmd, lief.MachO.DylibCommand):
            cmd.name = "/Users/random" + cmd.name

    output = tmp_path / "out.macho"
    macho.write(output)
    new = lief.MachO.parse(output)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err
