#!/usr/bin/env python
import re
import shutil
import subprocess
import pathlib
import os
import pytest
import random
from subprocess import Popen

import lief
from utils import get_sample, is_apple_m1, is_osx, sign, chmod_exe, is_github_ci

lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

def dyld_check(path: str):
    dyld_info_path = "/usr/bin/dyld_info"
    if not pathlib.Path(dyld_info_path).exists():
        dyld_info_path = shutil.which("dyld_info")

    if dyld_info_path is None:
        return

    cmd = [
        dyld_info_path,
        "-validate_only",
        path
    ]
    kwargs = {
        "universal_newlines": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT
    }
    print("Running {}".format(" ".join(cmd)))
    with Popen(cmd, **kwargs) as proc:
        print(proc.stdout.read())
        proc.poll()
        assert proc.returncode == 0, f"Return code: {proc.returncode}"

def run_program(path, args=None):
    if is_apple_m1():
        sign(path)

    # Make sure the program has exec permission
    chmod_exe(path)
    dyld_check(path)

    env = os.environ
    env["DYLD_PRINT_APIS"] = "1"
    env["DYLD_PRINT_WARNINGS"] = "1"

    kwargs = {
        "universal_newlines": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "env": env,
    }

    prog_args = path if args is None else [path] + args
    with Popen(prog_args, **kwargs) as proc:
        proc.poll()
        print(f"{path} exited with {proc.returncode}")
        return proc.stdout.read()

def test_id(tmp_path):
    original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    output = f"{tmp_path}/test_id.bin"
    original.write(output)
    modified = lief.parse(output)

    checked, err = lief.MachO.check_layout(modified)
    assert checked, err


def test_add_command(tmp_path):
    bin_path = pathlib.Path(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    original = lief.parse(bin_path.as_posix())

    output = f"{tmp_path}/test_add_command.id.bin"

    LIB_NAME = "/usr/lib/libSystem.B.dylib"

    dylib_1 = lief.MachO.DylibCommand.lazy_load_dylib(LIB_NAME)
    dylib_2 = lief.MachO.DylibCommand.weak_lib(LIB_NAME)

    original.add(dylib_1)
    original.add(dylib_2, 0)

    original.remove_signature()

    original.write(output)

    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert len([l for l in new.libraries if l.name == LIB_NAME]) > 0

    if is_osx():
        assert run_program(bin_path.as_posix())

        stdout = run_program(output)
        print(stdout)
        assert re.search(r'uid=', stdout) is not None


def test_remove_cmd(tmp_path):
    bin_path = pathlib.Path(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
    original = lief.parse(bin_path.as_posix())

    output = f"{tmp_path}/test_remove_cmd.id.bin"

    uuid_cmd = original[lief.MachO.LOAD_COMMAND_TYPES.UUID]
    original.remove(uuid_cmd)
    original.remove_command(len(original.commands) - 1)


    original.write(output)

    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert lief.MachO.LOAD_COMMAND_TYPES.UUID not in new
    assert lief.MachO.LOAD_COMMAND_TYPES.CODE_SIGNATURE not in new

    if is_osx():
        assert run_program(bin_path.as_posix())

        stdout = run_program(output)
        print(stdout)
        assert re.search(r'uid=', stdout) is not None

def test_extend_cmd(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    original = lief.parse(bin_path.as_posix())

    output = f"{tmp_path}/test_extend_cmd.id.bin"

    # Extend UUID
    uuid_cmd = original[lief.MachO.LOAD_COMMAND_TYPES.UUID]
    original_size = uuid_cmd.size
    original.extend(uuid_cmd, 0x4000)

    original.remove_signature()
    original.write(output)

    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new[lief.MachO.LOAD_COMMAND_TYPES.UUID].size == original_size + 0x4000

def test_add_section_id(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_id.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/test_add_section_id.id.bin"

    # Add 50 sections
    for i in range(50):
        section = lief.MachO.Section(f"__lief_{i}", [0x90] * 0x100)
        original.add_section(section)

    assert original.virtual_size % original.page_size == 0

    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'uid=', stdout) is not None

@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_add_section_ssh(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/test_add_section_sshd.sshd.bin"
    page_size = original.page_size

    # Add 3 section into __TEXT
    __text = original.get_segment("__TEXT")
    for i in range(3):
        section = lief.MachO.Section(f"__text_{i}")
        section.content = [0xC3] * 0x100
        original.add_section(__text, section)

    assert original.virtual_size % page_size == 0
    assert __text.virtual_size % page_size == 0

    original.remove_signature()
    original.write(output)

    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix(), args=["--help"])
        stdout = run_program(output, args=["--help"])

        print(stdout)
        assert re.search(r'OpenSSH_6.9p1, LibreSSL 2.1.8', stdout) is not None


def test_add_segment_nm(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_nm.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/test_add_segment_nm.nm.bin"

    # Add segment without section
    segment = lief.MachO.SegmentCommand("__LIEF", [0x60] * 0x100)
    segment = original.add(segment)

    original.write(output)

    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output, ["-version"])
        print(stdout)
        assert re.search(r'Default target:', stdout) is not None

def test_add_segment_all(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_all.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/test_add_segment_all.all.bin"

    # Add segment with sections
    segment = lief.MachO.SegmentCommand("__LIEF_2")
    for i in range(5):
        section = lief.MachO.Section(f"__lief_2_{i}", [i] * 0x100)
        segment.add_section(section)
    segment = original.add(segment)

    original.write(output)

    new = lief.parse(output)
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)
        print(stdout)
        assert re.search(r'Hello World: 1', stdout) is not None

@pytest.mark.skipif(is_github_ci(), reason="sshd does not work on Github Action")
def test_ssh_segments(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_sshd.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/ssh_with_segments.bin"

    # Add segment with sections
    for i in range(10):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        segment = original.add(segment)

    original.write(output)

    new = lief.parse(output)
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert len(new.segments) == len(original.segments)

    if is_osx():
        assert run_program(bin_path.as_posix(), args=["--help"])
        stdout = run_program(output, args=["--help"])

        print(stdout)
        assert re.search(r'OpenSSH_6.9p1, LibreSSL 2.1.8', stdout) is not None

def test_remove_section(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_section_to_remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    original.remove_section("__to_remove")

    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_section("__to_remove") is None

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None

def test_remove_section_with_segment_name(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/MachO64_x86-64_binary_section_to_remove.bin"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    original.remove_section("__DATA", "__to_remove")

    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    assert new.get_section("__DATA", "__to_remove") is None

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Hello World', stdout) is not None

def test_objc_arm64(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/test_objc_arm64.macho"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    for i in range(50):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        segment = original.add(segment)

    # Extend the symbols table
    for i in range(10):
        sym = f"_foooo_{i}"
        original.add_exported_function(original.imagebase + i * 8, sym)

        sym = f"_foooo2_{i}"
        original.add_local_symbol(original.entrypoint + i * 8, sym)

    functions = original.function_starts.functions
    functions *= 2
    sorted(functions)
    original.function_starts.functions = functions

    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_apple_m1():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Printing Process Completed', stdout) is not None


def test_objc_x86_64(tmp_path):
    bin_path = pathlib.Path(get_sample("MachO/test_objc_x86_64.macho"))
    original = lief.parse(bin_path.as_posix())
    output = f"{tmp_path}/{bin_path.name}"

    for i in range(50):
        segment = lief.MachO.SegmentCommand(f"__LIEF_{i}", [i] * (0x457 + i))
        segment = original.add(segment)

    # Extend the symbols table
    for i in range(10):
        sym = f"_foooo_{i}"
        original.add_exported_function(original.imagebase + i * 8, sym)

        sym = f"_foooo2_{i}"
        original.add_local_symbol(original.entrypoint + i * 8, sym)

    functions = original.function_starts.functions
    functions *= 2
    sorted(functions)
    original.function_starts.functions = functions

    original.write(output)
    new = lief.parse(output)

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    if is_osx():
        assert run_program(bin_path.as_posix())
        stdout = run_program(output)

        print(stdout)
        assert re.search(r'Printing Process Completed', stdout) is not None

def test_break(tmp_path):
    FILES = [
        "MachO/mbedtls_selftest_arm64.bin",
        "MachO/mbedtls_selftest_x86_64.bin"
    ]
    def swap(target: lief.MachO.Binary, lhs: str, rhs: str):
        lhs_sec = target.get_section(lhs)
        if lhs_sec is None:
            print(f"Can't find section '{lhs_sec}'")
            return
        rhs_sec = target.get_section(rhs)
        if rhs_sec is None:
            print(f"Can't find section '{rhs_sec}'")
            return

        tmp = lhs_sec.name
        rhs_sec.name = tmp

    def shuffle(target: lief.MachO.Binary, name: str):
        section = target.get_section(name)
        if section is None:
            return
        print(f"[+] Shuffling '{name}'")
        section_content = list(section.content)
        random.shuffle(section_content)
        section.content = section_content

    def corrupt_function_starts(bin: lief.MachO.Binary, break_alignment: bool = False):
        fstart = bin[lief.MachO.LOAD_COMMAND_TYPES.FUNCTION_STARTS]
        if fstart is None:
            return
        fstart.functions = [f + 5 for f in fstart.functions]

    def process_exports(bin: lief.MachO.Binary, sym: lief.MachO.Symbol):
        #print(sym.export_info.address)
        original_name = sym.export_info.symbol.name
        name = list(original_name)
        random.shuffle(name)
        new_name = "_" + "".join(name)
        address = sym.export_info.address
        bin.add_local_symbol(address, new_name)

    def process_imports(bin: lief.MachO.Binary, sym: lief.MachO.Symbol):
        original_name = sym.binding_info.symbol.name
        name = list(original_name)
        random.shuffle(name)
        new_name = "_" + "".join(name)
        address = sym.binding_info.address - bin.imagebase
        bin.add_local_symbol(address, new_name)

    def process_local_symbol(bin: lief.MachO.Binary, sym: lief.MachO.Symbol):
        original_name = sym.name
        name = list(sym.name)
        random.shuffle(name)
        sym.name = "_" + "".join(name)
        sym.type = 0xf
        sym.description = 0x300
        sym.numberof_sections = 1
        sym.value += 2

    def process_symbols(bin: lief.MachO.Binary):
        exports = []
        imports = []
        for sym in bin.symbols:
            if sym.has_export_info:
                #print(f"[EXPORT]: {sym.name}")
                exports.append(sym)
            elif sym.has_binding_info:
                #print(f"[IMPORT]: {sym.name}")
                imports.append(sym)
            else:
                # "classical" symbol
                process_local_symbol(bin, sym)

        for sym in exports:
            process_exports(bin, sym)

        for sym in imports:
            process_imports(bin, sym)


    def fake_objc(bin: lief.MachO.Binary):
        segment = lief.MachO.SegmentCommand("__DATA_LIEF")

        __objc_classlist = lief.MachO.Section("__objc_classlist",
                                              [random.randint(0, 255) for _ in range(0x100)])
        __objc_imageinfo = lief.MachO.Section("__objc_imageinfo",
                                              [random.randint(0, 255) for _ in range(0x100)])
        __objc_const     = lief.MachO.Section("__objc_const",
                                              [random.randint(0, 255) for _ in range(0x100)])
        __objc_classrefs = lief.MachO.Section("__objc_classrefs",
                                              [random.randint(0, 255) for _ in range(0x100)])

        __objc_classlist = segment.add_section(__objc_classlist)
        __objc_imageinfo = segment.add_section(__objc_imageinfo)
        __objc_const     = segment.add_section(__objc_const)
        __objc_classrefs = segment.add_section(__objc_classrefs)

        objc_section = [__objc_classlist, __objc_imageinfo, __objc_const, __objc_classrefs]
        section: lief.MachO.Section
        for section in objc_section:
            section.type = lief.MachO.SECTION_TYPES.REGULAR
            section.flags = lief.MachO.SECTION_FLAGS.NO_DEAD_STRIP
            section.alignment = 0x3

        __data_lief: lief.MachO.SegmentCommand = bin.add(segment)
        __data_lief.init_protection = 3
        __data_lief.max_protection = 3

    for file in FILES:
        bin_path = pathlib.Path(get_sample(file))
        original = lief.parse(bin_path.as_posix())
        output = f"{tmp_path}/{bin_path.name}"

        SWAP_LIST = [
            ("__text", "__stubs"),
            ("__cstring", "__unwind_info"),
        ]
        for (lhs, rhs) in SWAP_LIST:
            swap(original, lhs, rhs)

        process_symbols(original)
        fake_objc(original)
        corrupt_function_starts(original)

        original.write(output)
        new = lief.parse(output)

        checked, err = lief.MachO.check_layout(new)
        assert checked, err
        should_run = (original.header.cpu_type == lief.MachO.CPU_TYPES.x86_64 and is_osx()) or \
                     (original.header.cpu_type == lief.MachO.CPU_TYPES.ARM64 and is_apple_m1())

        if should_run:
            assert run_program(bin_path.as_posix())
            stdout = run_program(output)

            print(stdout)
            assert re.search(r'All tests PASS', stdout) is not None

def test_issue_726(tmp_path):
    for filename in ("MachO/mbedtls_selftest_arm64.bin", "MachO/mbedtls_selftest_x86_64.bin"):
        bin_path = pathlib.Path(get_sample(filename))
        original = lief.parse(bin_path.as_posix())
        output = f"{tmp_path}/{bin_path.name}"

        original.write(output)
        new = lief.parse(output)

        for parsed in (original, new):
            assert parsed.get_segment("__LINKEDIT").virtual_size % parsed.page_size == 0
