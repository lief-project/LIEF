#!python
import lief
import pytest
import ctypes
import io
import sys
import subprocess

from pathlib import Path
from multiprocessing import Process
from subprocess import Popen

from utils import (
    get_sample, is_windows, is_x86_64, win_exec,
    has_private_samples, is_windows_x86_64
)
if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX) # type: ignore


def _load_library(path: Path):
    lib = ctypes.windll.LoadLibrary(path.as_posix()) # type: ignore
    assert lib is not None

@pytest.mark.parametrize("sample", [
    "PE/ucrtbase.dll",
    "PE/LIEF-win64.dll",
    "PE/pe_reader.exe",
])
def test_add_sections(tmp_path: Path, sample: str):
    input_path = Path(get_sample(sample))
    pe = lief.PE.parse(input_path)

    for i in range(20):
        section = lief.PE.Section(f".lief_{i}")
        if i % 3 == 0:
            section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.CNT_CODE |
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
                lief.PE.Section.CHARACTERISTICS.MEM_READ
            ).value
            section.content = [0x90 for i in range(123)]
        if i % 3 == 1:
            section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA |
                lief.PE.Section.CHARACTERISTICS.MEM_WRITE |
                lief.PE.Section.CHARACTERISTICS.MEM_READ
            ).value
            section.content = [0x41 for i in range(456)]
        if i % 3 == 2:
            section.characteristics = (
                lief.PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA |
                lief.PE.Section.CHARACTERISTICS.MEM_WRITE |
                lief.PE.Section.CHARACTERISTICS.MEM_READ
            ).value
            section.content = [0x42 for i in range(789)]
        else:
            section.content = [0x90 for i in range(0x200)]
        pe.add_section(section)

    output = tmp_path / input_path.name
    pe.write(output.as_posix())

    new = lief.PE.parse(output)
    assert len([s for s in new.sections if s.name.startswith(".lief_")]) == 20
    checked, msg = lief.PE.check_layout(new)
    assert checked, msg

    if is_windows() and is_x86_64():
        if input_path.name.endswith(".dll"):
            p = Process(target=_load_library, args=(output,))
            p.start()
            p.join()
            assert p.exitcode == 0

        if input_path.name == "pe_reader.exe":
            ret = win_exec(output, gui=False, args=[output.as_posix(), ])
            assert ret is not None

            retcode, stdout = ret
            assert retcode == 0
            assert len(stdout) > 0

def test_issue_952(tmp_path: Path):
    pe = lief.PE.parse(get_sample("PE/PE32_x86_binary_HelloWorld.exe"))
    stub = bytes(pe.dos_stub)
    assert not all(x == 0 for x in stub)

    out = tmp_path / "out.exe"
    pe.write(out.as_posix())

    new = lief.PE.parse(out.as_posix())
    assert bytes(new.dos_stub) == stub

    checked, msg = lief.PE.check_layout(new)
    assert checked, msg


def test_code_injection(tmp_path: Path):
    def resolved_import(pe: lief.PE.Binary, imp: lief.PE.Import,
                        entry: lief.PE.ImportEntry, rva: int):
        fixup_location = pe.get_section(".lief")

        LEA_SZ = 7
        JMP_SZ = 6
        FIXUP_POS = 7 + 2 # The jmp offset is encoded after the 2 first byes
        FIXUP_SIZE = 4 # Size of the jump is 4 bytes

        # rip is 'ahead' of the jmp
        rip_at_jmp = fixup_location.virtual_address + LEA_SZ + JMP_SZ

        # Delta to reach the IAT
        delta = rva - rip_at_jmp

        content = list(fixup_location.content)
        content = (
            content[:FIXUP_POS] +
            list(delta.to_bytes(length=FIXUP_SIZE, byteorder='little')) +
            content[FIXUP_POS + FIXUP_SIZE:]
        )
        fixup_location.content = content

        print(f"{entry.name}: IAT: 0x{rva:08x}")

    input_path = Path(get_sample("PE/LIEF-win64.dll"))
    pe = lief.PE.parse(input_path)

    # import 'puts' from 'api-ms-win-crt-stdio-l1-1-0.dll'
    stdio = pe.add_import("api-ms-win-crt-stdio-l1-1-0.dll")
    stdio.add_entry("puts")

    code = [
        # lea rcx, [rip + size next inst] -> Hello World
        0x48, 0x8d ,0x0d, 0x06, 0x00, 0x00, 0x00,
        # jmp qword ptr [rip + <fixup>]
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
    ] + list(b"Hello World")

    section = lief.PE.Section(".lief")
    section.content = code
    section.characteristics = (
        lief.PE.Section.CHARACTERISTICS.MEM_READ |
        lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
        lief.PE.Section.CHARACTERISTICS.CNT_CODE |
        lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA
    ).value

    new_section = pe.add_section(section)
    pe.tls.callbacks += [new_section.virtual_address + pe.imagebase]

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.resolved_iat_cbk = resolved_import

    output = tmp_path / input_path.name

    pe.write(output.as_posix(), config)

    new = lief.PE.parse(output)
    err, msg = lief.PE.check_layout(new)
    assert err, msg

    if is_windows_x86_64():
        popen_args = {
            "universal_newlines": True,
            "shell": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "creationflags": 0x8000000  # win32con.CREATE_NO_WINDOW
        }

        args = [
            sys.executable,
            '-c',
            f'import ctypes; ctypes.windll.LoadLibrary("{output.as_posix()}")'
        ]
        with Popen(args, **popen_args) as proc: # type: ignore[call-overload]
            stdout, _ = proc.communicate(10)
            print("stdout:", stdout)
            assert proc.returncode == 0
            assert "Hello World" in stdout
