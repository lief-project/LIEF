#!/usr/bin/env python
import unittest
import lief
import tempfile
import logging
import os
from subprocess import Popen
import subprocess
import stat
import re
import sys

from unittest import TestCase
from utils import get_sample

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.WARNING)

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(CURRENT_DIRECTORY, "HelloWorld.shellcode")

def run_program(path, args=None):
    # Make sure the program had exec permission
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)


    prog_args = path if not args else [path] + args
    p = Popen(prog_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, _ = p.communicate()
    stdout = stdout.decode("utf8")
    return stdout


class TestMachOBuilder(TestCase):

    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_id(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        _, output = tempfile.mkstemp(prefix="lief_id_builder")
        original.write(output)
        modified = lief.parse(output)

        self.check_consistency(original, modified)

    def check_consistency(self, original, modified):
        # Header
        self.assertEqual(original.header, modified.header)

        for cmd_o, cmd_m in zip(original.commands, modified.commands):
            #if cmd_o.command == lief.MachO.LOAD_COMMAND_TYPES.DYSYMTAB:
            #    continue
            #self.assertEqual(cmd_o, cmd_m, msg="\n{}\n\n{}".format(cmd_o, cmd_m))
            pass


class TestAddCommand(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)


    def test_id(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        _, output = tempfile.mkstemp(prefix="lief_id_add_cmd")

        LIB_NAME = "/usr/lib/libSystem.B.dylib"

        dylib_1 = lief.MachO.DylibCommand.lazy_load_dylib(LIB_NAME)
        dylib_2 = lief.MachO.DylibCommand.weak_lib(LIB_NAME)

        original.add(dylib_1)
        original.add(dylib_2, 0)

        original.remove_signature()

        original.write(output)

        new = lief.parse(output)
        self.assertTrue(len([l for l in new.libraries if l.name == LIB_NAME]))

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'uid=', stdout))


class TestRemoveCommand(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_id(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        _, output = tempfile.mkstemp(prefix="lief_id_remove_cmd")

        uuid_cmd = original[lief.MachO.LOAD_COMMAND_TYPES.UUID]
        original.remove(uuid_cmd)
        original.remove_command(len(original.commands) - 1)


        original.write(output)

        new = lief.parse(output)
        self.assertFalse(lief.MachO.LOAD_COMMAND_TYPES.UUID in new)
        self.assertFalse(lief.MachO.LOAD_COMMAND_TYPES.CODE_SIGNATURE in new)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'uid=', stdout))



class TestExtendCommand(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_id(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        _, output = tempfile.mkstemp(prefix="lief_id_remove_cmd")

        # Extend UUID
        uuid_cmd = original[lief.MachO.LOAD_COMMAND_TYPES.UUID]
        original_size = uuid_cmd.size
        original.extend(uuid_cmd, 0x100)
        uuid_cmd = original[lief.MachO.LOAD_COMMAND_TYPES.UUID]

        # Extend __LINKEDIT (last one)
        original.extend_segment(original.get_segment("__LINKEDIT"), 0x30000)

        original.remove_signature()
        original.write(output)

        new = lief.parse(output)
        self.assertEqual(new[lief.MachO.LOAD_COMMAND_TYPES.UUID].size, original_size + 0x100)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'uid=', stdout))

class TestSectionSegment(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_id(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_id.bin'))
        _, output = tempfile.mkstemp(prefix="lief_id_")

        # Add 50 sections
        for i in range(50):
            section = lief.MachO.Section("__lief_{:d}".format(i), [0x90] * 0x100)
            original.add_section(section)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'uid=', stdout))

    def test_ssh(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin'))
        _, output = tempfile.mkstemp(prefix="lief_ssh_")

        # Add 3 section into __TEXT
        __text = original.get_segment("__TEXT")
        for i in range(3):
            section = lief.MachO.Section("__text_{:d}".format(i))
            section.content = [0xC3] * 0x100
            original.add_section(__text, section)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output, ["--help"])
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'OpenSSH_6.9p1, LibreSSL 2.1.8', stdout))


    def test_nm(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_nm.bin'))
        _, output = tempfile.mkstemp(prefix="lief_nm_")

        # Add segment without section
        segment = lief.MachO.SegmentCommand("__LIEF", [0x60] * 0x100)
        segment = original.add(segment)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output, ["-version"])
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Default target:', stdout))

    def test_all(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin'))
        _, output = tempfile.mkstemp(prefix="lief_all_")

        # Add segment with sections
        segment = lief.MachO.SegmentCommand("__LIEF_2")
        for i in range(5):
            section = lief.MachO.Section("__lief_2_{:d}".format(i), [i] * 0x100)
            segment.add_section(section)
        segment = original.add(segment)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World: 1', stdout))




class TestLibraryInjection(TestCase):
    COUNT = 0
    LIBRARY_CODE = r"""\
    #include <stdio.h>
    #include <stdlib.h>

    __attribute__((constructor))
    void my_constructor(void) {
      printf("CTOR CALLED\n");
    }
    """

    @staticmethod
    def compile(output, extra_flags=None):
        if not sys.platform.startswith("darwin"):
            return

        logger = logging.getLogger(__name__)
        extra_flags = extra_flags if extra_flags else []
        _, srcpath = tempfile.mkstemp(prefix="libexample_", suffix=".c")

        with open(srcpath, 'w') as f:
            f.write(TestLibraryInjection.LIBRARY_CODE)

        COMPILER = "/usr/bin/clang"
        CC_FLAGS = ['-fPIC', '-shared'] + extra_flags

        cmd = [COMPILER, '-o', output] + CC_FLAGS + [srcpath]
        logger.debug("Compile 'libexample' with: {}".format(" ".join(cmd)))

        p = Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout, _ = p.communicate()

        logger.debug(stdout)
        return output

    def setUp(self):
        self.logger = logging.getLogger(__name__)
        _, self.library_path = tempfile.mkstemp(prefix="libexample_", suffix=".dylib")
        TestLibraryInjection.compile(self.library_path)

    def test_all(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin'))
        _, output = tempfile.mkstemp(prefix="lief_all_")

        original.add_library(self.library_path)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'CTOR CALLED', stdout))


    def test_ssh(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin'))
        _, output = tempfile.mkstemp(prefix="lief_ssh_")

        original.add_library(self.library_path)

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output, ["--help"])
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'CTOR CALLED', stdout))



class TestShellCodeInjection(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.shellcode = None
        with open(STUB, "rb") as f:
            self.shellcode = list(f.read())

        # For Python 2
        if type(self.shellcode[0]) is str:
            self.shellcode = list(map(ord, self.shellcode))

    def test_all(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_all.bin'))
        _, output = tempfile.mkstemp(prefix="lief_all_")

        section = lief.MachO.Section("__shell", self.shellcode)
        section.alignment = 2
        section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
        section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS

        section = original.add_section(section)

        __TEXT = original.get_segment("__TEXT")

        original.main_command.entrypoint = section.virtual_address - __TEXT.virtual_address

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World!', stdout))


    def test_ssh(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sshd.bin'))
        _, output = tempfile.mkstemp(prefix="lief_ssh_")

        section = lief.MachO.Section("__shell", self.shellcode)
        section.alignment = 2
        section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
        section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS

        section = original.add_section(section)

        __TEXT = original.get_segment("__TEXT")

        original.main_command.entrypoint = section.virtual_address - __TEXT.virtual_address
        original.remove_signature()

        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World!', stdout))


class TestRemoveSection(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_simple(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_section_to_remove.bin'))
        _, output = tempfile.mkstemp(prefix="lief_sec_remove_")

        original.remove_section("__to_remove")
        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World', stdout))

class TestRemoveSymbol(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)

    def test_unexport(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sym2remove.bin'))
        _, output = tempfile.mkstemp(prefix="lief_sym_remove_")

        original.unexport("_remove_me")
        original.write(output)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World', stdout))

    def test_rm_symbol(self):
        original = lief.parse(get_sample('MachO/MachO64_x86-64_binary_sym2remove.bin'))
        _, output = tempfile.mkstemp(prefix="lief_sym_remove_")

        for s in ["__ZL6BANNER", "_remove_me"]:
            self.assertTrue(original.can_remove_symbol(s))
            original.remove_symbol(s)

        original.write(output)
        new = lief.parse(output)
        ok, err = lief.MachO.check_layout(new)
        self.assertTrue(ok, err)

        if sys.platform.startswith("darwin"):
            stdout = run_program(output)
            self.logger.debug(stdout)
            self.assertIsNotNone(re.search(r'Hello World', stdout))


if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)

