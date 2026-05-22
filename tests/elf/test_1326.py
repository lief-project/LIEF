from pathlib import Path

import lief
import os
import subprocess
from pathlib import Path
from subprocess import Popen
def generate_elf_with_stapsdt():
    TMP = Path("/tmp")
    SOURCE = (TMP / "elf-note-stapsdt.c")
    ELF = (TMP / "elf-note-stapsdt")
    CC = os.getenv("CC", "/usr/bin/cc")
    if not os.path.exists(CC):
        raise RuntimeError("Unable to find a compiler")
    CODE = r"""
/*
 * Simple C example with .note.stapsdt section for SystemTap SDT probes
 *
 * Dependency: sudo apt-get install systemtap-sdt-dev
*/

#include <stdio.h>
#include <sys/sdt.h>

int main(int argc, char **argv) {
    int x = 42;
    
    printf("Hello, World!\n");
    
    // SystemTap SDT probe point
    DTRACE_PROBE1(my_provider, my_probe1, argc);
    DTRACE_PROBE1(my_provider, my_probe2, x);
    
    printf("x = %d, argc = %d\n", x, argc);

    (void)argv;
    
    return 0;
}
"""
    SOURCE.write_text(CODE)
    cmd = [CC, "-o", str(ELF), str(SOURCE)]
    lief.logging.info("Compile 'elf-note-stapsdt' with: {}".format(" ".join(cmd)))
    with Popen(cmd, cwd=TMP, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        assert P.stdout is not None
        stdout = P.stdout.read()
        lief.logging.info(stdout)
        assert stdout == b""
        return ELF

def set_rpath(source, target, rpath):
    elf = lief.ELF.parse(source)
    existing = []
    for entry in elf.dynamic_entries:
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.RPATH,
            lief.ELF.DynamicEntry.TAG.RUNPATH,
        ]:
            existing.append(entry)
    for entry in existing:
        elf.remove(entry)
    elf.add(lief.ELF.DynamicEntryRunPath(rpath))
    elf.write(target)

def show_notes(source):
    elf = lief.ELF.parse(source)
    for section in elf.sections:
        if section.type == lief.ELF.Section.TYPE.NOTE and section.name == ".note.stapsdt":
            print(f"  - NOTE: {section.name}, Size: {section.size}, Offset: 0x{section.offset:x}, VAddr: 0x{section.virtual_address:x}, Content: 0x{section.content[0]:x}...")
            assert section.content[0] != 0
def test_1326(count):
    # Test for the issue https://github.com/lief-project/LIEF/issues/1326
    sample = generate_elf_with_stapsdt()
    source = str(sample)

    print(f"ORIGINAL")
    show_notes(source)
    for round in range(count):
        print(f"ROUND #{round+1}")
        target = str(sample)+"."+str(round)
        set_rpath(source, target, r"${ORIGIN}")
        show_notes(source)
        source = target
    print()
    print(f"ELF with .note.stapsdt survied {count} rounds")

if __name__ == "__main__":
    test_1326(10)
