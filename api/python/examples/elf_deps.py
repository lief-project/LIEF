#!/usr/bin/env python3
"""Analyze ELF shared library dependencies and symbol versioning.

A cross-platform alternative to ldd that works without executing the binary.
Lists shared library dependencies, RPATH/RUNPATH search paths, and optionally
shows imported symbol versions (useful for checking glibc compatibility).

Inspired by conda-build's liefldd.py and Bitcoin's symbol-check.py.

Example:

    $ python elf_deps.py /usr/bin/ls
    Dependencies: /usr/bin/ls
    ========================================
    Interpreter:    /lib64/ld-linux-x86-64.so.2
    Type:           DYN (Position-Independent Executable)

    Shared Libraries:
      libselinux.so.1
      libc.so.6
      ld-linux-x86-64.so.2

    $ python elf_deps.py --versions /usr/bin/ls
    ...
    Symbol Versions:
      GLIBC_2.2.5  (25 symbols)
      GLIBC_2.3    (1 symbols)
      GLIBC_2.17   (2 symbols)
"""

import argparse
from collections import defaultdict

import lief

HEADER_TYPES = {
    lief.ELF.Header.FILE_TYPE.EXEC: "EXEC (Executable)",
    lief.ELF.Header.FILE_TYPE.DYN: "DYN (Shared Object / PIE)",
    lief.ELF.Header.FILE_TYPE.REL: "REL (Relocatable)",
    lief.ELF.Header.FILE_TYPE.CORE: "CORE (Core Dump)",
}


def analyze_deps(filename, show_versions=False):
    """Analyze ELF dependencies and symbol version requirements."""
    binary = lief.ELF.parse(filename)
    if binary is None:
        print(f"Error: failed to parse '{filename}' as ELF")
        return False

    file_type = HEADER_TYPES.get(binary.header.file_type, str(binary.header.file_type))
    interpreter = binary.interpreter or "(none — statically linked)"

    print(f"Dependencies: {filename}")
    print("=" * 48)
    print(f"  Interpreter:  {interpreter}")
    print(f"  Type:         {file_type}")
    print(f"  Arch:         {binary.header.machine_type.name}")
    print()

    # Shared libraries (DT_NEEDED entries)
    libraries = list(binary.libraries)
    if libraries:
        print("  Shared Libraries:")
        for lib in libraries:
            print(f"    {lib}")
    else:
        print("  Shared Libraries: (none — statically linked)")
    print()

    # RPATH and RUNPATH
    rpath = None
    runpath = None
    for entry in binary.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryRpath):
            rpath = entry.rpath
        elif isinstance(entry, lief.ELF.DynamicEntryRunPath):
            runpath = entry.runpath

    if rpath or runpath:
        print("  Search Paths:")
        if rpath:
            print(f"    RPATH:   {rpath}")
        if runpath:
            print(f"    RUNPATH: {runpath}")
        print()

    # Symbol versions
    if show_versions:
        version_counts = defaultdict(int)
        version_symbols = defaultdict(list)

        for sym in binary.imported_symbols:
            if not sym.has_version:
                continue
            version = sym.symbol_version
            if not version.has_auxiliary_version:
                continue
            ver_name = version.symbol_version_auxiliary.name
            version_counts[ver_name] += 1
            version_symbols[ver_name].append(sym.name)

        if version_counts:
            print("  Symbol Versions:")
            for ver_name in sorted(version_counts):
                count = version_counts[ver_name]
                print(f"    {ver_name:<24} ({count} symbol{'s' if count != 1 else ''})")
            print()

            # Show highest required version per library prefix
            lib_versions = defaultdict(list)
            for ver_name in version_counts:
                parts = ver_name.rsplit("_", 1)
                if len(parts) == 2:
                    lib, ver_str = parts
                    try:
                        ver_tuple = tuple(int(x) for x in ver_str.split("."))
                        lib_versions[lib].append((ver_tuple, ver_name))
                    except ValueError:
                        pass

            if lib_versions:
                print("  Minimum Required Versions:")
                for lib in sorted(lib_versions):
                    max_ver = max(lib_versions[lib], key=lambda x: x[0])
                    print(f"    {lib}: {max_ver[1]}")
                print()

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ELF shared library dependencies"
    )
    parser.add_argument("binaries", nargs="+", help="ELF binaries to analyze")
    parser.add_argument(
        "-v",
        "--versions",
        action="store_true",
        help="Show imported symbol version requirements",
    )
    args = parser.parse_args()

    for path in args.binaries:
        analyze_deps(path, show_versions=args.versions)


if __name__ == "__main__":
    main()
