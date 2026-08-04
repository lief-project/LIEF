#!/usr/bin/env python3
import ctypes
import sys
from itertools import islice

import lief


def host_info():
    print("Host")
    # lief-doc: host-start
    print(f"    Hostname:    {lief.runtime.Host.name}")
    print(f"    Home:        {lief.runtime.Host.home_dir}")
    print(f"    cache:       {lief.runtime.Host.cache_dir}")
    print(f"    temp:        {lief.runtime.Host.tmp_dir}")
    print(f"    config:      {lief.runtime.Host.config_dir}")
    # lief-doc: host-end

    # lief-doc: host-linux-start
    print(f"    sys_name:    {lief.runtime.linux.Host.sys_name}")
    print(f"    sys_release: {lief.runtime.linux.Host.sys_release}")
    print(f"    sys_version: {lief.runtime.linux.Host.sys_version}")
    print(f"    hardware:    {lief.runtime.linux.Host.hardware}")
    # lief-doc: host-linux-end
    print()


def process_info():
    print("Process")
    # lief-doc: process-start
    print(f"    PID:       {lief.runtime.Process.pid}")
    print(f"    TID:       {lief.runtime.Process.tid}")
    print(f"    Page size: {lief.runtime.Process.page_size:#06x}")
    print(f"    Arch:      {lief.runtime.Process.arch}")
    print(f"    Platform:  {lief.runtime.Process.platform}")
    print(f"    TERM:      {lief.runtime.Process.get_env('TERM')}")
    # lief-doc: process-end

    # lief-doc: process-linux-start
    print(f"    glibc:     {lief.runtime.linux.Process.glibc_version}")
    # lief-doc: process-linux-end


def modules_info():
    print("Module API")
    libc: lief.runtime.linux.Module | None = None
    # lief-doc: modules-start
    for mod in lief.runtime.modules():
        print(mod)
        # Look for the libc
        if mod.name.startswith("libc.so"):
            print(
                f"libc.so found: {mod.path} ([{mod.imagebase:#010x}, {mod.end:#010x}])"
            )
            assert isinstance(mod, lief.runtime.linux.Module)
            libc = mod
    # lief-doc: modules-end

    if libc is None:
        return

    # lief-doc: modules-linux-start
    print(f"libc path: {libc.path}")
    if __cxa_finalize := libc.dlsym("__cxa_finalize"):
        __cxa_finalize_addr = lief.to_int(__cxa_finalize)
        print(f"{libc.name}!__cxa_finalize: {__cxa_finalize_addr:#010x}")

    if malloc := libc.dlsym("malloc"):
        malloc_addr = lief.to_int(malloc)
        # lief.to_int is used to convert an opaque pointer (void*) into a
        # regular Python int
        print(f"{libc.name}!malloc: {malloc_addr:#010x}")

        # With LIEF extended, we can disassemble the function from its
        # absolute memory address:
        if lief.__extended__:
            for inst in islice(lief.runtime.disassemble(malloc_addr), 4):
                print("   ", inst)

    # This parses the ELF from its path on the disk
    if (elf_on_disk := libc.parse_from_path()) is not None and (
        __cxa_finalize := elf_on_disk.get_symbol("__cxa_finalize")
    ) is not None:
        print(f"__cxa_finalize: {__cxa_finalize.value:#010x}")

    # This code loads 'librt.so' and wrap the dlopen handler in a Module.
    if librt := lief.runtime.linux.dlopen("librt.so.1"):
        print(
            f"librt loaded: {librt.path} (dlopen handler={lief.to_int(librt.handle):#010x})"
        )

        # Parse the ELF directly from memory.
        if librt_mem := librt.parse_from_memory():
            # This code looks for the relocation associated with the
            # **imported** symbol `__cxa_finalize` that is defined in the libc.
            # The relocation holds the address where the function is resolved.
            # Therefore, by reading this relocation address we can access the
            # resolved address of `__cxa_finalize`. This address should match
            # the value previously returned by dlsym
            __cxa_finalize_reloc = next(
                (
                    reloc
                    for reloc in librt_mem.relocations
                    if reloc.symbol is not None
                    and reloc.symbol.name == "__cxa_finalize"
                ),
                None,
            )
            if __cxa_finalize_reloc is not None:
                abs_reloc_addr = librt.imagebase + __cxa_finalize_reloc.address
                # We assume a 64-bit architecture
                __cxa_finalize_addr = lief.runtime.Memory.read_u64(abs_reloc_addr)
                print(
                    f"{librt.name} -> {abs_reloc_addr:#010x} -> {__cxa_finalize_addr:#010x}"
                )
    # lief-doc: modules-linux-end


def memory_example():
    # lief-doc: memory-start
    chunk = lief.runtime.Memory.mmap(
        lief.runtime.Process.page_size,
        lief.runtime.Memory.ANONYMOUS | lief.runtime.Memory.PRIVATE,
        lief.runtime.Memory.READ | lief.runtime.Memory.WRITE | lief.runtime.Memory.EXEC,
    )

    raw_inst = lief.runtime.assemble(
        chunk.addr,
        r"""
        .global _start

        .text
        _start:
            push 1
            pop  rax
            mov  edi, eax
            lea  rsi, [rip + msg]
            mov  rdx, 28
            syscall
            ret

        msg:
            .ascii "LIEF Runtime Extended Demo\n"
        """,
    )

    # Ensure the assembly is correctly JITed at the beginning of the allocated
    # memory
    for inst in islice(lief.runtime.disassemble(chunk.addr), 7):
        print(inst)

    # Dump as raw bytes
    raw_bytes = lief.runtime.Memory.read(chunk.addr, len(raw_inst))
    print(raw_bytes.hex(":"))

    # Change the permission to R-X
    chunk.make_rx()

    VoidVoidFunc = ctypes.CFUNCTYPE(None)  # void(*)()
    hello_jit = VoidVoidFunc(chunk.addr)
    hello_jit()

    # Change the message
    pos = raw_bytes.find(b"LIEF Runtime")
    chunk.make_rw()
    lief.runtime.Memory.write(b"Hello Python ctypes World!\n", chunk.addr + pos)
    chunk.make_rx()

    # Print again
    hello_jit()

    # Don't miss good practices!
    chunk.deallocate()
    # lief-doc: memory-end


def main() -> int:
    if not lief.runtime.enabled:
        print("Error: LIEF's runtime is not enabled", file=sys.stderr)
        return 0

    host_info()
    process_info()
    modules_info()
    memory_example()
    return 0


if __name__ == "__main__":
    sys.exit(main())
