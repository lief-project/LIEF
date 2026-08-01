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

    # lief-doc: host-android-start
    if (sdk := lief.runtime.android.Host.sdk_version) is not None:
        print(f"    SDK:         {sdk}")
    # lief-doc: host-android-end
    print()


def process_info():
    print("Process")
    # lief-doc: process-start
    print(f"    PID:       {lief.runtime.Process.pid}")
    print(f"    TID:       {lief.runtime.Process.tid}")
    print(f"    Page size: {lief.runtime.Process.page_size:#06x}")
    print(f"    Arch:      {lief.runtime.Process.arch}")
    print(f"    Platform:  {lief.runtime.Process.platform}")
    # lief-doc: process-end

    # lief-doc: process-android-start
    # Access a named property
    sdk = lief.runtime.android.Process.get_system_property("ro.build.version.sdk")
    if sdk is not None:
        print(f"    {sdk.name}: {sdk.value} (serial: {sdk.serial})")

    # Iterate over all properties
    for prop in lief.runtime.android.Process.properties:
        print(f"    {prop.name}: {prop.value} (serial: {prop.serial})")
    # lief-doc: process-android-end


def modules_info():
    print("Module API")
    libc: lief.runtime.android.Module | None = None
    # lief-doc: modules-start
    for mod in lief.runtime.modules():
        print(mod)
        # Look for the Bionic libc
        if mod.name.endswith("libc.so"):
            print(
                f"libc.so found: {mod.path} ([{mod.imagebase:#010x}, {mod.end:#010x}])"
            )
            assert isinstance(mod, lief.runtime.android.Module)
            libc = mod
    # lief-doc: modules-end

    if libc is None:
        return

    # lief-doc: modules-android-start
    print(f"libc path: {libc.path}")
    if __cxa_finalize := libc.dlsym("__cxa_finalize"):
        __cxa_finalize_addr = lief.to_int(__cxa_finalize)
        print(f"{libc.name}!__cxa_finalize: {__cxa_finalize_addr:#010x}")

    if malloc := libc.dlsym("malloc"):
        malloc_addr = lief.to_int(malloc)
        print(f"{libc.name}!malloc: {malloc_addr:#010x}")

        # With LIEF extended, we can disassemble the function from its
        # absolute memory address:
        if lief.__extended__:
            for inst in islice(lief.runtime.disassemble(malloc_addr), 4):
                print("   ", inst)

    if (elf_on_disk := libc.parse_from_path()) is not None and (
        __cxa_finalize := elf_on_disk.get_symbol("__cxa_finalize")
    ) is not None:
        print(f"__cxa_finalize: {__cxa_finalize.value:#010x}")

    if liblog := lief.runtime.android.dlopen("liblog.so"):
        print(
            f"liblog loaded: {liblog.path} "
            f"(dlopen handler={lief.to_int(liblog.handle):#010x})"
        )

        if log_print := liblog.dlsym("__android_log_print"):
            log_print_addr = lief.to_int(log_print)
            print(f"{liblog.name}!__android_log_print: {log_print_addr:#010x}")
    # lief-doc: modules-android-end


def memory_example():
    print("Memory")
    # lief-doc: memory-start
    chunk = lief.runtime.Memory.mmap(
        lief.runtime.Process.page_size,
        lief.runtime.Memory.ANONYMOUS | lief.runtime.Memory.PRIVATE,
        lief.runtime.Memory.READ | lief.runtime.Memory.WRITE | lief.runtime.Memory.EXEC,
    )

    class Config(lief.assembly.AssemblerConfig):
        def resolve_symbol(self, name: str) -> int | None:
            libc = lief.runtime.android.dlopen("libc.so")
            if libc is None:
                print("Failed to dlopen libc.so", file=sys.stderr)
                return None

            if name == "write":
                return lief.to_int(libc.dlsym("write"))
            return None

    config = Config()

    raw_inst = lief.runtime.assemble(
        chunk.addr,
        r"""
        .text
            .global main
            .align 2

        main:
            stp     x29, x30, [sp, -16]!
            mov     x29, sp

            ldr     x8, =write

            mov     x0, 1    // STDOUT_FILENO
            adr     x1, msg  // buf = &msg
            mov     x2, 27   // len = len("LIEF Runtime Extended Demo\n")
            blr     x8       // write(STDOUT_FILENO, msg, 27)

            ldp     x29, x30, [sp], 16
            ret

        msg:
            .ascii "LIEF Runtime Extended Demo\n"
        """,
        config,
    )

    # Disassemble the JITed stub from memory
    for inst in islice(lief.runtime.disassemble(chunk.addr), 9):
        print(inst)

    # Dump as raw bytes
    raw_bytes = lief.runtime.Memory.read(chunk.addr, len(raw_inst))
    print(raw_bytes.hex(":"))

    # Flush the instruction cache before executing the freshly written code
    # (this is required on AArch64).
    chunk.cache_flush()

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
    chunk.cache_flush()

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
