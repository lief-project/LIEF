#!/usr/bin/env python3
import ctypes
import sys
from itertools import islice

import lief


def host_info():
    print("Host")
    # lief-doc: host-start
    print(f"    Hostname: {lief.runtime.Host.name}")
    print(f"    Home:     {lief.runtime.Host.home_dir}")
    print(f"    Cache:    {lief.runtime.Host.cache_dir}")
    print(f"    Temp:     {lief.runtime.Host.tmp_dir}")
    print(f"    Config:   {lief.runtime.Host.config_dir}")
    # lief-doc: host-end

    # lief-doc: host-osx-start
    print(f"    Version:  {lief.runtime.osx.Host.os_version_name}")
    sip = "enabled" if lief.runtime.osx.Host.is_sip_enabled else "disabled"
    print(f"    SIP:      {sip}")
    # lief-doc: host-osx-end
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

    # lief-doc: process-osx-start
    print(f"    dyld:      {lief.runtime.osx.Process.dyld_version}")
    # lief-doc: process-osx-end


def modules_info():
    print("Module API")

    # Module referencing libsystem_c.dylib in memory
    libsystem: lief.runtime.osx.Module | None = None

    # lief-doc: modules-start
    for mod in lief.runtime.modules():
        print(mod)
        # Look for the C library
        if mod.name.endswith("libsystem_c.dylib"):
            print(
                f"libsystem_c.dylib found: {mod.path} ([{mod.imagebase:#010x}, {mod.end:#010x}])"
            )
            assert isinstance(mod, lief.runtime.osx.Module)
            libsystem = mod
    # lief-doc: modules-end

    if libsystem is None:
        return

    # lief-doc: modules-osx-start
    print(f"libsystem_c path: {libsystem.path}")
    if arc4_init := libsystem.dlsym("arc4_init"):
        # lief.to_int converts an opaque pointer (void*) into a regular Python int
        arc4_init_addr = lief.to_int(arc4_init)
        print(f"{libsystem.name}!arc4_init: {arc4_init_addr:#010x}")

        # With LIEF extended, we can disassemble the function directly from its
        # absolute memory address:
        if lief.__extended__:
            for inst in islice(lief.runtime.disassemble(arc4_init_addr), 4):
                print("   ", inst)

    # libsystem.path looks like a valid path but libsystem_c.dylib lives in the
    # dyld-shared-cache. Therefore, it's pointless to try to parse the library
    # from its filepath as the library does not exist on the disk.
    macho_on_disk: lief.MachO.Binary | None = None
    with lief.logging.level_scope(lief.logging.Level.Off):
        macho_on_disk = libsystem.parse_from_path()

    if macho_on_disk is None:
        print(f"As expected, {libsystem.path} is not present in the filesystem")

    # But we can parse it from memory:
    if macho_memory := libsystem.parse_from_memory():
        print(f"in-memory imagebase: {macho_memory.imagebase:#010x}")
        # List 'exported' symbols
        for sym in macho_memory.exported_symbols:
            print(f"{sym.name:10}: {sym.value:#010x}")

    # lief-doc: modules-osx-end


def memory_example():
    print("Memory")
    # lief-doc: memory-start
    # The JIT below allocates and executes RWX memory. On macOS this is only
    # permitted when SIP is disabled, so we check it before.
    if lief.runtime.osx.Host.is_sip_enabled:
        print("SIP is enabled: skipping the JIT memory example", file=sys.stderr)
        return

    # Note the `JIT` flag here that is used to switch the allocated chunk into
    # R-X once the shellcode is committed.
    chunk = lief.runtime.Memory.mmap(
        lief.runtime.Process.page_size,
        lief.runtime.Memory.ANONYMOUS
        | lief.runtime.Memory.PRIVATE
        | lief.runtime.Memory.JIT,
        lief.runtime.Memory.READ | lief.runtime.Memory.WRITE,
    )

    # The message printed by the shellcode. It must stay alive while the JITed
    # function runs, so we keep a reference for the whole function.
    MSG = b"Hello World\n"
    msg = ctypes.create_string_buffer(MSG)

    # libSystem re-exports the libc symbols (write, ...)
    libsystem = lief.runtime.osx.dlopen("libSystem.B.dylib")

    # The assembler resolves the symbols referenced by the shellcode through
    # this config, mirroring the C++ ``AssemblerConfig::resolve_symbol`` override.
    class Config(lief.assembly.AssemblerConfig):
        def resolve_symbol(self, name: str) -> int | None:
            if libsystem is None:
                print("Failed to dlopen libSystem.B.dylib", file=sys.stderr)
                return None

            # Resolve the symbols that are used by the shellcode
            if name == "write":
                return lief.to_int(libsystem.dlsym("write"))
            if name == "var_msg":
                return ctypes.addressof(msg)
            if name == "var_msg_len":
                return len(MSG)
            return None

    config = Config()

    # Shellcode dynamically compiled and whose referenced symbols are resolved
    # at runtime by the provided config
    lief.runtime.assemble(
        chunk.addr,
        r"""
        .text
            .global main
            .align 2

        main:
            stp     x29, x30, [sp, -16]!
            mov     x29, sp

            // Here we use symbols that are **dynamically** resolved by the
            // AssemblerConfig
            ldr     x8, =write          // write(2) libc wrapper
            ldr     x1, =var_msg        // buffer
            ldr     w2, =var_msg_len    // length

            // write(STDOUT_FILENO, msg, len)
            mov     x0, 1
            blr     x8

            mov     x0, xzr
            ldp     x29, x30, [sp], 16
            ret
        """,
        config,
    )

    # Flush the instruction cache
    chunk.cache_flush()

    # Change the permission to R-X and invoke the JITed function
    chunk.make_rx()

    void_void_func = ctypes.CFUNCTYPE(None)  # void(*)()
    hello_jit = void_void_func(chunk.addr)

    # This call prints the message "Hello World" on the console
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
