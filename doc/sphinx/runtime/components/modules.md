---
description: Enumerate loaded modules, resolve symbols, parse files and in-memory images, and interpret live addresses with the LIEF runtime API.
---

(runtime_modules)=

# {fa}`solid fa-cubes` Modules

The {sub-ref}`lief-runtime-module` interface exposes the different modules
(executables and shared libraries) that are loaded in the current process.
It is a cross-platform API and is extended on each supported platform with
OS-specific helpers (e.g. {sub-ref}`lief-runtime-linux-module`,
{sub-ref}`lief-runtime-windows-module`, {sub-ref}`lief-runtime-osx-module`).

## Enumerate and locate modules

The following Linux example enumerates the loaded modules, prints their
attributes, and selects `libc` for later inspection. The enumeration API is shared
by all supported platforms:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_linux.py", "modules") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "modules") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_linux.rs", "modules") }}
:::
::::

For a direct lookup, use {sub-ref}`lief-runtime-module_from_name`,
{sub-ref}`lief-runtime-module_from_path`, or {sub-ref}`lief-runtime-module_from_addr`.
Name and path lookups use exact matches. Address lookup expects an absolute
address in the current process.

{sub-ref}`lief-runtime-current_module` returns the module that contains the
code calling it: from C++, the executable or the library that makes the call.
From Rust it is the executable or the library that embeds the `lief` crate and from
Python, the module of LIEF's native extension.

The platform-specific module interfaces let you parse an image from its path on
disk or from its current mapping:

| Operation | Result |
| --- | --- |
| Parse from the module's path | The executable file as stored on disk, using its file layout |
| Parse from memory | The loaded image, which may contain relocations and runtime changes |
| {sub-ref}`lief-runtime-module-dump` | Raw bytes from the module's mapped address range |

Parsing produces a LIEF binary object for analysis. Modifying that object does
not automatically patch the running module. You should use the {ref}`memory API <runtime_memory>`
when you intend to write to the process's memory.

A raw memory dump is not necessarily a valid on-disk executable. For offline
analysis, use the dump-parsing APIs documented for {ref}`ELF <format-elf-dump>`,
{ref}`PE <format-pe-dump>`, and {ref}`Mach-O <format-macho-dump>`.

## {fa}`brands fa-linux` Linux

On Linux, {sub-ref}`lief-runtime-linux-module` extends the generic interface with
platform-specific helpers. In particular, it exposes the {sub-ref}`lief-runtime-linux-dlopen`
& {sub-ref}`lief-runtime-linux-module-dlsym` and can parse the
module directly from its path on disk or from its in-memory representation.
The following snippet demonstrates these operations on the `libc` module:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_linux.py", "modules-linux") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "modules-linux") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_linux.rs", "modules-linux") }}
:::
::::

## {fa}`brands fa-windows` Windows

On Windows, you can perform similar operations such as in-memory parsing, accessing
the `HMODULE` handle, and resolving functions through a dlsym-like helper:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_windows.py", "modules-windows") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_windows.cpp", "modules-windows") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_windows.rs", "modules-windows") }}
:::
::::

## {fa}`brands fa-apple` macOS

System libraries can be located in the {ref}`Dyld shared cache <extended-dsc>` even
when their module paths look like ordinary files. In that case, parsing from the
path can fail. The example below parses the mapped library from memory and lists
its exported symbols:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_osx.py", "modules-osx") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_osx.cpp", "modules-osx") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_osx.rs", "modules-osx") }}
:::
::::

## {fa}`brands fa-android` Android

On Android, {sub-ref}`lief-runtime-android-module` extends the generic interface with
the same helpers as on Linux: loading a library with
{sub-ref}`lief-runtime-android-dlopen`, resolving symbols with
{sub-ref}`lief-runtime-android-module-dlsym` and parsing modules from their path on
disk. The following snippet
demonstrates these operations on the Bionic `libc` and `liblog` modules:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_android.py", "modules-android") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_android.cpp", "modules-android") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_android.rs", "modules-android") }}
:::
::::

{{ cross_api }}
