(runtime_memory)=

# {fa}`solid fa-memory` Memory

The {sub-ref}`lief-runtime-memory` interface exposes an API to allocate, inspect and
manipulate memory in the current process. It can be used to map anonymous
pages, change their protection and read or write from any virtual address.

Combined with {sub-ref}`lief-runtime-assemble`, it enables lightweight JIT
code generation directly from LIEF, while {sub-ref}`lief-runtime-disassemble` can be
used to disassemble code directly from memory.

## {fa}`brands fa-linux` Linux x86-64

The following snippet allocates a writable and executable page, assembles a
small x86-64 stub inside it that prints `LIEF Runtime Extended Demo`, calls
the resulting function, and rewrites part of the buffer before invoking it
again:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_linux.py", "memory") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "memory") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_linux.rs", "memory") }}
:::
::::

## {fa}`brands fa-windows` Windows ARM64

:::{admonition} x86-64
:class: tip

This part focuses on the ARM64 architecture but it works in the exact same way
for Windows x86-64.
:::

Similarly, we can JIT a `Hello World` shellcode on Windows ARM64 with the
following snippet:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_windows.py", "memory") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_windows.cpp", "memory") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_windows.rs", "memory") }}
:::
::::

Note that this shellcode uses the external functions `GetStdHandle` and
`WriteFile` that are **dynamically** resolved and injected into the shellcode
**at runtime**. The shellcode is thus generated with dynamic information that
would otherwise have been tedious to resolve at the assembly level.

## {fa}`brands fa-apple` OSX ARM64

:::{admonition} SIP
:class: warning

Allocating and executing JIT memory on macOS requires System Integrity
Protection (SIP) to be disabled. The snippet below therefore only runs the
JIT part when {sub-ref}`lief-runtime-osx-host-is-sip-enabled` reports that SIP is
disabled.
:::

Similarly, we can JIT a `Hello World` shellcode on macOS ARM64. The shellcode
calls `write`, which is **dynamically** resolved from `libSystem` at
runtime:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_osx.py", "memory") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_osx.cpp", "memory") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_osx.rs", "memory") }}
:::
::::

## {fa}`brands fa-android` Android ARM64

Similarly, we can JIT a small AArch64 stub on Android to print
`LIEF Runtime Extended Demo`. The Python tab calls `write`,
which is **dynamically** resolved from Bionic `libc` at runtime:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../api/python/examples/runtime_android.py", "memory") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_android.cpp", "memory") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../api/rust/examples/src/bin/runtime_android.rs", "memory") }}
:::
::::

{{ cross_api }}
