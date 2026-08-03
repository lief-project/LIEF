(runtime_process)=

# {fa}`solid fa-gears` Process

The {sub-ref}`lief-runtime-process` interface exposes an API to query information
about the current process. It provides cross-platform API and is extended
on each platform with additional OS-specific helpers.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_linux.py", "process") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "process") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_linux.rs", "process") }}
:::
::::

## {fa}`brands fa-linux` Linux

On Linux, {sub-ref}`lief-runtime-linux-process` extends the generic interface with
platform-specific helpers. For instance,
{sub-ref}`lief-runtime-linux-process-glibc_version` returns the version of the GNU
C Library loaded in the current process:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_linux.py", "process-linux") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "process-linux") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_linux.rs", "process-linux") }}
:::
::::

## {fa}`brands fa-windows` Windows

On Windows, the process interface is extended with
{sub-ref}`lief-runtime-windows-process` which exposes the Process Environment
Block (PEB) of the current process. The returned {sub-ref}`lief-runtime-windows-peb`
object provides access to some fields of the structure (whether the
process is being debugged, the loader data, the process parameters, ...):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_windows.py", "process-windows") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_windows.cpp", "process-windows") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_windows.rs", "process-windows") }}
:::
::::

The loader's module list is exposed through {sub-ref}`lief-runtime-windows-peb-entries`,
which yields {sub-ref}`lief-runtime-windows-ldr` objects. In addition to
the base name and image base, each entry exposes the extended
`LDR_DATA_TABLE_ENTRY` fields.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_windows.py", "peb-module-details") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_windows.cpp", "peb-module-details") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_windows.rs", "peb-module-details") }}
:::
::::

## {fa}`brands fa-apple` OSX

On macOS, {sub-ref}`lief-runtime-osx-process` extends the generic interface with
platform-specific helpers. For instance, {sub-ref}`lief-runtime-osx-process-dyld_version`
returns the version of `dyld` (the dynamic loader) in the current process:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_osx.py", "process-osx") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_osx.cpp", "process-osx") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_osx.rs", "process-osx") }}
:::
::::

## {fa}`brands fa-android` Android

On Android, {sub-ref}`lief-runtime-android-process` extends the generic interface. Here are
some examples of the API:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_android.py", "process-android") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_android.cpp", "process-android") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_android.rs", "process-android") }}
:::
::::

{{ cross_api }}
