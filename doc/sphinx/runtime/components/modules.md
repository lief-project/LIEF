(runtime_modules)=

# {fa}`solid fa-cubes` Modules

The {sub-ref}`lief-runtime-module` interface exposes the different modules
(executables and shared libraries) that are loaded in the current process.
It is a cross-platform API and is extended on each supported platform with
OS-specific helpers (e.g. {sub-ref}`lief-runtime-linux-module`,
{sub-ref}`lief-runtime-windows-module`, {sub-ref}`lief-runtime-osx-module`).

The following snippet shows how to iterate over the modules loaded in the
current process and how to access common attributes such as the imagebase
or the name:

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

## {fa}`brands fa-apple` OSX

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
