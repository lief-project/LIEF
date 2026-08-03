(runtime_host)=

# {fa}`solid fa-server` Host

The {sub-ref}`lief-runtime-host` interface exposes an API to query information about
the host on which LIEF is running. It provides a cross-platform API for
common values like the hostname and standard user directories (home, cache, ...).
Platform-specific information is provided within their own namespace/module.

## {fa}`solid fa-globe` Cross-platform

The following snippet illustrates how to retrieve the generic host
information that is available on every supported platform:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_linux.py", "host") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "host") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_linux.rs", "host") }}
:::
::::

## {fa}`brands fa-linux` Linux

The {sub-ref}`lief-runtime-linux-host` interface exposes Linux-specific host information:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_linux.py", "host-linux") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_linux.cpp", "host-linux") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_linux.rs", "host-linux") }}
:::
::::

## {fa}`brands fa-windows` Windows

The {sub-ref}`lief-runtime-windows-host` interface exposes Windows-specific host
information such as the operating system version
({sub-ref}`lief-runtime-windows-host-version`):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_windows.py", "host-windows") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_windows.cpp", "host-windows") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_windows.rs", "host-windows") }}
:::
::::

## {fa}`brands fa-apple` OSX

The {sub-ref}`lief-runtime-osx-host` interface exposes macOS-specific host
information such as whether System Integrity
Protection is enabled ({sub-ref}`lief-runtime-osx-host-is-sip-enabled`):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_osx.py", "host-osx") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_osx.cpp", "host-osx") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_osx.rs", "host-osx") }}
:::
::::

## {fa}`brands fa-android` Android

The {sub-ref}`lief-runtime-android-host` interface exposes Android-specific host
information such as the device's SDK/API level
({sub-ref}`lief-runtime-android-host-sdk_version`):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../examples/python/runtime_android.py", "host-android") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../examples/cpp/runtime_android.cpp", "host-android") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../examples/rust/runtime_android.rs", "host-android") }}
:::
::::

{{ cross_api }}
