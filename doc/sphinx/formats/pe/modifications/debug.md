(pe_debug_modification)=

# {fa}`solid fa-gears` Debug Modification

LIEF can create, modify, or delete PE debug information entries.

:::{figure} ../../../_static/pe_debug/overview.webp
:alt: PE Debug Overview
:scale: 50%
:::

This debug information is located in the `IMAGE_DIRECTORY_ENTRY_DEBUG` and is
represented in LIEF through the {sub-ref}`lief-pe-debug` class.

These entries can be modified using the API exposed by these structures.
For example, the PDB path referenced in a {sub-ref}`lief-pe-codeviewpdb` entry can be
changed as follows:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_debug.py", "change-name") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_debug.cpp", "change-name") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_debug.rs", "change-name") }}
:::
::::

The {sub-ref}`lief-pe-binary-remove-debug` function can be used to remove a specific
entry, whereas the {sub-ref}`lief-pe-binary-clear-debug` function removes **all**
debug entries:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_debug.py", "remove") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_debug.cpp", "remove") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_debug.rs", "remove") }}
:::
::::

Finally, {sub-ref}`lief-pe-binary-add-debug-info` can be used to add a crafted debug
entry to an existing PE.

For example, a custom {sub-ref}`lief-pe-codeviewpdb` can be created as follows:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_debug.py", "add") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_debug.cpp", "add") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_debug.rs", "add") }}
:::
::::

{{ cross_api }}
