# {fa}`solid fa-gears` Exports Modification

:::{figure} ../../../_static/pe_exports/overview.webp
:alt: PE Resources Overview
:scale: 50%
:::

LIEF provides extensive support for modifying the PE export table, enabling you
to add, remove, or modify export entries, or create an entire export table for
a PE binary.

This functionality requires enabling {sub-ref}`lief-pe-builder-config-exports`, as the
modified export table is **relocated** to a **new** section. The section name
can be controlled with {sub-ref}`lief-pe-builder-config-export_section`.

## Creating Export Entries

Creating a {sub-ref}`lief-pe-export-entry` is useful for exposing a "hidden" function by
its address, allowing it to be used like a standard linker-generated export.

This could be used for code lifting or fuzzing.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_exports.py", "create-entries") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_exports.cpp", "create-entries") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_exports.rs", "create-entries") }}
:::
::::

## Creating an Export Table

This section introduces the API for creating an export table. We'll explore a
scenario where we want to convert a PE executable into a DLL.

:::{note}
The process of converting an executable to a library is also detailed for ELF
binaries in the tutorial: {ref}`tuto_elf_bin2lib`.
:::

First, we must update the PE headers to ensure they are compliant with the DLL
format:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_exports.py", "dll-header") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_exports.cpp", "dll-header") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_exports.rs", "dll-header") }}
:::
::::

Then, we can start creating and populating a new export table:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_exports.py", "create-table") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_exports.cpp", "create-table") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_exports.rs", "create-table") }}
:::
::::

:::{admonition} Limitations
:class: tip

This binary-to-library example assumes that the original executable was
compiled to be position-independent, meaning it contains relocations.
:::

Within a Python environment, we can verify that `lib_exe2dll.dll` can be
loaded as a DLL and that we can call `cbk1` and `cbk2`:

```python
import ctypes

lib = ctypes.windll.LoadLibrary("lib_exe2dll.dll")

assert lib.cbk1() >= 0
assert lib.cbk2() >= 0
```

{{ cross_api }}
