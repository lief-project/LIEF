(extended-pdb)=

# {fa}`brands fa-windows` PDB

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

Unlike DWARF debug information, PDB debug information is always stored
externally from the original binary. Nevertheless, the original binary keeps
the path of the PDB file in the {sub-ref}`lief-pe-codeviewpdb-filename` attribute.

Based on this fact, {sub-ref}`lief-pdb-binary-debug-info` tries to instantiate a
{sub-ref}`lief-pdb-debug-info` object using this file path. If it fails, it returns
`nullptr` or `None`.

You can also instantiate a {sub-ref}`lief-pdb-debug-info` object using {sub-ref}`lief-pdb-load`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pdb.py", "load") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pdb.cpp", "load") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pdb.rs", "load") }}
:::
::::

At this point, the PDB instance ({sub-ref}`lief-pdb-debug-info`) can be used to explore
the PDB debug information:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pdb.py", "explore") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pdb.cpp", "explore") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pdb.rs", "explore") }}
:::
::::

(extended-pdb-load-ext)=

You can also use the {sub-ref}`lief-abstract-binary-load_debug_info` function to bind
a PDB file to an existing {sub-ref}`lief-abstract-binary`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pdb.py", "load-ext") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pdb.cpp", "load-ext") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pdb.rs", "load-ext") }}
:::
::::

Note that {sub-ref}`lief-abstract-binary-load_debug_info` can also attach an external
DWARF file to a PE binary, even though this is not a typical use case.
For instance, the {ref}`BinaryNinja <plugins-binaryninja-dwarf>` and
{ref}`Ghidra <plugins-ghidra-dwarf>` DWARF export plugins can generate
a DWARF file for a PE binary based on analysis performed by these frameworks.

This external loading API is useful for adding debug information that might not
already be present in the binary. For instance, the {sub-ref}`lief-disassemble` function
can leverage this additional debug information to disassemble functions
defined in the debug file previously loaded:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pdb.py", "disassemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pdb.cpp", "disassemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pdb.rs", "disassemble") }}
:::
::::

(extended-pdb-to-decl)=

## Generating C/C++ Definitions

PDB types, functions and compilation units can be turned into C/C++ definitions
using the `to_decl()` function:

- {sub-ref}`lief-pdb-type-to_decl`
- {sub-ref}`lief-pdb-function-to_decl`
- {sub-ref}`lief-pdb-cu-to_decl`

The generated output can be configured with a {sub-ref}`lief-declopt` structure:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pdb.py", "to-decl") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pdb.cpp", "to-decl") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pdb.rs", "to-decl") }}
:::
::::

______________________________________________________________________

## API

You can find the documentation of the API for the different languages here:

{fa}`brands fa-python` {doc}`Python API <python>`

{fa}`regular fa-file-code` {doc}`C++ API <cpp>`

{fa}`brands fa-rust` Rust API: {rust:module}`lief::pdb`

{{ cross_api }}
