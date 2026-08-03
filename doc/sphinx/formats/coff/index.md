(format-coff)=

# {fa}`brands fa-windows` COFF

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

COFF object files can be parsed using {sub-ref}`lief-coff-parse` or the generic
{sub-ref}`lief-parse` function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/coff.py", "parse", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/coff.cpp", "parse", prepend="#include <LIEF/COFF.hpp>") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/coff.rs", "parse") }}
:::
::::

These functions return a {sub-ref}`lief-coff-Binary` instance that exposes the main API
for processing and accessing COFF information:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/coff.py", "sections") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/coff.cpp", "sections") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/coff.rs", "sections") }}
:::
::::

(format-coff-disassembler)=

## Disassembler

The {sub-ref}`lief-coff-Binary` object exposes a disassembler API for iterating over
the instructions of a COFF binary. One can disassemble a function using
{sub-ref}`lief-coff-binary-disassemble`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/coff.py", "disassemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/coff.cpp", "disassemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/coff.rs", "disassemble") }}
:::
::::

For more details about the disassembler and the {sub-ref}`lief-asm-instruction` API,
please refer to the {ref}`Disassembler section <extended-disassembler>`.

{{ cross_api }}
