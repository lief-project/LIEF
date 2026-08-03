(format-pe)=

# {fa}`brands fa-windows` PE

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-gears">&nbsp;</i>Modifications
  :maxdepth: 1

  modifications/imports
  modifications/resources
  modifications/tls
  modifications/debug
  modifications/exports
```

## Introduction

PE binaries can be parsed using the {sub-ref}`lief-pe-parse` function.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "parse", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "parse", prepend="#include <LIEF/PE.hpp>") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "parse") }}
:::
::::

:::{note}
In Python, you can also use the generic {py:func}`lief.parse`, which returns a
{class}`lief.PE.Binary` object.
:::

With the parsed PE binary, you can use the {sub-ref}`lief-pe-binary` API to
inspect or modify the binary itself.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "inspect") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "inspect") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "inspect") }}
:::
::::

After modifying a {sub-ref}`lief-pe-binary` object, you can use {sub-ref}`lief-pe-binary-write` to
write the changes back to a raw PE file.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "add-section") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "add-section") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "add-section") }}
:::
::::

```{eval-rst}
.. seealso::

  :ref:`binary-abstraction`

```

(format-pe-dump)=

## Dump Analysis

LIEF has the support to process PE memory dump with {sub-ref}`lief-pe-parse_from_dump`. This function
translates the file offsets referenced by the PE structures into their location inside
the dump, using the base address passed as the second parameter:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "dump") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "dump") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "dump") }}
:::
::::

:::{note}
The second parameter **must** be the (absolute) virtual address at which the
dump was mapped. It is used to convert the RVAs found in the PE structures
back into an offset within the dump.
:::

### Producing a dump with the runtime API

Such a dump can be produced from a live process thanks to the LIEF
{ref}`runtime <runtime-intro>` and, more precisely, the
{ref}`Module API <runtime_modules>`. {sub-ref}`lief-runtime-module-dump` captures the
memory of a loaded module (from its imagebase over its virtual size):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "dump-runtime") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "dump-runtime") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "dump-runtime") }}
:::
::::

## Advanced Parsing/Writing

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-gears">&nbsp;</i>Modifications
  :maxdepth: 1

  modifications/imports
  modifications/resources
  modifications/tls
```

{sub-ref}`lief-pe-parse` can take an extra {sub-ref}`lief-pe-parser-config` parameter to specify
parts of the PE format to ignore during parsing.

:::{warning}
Generally, {sub-ref}`lief-pe-binary-write` requires a **complete** initial
parsing of the PE file.
:::

Similarly, {sub-ref}`lief-pe-binary-write` can take an extra {sub-ref}`lief-pe-builder-config`
parameter to include or ignore parts of the PE binary during the build
process.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "advanced") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "advanced") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "advanced") }}
:::
::::

You can also use {sub-ref}`lief-pe-binary-write_to_bytes` to get the new PE binary
as a buffer of bytes:

:::{note}
This API can also take an extra {sub-ref}`lief-pe-builder-config` parameter.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "write-bytes") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "write-bytes") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "write-bytes") }}
:::
::::

## PDB Support

Using {ref}`LIEF Extended <extended-intro>`, you can access PDB debug information
({sub-ref}`lief-pdb-debug-info`) using the {sub-ref}`lief-pdb-binary-debug-info` function.

For more details regarding PDB support, please refer to the
{ref}`PDB section <extended-pdb>`.

## Authenticode

LIEF supports PE Authenticode by providing an API for inspecting and
**verifying** PE executable signatures.

PE Authenticode signatures can be accessed by iterating over
{sub-ref}`lief-pe-binary-signatures`. The {sub-ref}`lief-pe-binary-verify_signature` function can
be used to verify that a PE binary is correctly signed.

:::{note}
Typically, a signed PE executable contains a single signature, but the
format allows for multiple signatures. Consequently,
{sub-ref}`lief-pe-binary-signatures` returns an iterator rather than a single
signature object.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/pe.py", "authenticode") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/pe.cpp", "authenticode") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/pe.rs", "authenticode") }}
:::
::::

You can find additional details about Authenticode support in this tutorial:
{ref}`PE Authenticode <pe-authenticode>`

{{ cross_api }}
