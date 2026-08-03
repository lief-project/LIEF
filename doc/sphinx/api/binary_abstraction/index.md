(binary-abstraction)=

# {fa}`brands fa-uncharted` Binary Abstraction

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

{ref}`ELF <format-elf>`, {ref}`PE <format-pe>`, {ref}`Mach-O <format-macho>`
binaries share similar characteristics, such as an entry point, imported/exported
functions, etc.

These shared characteristics are represented in an *abstract* layer, which is
defined by an inheritance relationship in C++/Python and by a trait in Rust.

Specifically, {sub-ref}`lief-elf-binary`, {sub-ref}`lief-pe-binary`, and {sub-ref}`lief-macho-binary`
either inherit or implement the trait: {sub-ref}`lief-abstract-binary`.

In Python/C++, one can access an *abstract* binary object by using the generic
{sub-ref}`lief-abstract-parse` function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/abstract.py", "parse") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/abstract.cpp", "parse") }}
:::
::::

Due to Python's dynamic polymorphism, the return value of
{py:func}`lief.parse` is automatically cast into either:
{class}`lief.ELF.Binary`, {class}`lief.PE.Binary`, or {class}`lief.MachO.Binary`.
To **upcast** this object into a {class}`lief.Binary` object, one can use the
{attr}`lief.Binary.abstract` attribute, which returns a {class}`lief.Binary`
instance:

{{ literalinclude("../../../code/python/abstract.py", "upcast") }}

In C++, a {cpp:class}`LIEF::Binary` instance can be **downcast** to its underlying
type using the `classof` idiom:

{{ literalinclude("../../../code/cpp/abstract.cpp", "downcast") }}

```{eval-rst}
.. seealso::

  - :cpp:func:`LIEF::ELF::Binary::classof`
  - :cpp:func:`LIEF::PE::Binary::classof`
  - :cpp:func:`LIEF::MachO::Binary::classof`
```

{{ cross_api }}
