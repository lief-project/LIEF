(format-macho)=

# {fa}`brands fa-apple` Mach-O

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

Mach-O binaries can be parsed using the {sub-ref}`lief-macho-parse` function.

:::{note}
The Mach-O format defines FAT binaries, which can embed different
architectures into a single file. {sub-ref}`lief-macho-parse` always returns a
{sub-ref}`lief-macho-fatbinary`, assuming that a non-FAT Mach-O can be represented as
a {sub-ref}`lief-macho-fatbinary` containing a single architecture.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "parse", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "parse", prepend="#include <LIEF/MachO.hpp>") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "parse") }}
:::
::::

This {sub-ref}`lief-macho-fatbinary` object exposes facilities to either iterate over the
different {sub-ref}`lief-macho-binary` or pick/take a specific one:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "iterate") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "iterate") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "iterate") }}
:::
::::

After modifying a {sub-ref}`lief-macho-binary` or {sub-ref}`lief-macho-fatbinary` object, you can
use either {sub-ref}`lief-macho-binary-write` or {sub-ref}`lief-macho-fatbinary-write` to write
it back to a raw Mach-O file.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "write-fat") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "write-fat") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "write-fat") }}
:::
::::

You can also use {sub-ref}`lief-macho-binary-write_to_bytes` to get the new Mach-O binary
as a buffer of bytes:

:::{note}
This API can also take an extra {sub-ref}`lief-macho-builder-config` parameter.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "write-bytes") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "write-bytes") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "write-bytes") }}
:::
::::

## Advanced Parsing/Writing

{sub-ref}`lief-macho-parse` can take an extra {sub-ref}`lief-macho-parser-config` parameter to specify
parts of the Mach-O format to skip during parsing.

:::{warning}
Generally, {sub-ref}`lief-macho-binary-write` and {sub-ref}`lief-macho-fatbinary-write`
require a **complete** initial parsing of the Mach-O file.
:::

Similarly, {sub-ref}`lief-macho-binary-write` can also take an extra {sub-ref}`lief-macho-builder-config`
to specify which parts of the Mach-O should be rebuilt.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "advanced") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "advanced") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "advanced") }}
:::
::::

```{eval-rst}
.. seealso::

  :ref:`binary-abstraction`

```

(format-macho-dump)=

## Dump Analysis

LIEF has the support to process Mach-O memory dump with {sub-ref}`lief-macho-parse_from_dump`. This function
translates the file offsets referenced by the Mach-O structures into their location inside
the dump, using the base address passed as the second parameter. As for the regular parser,
it returns a {sub-ref}`lief-macho-fatbinary`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "dump") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "dump") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "dump") }}
:::
::::

:::{note}
The second parameter **must** be the (absolute) virtual address at which the
dump was mapped. It is used to convert the virtual addresses found in the
Mach-O structures back into an offset within the dump.
:::

### Producing a dump with the runtime API

Such a dump can be produced from a live process thanks to the LIEF
{ref}`runtime <runtime-intro>` and, more precisely, the
{ref}`Module API <runtime_modules>`. {sub-ref}`lief-runtime-module-dump` captures the
memory of a loaded module (from its imagebase over its virtual size):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "dump-runtime") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "dump-runtime") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "dump-runtime") }}
:::
::::

(format-macho-rpath)=

## RPath and Library Path Modification

Sometimes, we need to modify the Mach-O RPath commands or the (absolute) path of
a linked library in an executable. When recompiling or linking the executable
is not possible, LIEF can be used for these modifications.

For example, let's consider a binary with the following dependencies:

```bash
$ otool -L hello.bin
hello:
      /Users/romain/dev/libmylib.dylib (compatibility version 0.0.0, current version 0.0.0)
      /usr/lib/libc++.1.dylib (compatibility version 1.0.0, current version 1700.255.0)
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.100.2)
```

One can change the directory of `libmylib.dylib` with the following code:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "rpath-change-lib") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "rpath-change-lib") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "rpath-change-lib") }}
:::
::::

:::{note}
It is worth mentioning that LIEF doesn't impose restrictions on the length of modified library
paths. LIEF manages all internal modifications to support both longer and
shorter library paths.
:::

This type of modification can be used in conjunction with the `@rpath`
feature of Mach-O binaries:

1. We can add an extra `LC_RPATH` ({sub-ref}`lief-macho-rpath`) command to `hello.bin`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "rpath-add") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "rpath-add") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "rpath-add") }}
:::
::::

2. Then, we can change the library path of `libmylib.dylib` to include the RPath prefix:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/macho.py", "rpath-atrpath") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/macho.cpp", "rpath-atrpath") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/macho.rs", "rpath-atrpath") }}
:::
::::

## Objective-C Support

If a Mach-O binary is compiled from Objective-C sources, it may contain
metadata represented by the {sub-ref}`lief-objc-metadata` object.

This metadata can help understand the underlying structures of the binary, and
{ref}`LIEF Extended <extended-intro>` provides support for accessing this
information through {sub-ref}`lief-macho-binary-objc-metadata`.

For more details, you can check the {ref}`Obj-C section <extended-objc>`.

{{ cross_api }}
