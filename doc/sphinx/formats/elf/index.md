(format-elf)=

# {fa}`brands fa-linux` ELF

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

ELF binaries can be parsed with LIEF using the {sub-ref}`lief-elf-parse` function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "parse", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "parse", prepend="#include <LIEF/ELF.hpp>") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "parse") }}
:::
::::

:::{note}
In Python, you can also use {py:func}`lief.parse`, which returns a
{class}`lief.ELF.Binary` object.
:::

With the parsed ELF binary, you can use the {sub-ref}`lief-elf-binary` API to
inspect or modify the binary itself.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "inspect") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "inspect") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "inspect") }}
:::
::::

After modifying a {sub-ref}`lief-elf-binary` object, you can use the
{sub-ref}`lief-elf-binary-write` method to write it back to a raw ELF file.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "write") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "write") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "write") }}
:::
::::

```{eval-rst}
.. seealso::

  :ref:`binary-abstraction`
```

You can also use {sub-ref}`lief-elf-binary-write_to_bytes` to get the new ELF binary
as a buffer of bytes:

:::{note}
This API can also take an extra {sub-ref}`lief-elf-builder-config` parameter.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "write-bytes") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "write-bytes") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "write-bytes") }}
:::
::::

(format-elf-section-segment)=

## Adding a Section/Segment

The ELF format uses two tables to represent different slices of the binary:

1. The sections table
2. The segments table

While the sections table offers a detailed view of the binary, it is primarily
used by the **compiler** and the **linker**. In particular, this table is not required
for **loading** and **executing** an ELF file. While the Android loader
enforces the presence of a sections table and requires specific sections,
this table is not used during the actual loading process.

To modify an ELF file to load additional content into memory (e.g., code or data),
adding a {sub-ref}`lief-elf-segment` is recommended over adding a section:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "add-segment") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "add-segment") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "add-segment") }}
:::
::::

Alternatively, you can create a {sub-ref}`lief-elf-section`, which will **implicitly**
create an associated `PT_LOAD` segment:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "add-section-loaded") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "add-section-loaded") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "add-section-loaded") }}
:::
::::

As mentioned above, the segments table is more critical than the sections table
from a loading perspective. Therefore, it is more appropriate to explicitly add
a new segment rather than adding a section that implicitly adds a segment.

On the other hand, for debugging purposes or specialized tools, you might want
to add a **non-loaded** section. In this case, the section data is inserted at
the end of the binary, immediately after the data wrapped by the segments:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "add-section-unloaded") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "add-section-unloaded") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "add-section-unloaded") }}
:::
::::

See: {sub-ref}`lief-elf-binary-add` for detailed API information.

(format-elf-dump)=

## Dump Analysis

LIEF has the support to process ELF memory dump with {sub-ref}`lief-elf-parse_from_dump`. This function
translates the file offsets referenced by the ELF structures into their location inside
the dump, using the base address passed as the second parameter:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "dump") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "dump") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "dump") }}
:::
::::

:::{note}
The second parameter **must** be the (absolute) virtual address at which the
dump was mapped. It is used to convert the virtual addresses found in the ELF
structures back into an offset within the dump.
:::

:::{warning}
Parsing an ELF from a dump is subject to the same limitations as
parsing it from memory: the segments (`PT_LOAD`) and the program headers are
reliable, but the **section header table is generally not mapped** and the
content of the dynamic table (dynamic entries, dynamic symbols and
relocations) reflects its *runtime* state and may not be recoverable. Prefer
working with the segments when analyzing a dump.
:::

### Producing a dump with the runtime API

Such a dump can be produced from a live process thanks to the LIEF
{ref}`runtime <runtime-intro>` and, more precisely, the
{ref}`Module API <runtime_modules>`. {sub-ref}`lief-runtime-module-dump` captures the
memory of a loaded module (from its imagebase over its virtual size):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "dump-runtime") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "dump-runtime") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "dump-runtime") }}
:::
::::

## Advanced Parsing/Writing

{sub-ref}`lief-elf-parse` can take an extra {sub-ref}`lief-elf-parser-config` parameter to specify
parts of the ELF format to skip during parsing.

:::{warning}
Generally, {sub-ref}`lief-elf-binary-write` requires a **complete** initial
parsing of the ELF file.
:::

Similarly, {sub-ref}`lief-elf-binary-write` can also take an extra {sub-ref}`lief-elf-builder-config`
to specify which parts of the ELF should be rebuilt.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "advanced") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "advanced") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "advanced") }}
:::
::::

## DWARF Support

If the binary embeds DWARF debug information, you can use
{sub-ref}`lief-dwarf-binary-debug-info` to access the underlying {sub-ref}`lief-dwarf-debug-info`
object.

Note that this support is only available in the {ref}`Extended <extended-intro>`
version of LIEF.

(format-elf-rpath-modification)=

## R[UN]PATH Modification

LIEF provides comprehensive facilities for manipulating a binary's RPATH/RUNPATH.

:::{admonition} DT_RPATH vs DT_RUNPATH
:class: tip

`DT_RPATH` and `DT_RUNPATH` are both dynamic tags used to
specify runtime library search paths.

`DT_RPATH` is now considered legacy because it does not respect the
precedence of the `LD_LIBRARY_PATH` environment variable. This means that
if `LD_LIBRARY_PATH` is set to a valid directory where the library can
be found, it will be ignored in favor of the `DT_RPATH` value.
Therefore, the `DT_RUNPATH` tag should be preferred over `DT_RPATH`.

Note that if both tags are present, the loader will use the `DT_RUNPATH`
entry over the legacy `DT_RPATH`.
:::

The `DT_RPATH` tag is represented by the {sub-ref}`lief-elf-DynamicEntryRpath`
interface, and the `DT_RUNPATH` tag by {sub-ref}`lief-elf-DynamicEntryRunPath`.

The RPATH/RUNPATH modifications supported by LIEF include:

**Adding a new entry**

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "rpath-add") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "rpath-add") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "rpath-add") }}
:::
::::

**Changing an entry**

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "rpath-change") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "rpath-change") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "rpath-change") }}
:::
::::

**Removing entries**

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "rpath-remove") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "rpath-remove") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "rpath-remove") }}
:::
::::

You can also check the {ref}`lief-patchelf <tools-lief-patchelf>` section for a
command-line interface.

(format-elf-symbols-version)=

## Symbol Versions

The ELF format supports symbol versioning, allowing multiple versions of
the same function or variable to coexist within a single shared object.

During compilation, the linker selects the appropriate symbols and versions
based on the libraries provided as input. For example, if a program uses the
`printf` function and is linked with a version of `libc.so` that exposes
`printf@@GLIBC_2.40`, the compiled executable will require at least that
version of the `libc` to run.

These versioning requirements can be problematic when creating executables or
libraries intended for a wide range of Linux distributions.

The **best way** to ensure maximum compatibility is to target the minimum
supported version of Glibc. For instance, if you aim to support Linux
distributions with at least Glibc version `2.28` (released in 2018), you
should specifically provide that version of `libc.so` during linking:

```console
$ ld --sysroot=/sysroot/glibc-2.28/ my_program.o -o my_program.elf
$ ld -L /sysroot/glibc-2.28/lib64/ my_program.o -o my_program.elf -lc
```

In situations where you lack control over the link step, you may want to change
the versioning **post-compilation**. LIEF can be used in these situations to
perform the following modifications on symbol versions.

**Remove the version for a specific symbol**

In this example, we remove the version attached to the `printf` symbol
by setting the versioning as global (the default setting for imported functions).

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "symver-symbol") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "symver-symbol") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "symver-symbol") }}
:::
::::

**Remove all the versions for a specific library**

In this example, we remove all the symbol versions associated with an imported
library (`libm.so.6`):

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/elf.py", "symver-library") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/elf.cpp", "symver-library") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/elf.rs", "symver-library") }}
:::
::::

::::{tabs}
:::{tab} {fa}`solid fa-terminal` Before
```{code-block} console
$ readelf -V input.elf

Version symbols section '.gnu.version' contains 48 entries:
 Addr: 00000000000009bc  Offset: 0x0009bc  Link: 6 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  004:   2 (GLIBC_2.2.5)   0 (*local*)       4 (GLIBC_2.17)    3 (GLIBC_2.2.5)
  008:   2 (GLIBC_2.2.5)   5 (GLIBC_2.27)    2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
  00c:   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   6 (GLIBC_2.4)     2 (GLIBC_2.2.5)
  010:   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
  014:   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   0 (*local*)
  018:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
  01c:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  020:   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  024:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
  028:   3 (GLIBC_2.2.5)   0 (*local*)       3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
  02c:   3 (GLIBC_2.2.5)   7 (GLIBC_2.29)    2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)

Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0000000000000a20  Offset: 0x000a20  Link: 7 (.dynstr)
  0x0000: Version: 1  File: libm.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.29  Flags: none  Version: 7
  0x0020:   Name: GLIBC_2.27  Flags: none  Version: 5
  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 3
  0x0040: Version: 1  File: libc.so.6  Cnt: 3
  0x0050:   Name: GLIBC_2.4  Flags: none  Version: 6
  0x0060:   Name: GLIBC_2.17  Flags: none  Version: 4
  0x0070:   Name: GLIBC_2.2.5  Flags: none  Version: 2
```
:::
:::{tab} {fa}`solid fa-terminal` After
```{code-block} console
$ readelf -V updated.elf

Version symbols section '.gnu.version' contains 48 entries:
 Addr: 00000000000009bc  Offset: 0x0009bc  Link: 6 (.dynsym)
  000:   0 (*local*)       1 (*global*)      1 (*global*)      1 (*global*)
  004:   1 (*global*)      0 (*local*)       4 (GLIBC_2.17)    1 (*global*)
  008:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  00c:   1 (*global*)      1 (*global*)      6 (GLIBC_2.4)     1 (*global*)
  010:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  014:   1 (*global*)      1 (*global*)      1 (*global*)      0 (*local*)
  018:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  01c:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  020:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  024:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
  028:   1 (*global*)      0 (*local*)       1 (*global*)      1 (*global*)
  02c:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)

Version needs section '.gnu.version_r' contains 1 entries:
 Addr: 0000000000000a20  Offset: 0x000a20  Link: 7 (.dynstr)
  0x0000: Version: 1  File: libc.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.4  Flags: none  Version: 6
  0x0020:   Name: GLIBC_2.17  Flags: none  Version: 4
  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 2
```
:::
::::

{{ cross_api }}
