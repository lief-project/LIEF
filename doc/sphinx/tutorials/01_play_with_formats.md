# 01 - Parse and manipulate formats

The objective of this tutorial is to provide an overview of LIEF's API for
parsing and manipulating formats.

______________________________________________________________________

## ELF

We'll start with the `ELF` format. To create an {class}`.ELF.Binary` from a
file, simply pass its path to the {sub-ref}`lief-abstract-parse` or {sub-ref}`lief-elf-parse`
functions.

:::{note}
With the Python API, these functions exhibit the same behavior, but in C++,
{sub-ref}`lief-abstract-parse` will return a pointer to a
{sub-ref}`lief-abstract-binary` object, whereas {sub-ref}`lief-elf-parse`
will return a {sub-ref}`lief-elf-binary` object.
:::

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-parse", prepend="import lief") }}

Once the ELF file has been parsed, we can access its {class}`~lief.ELF.Header`:

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-header") }}

To change the entry point and the target architecture ({class}`~lief.ELF.ARCH`):

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-change-header") }}

Then, write these changes to a new ELF binary:

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-write") }}

We can also iterate over the {class}`~lief.ELF.Section` entries as follows:

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-sections") }}

To modify the content of the `.text` section:

{{ literalinclude("../../code/python/tuto_play_formats.py", "elf-text") }}

## PE

As with the `ELF` section, you can use the {sub-ref}`lief-abstract-parse` or
{sub-ref}`lief-pe-parse` functions to create a {class}`.PE.Binary`

{{ literalinclude("../../code/python/tuto_play_formats.py", "pe-parse", prepend="import lief") }}

To access the various PE headers ({class}`~lief.PE.DosHeader`,
{class}`~lief.PE.Header`, and {class}`~lief.PE.OptionalHeader`):

{{ literalinclude("../../code/python/tuto_play_formats.py", "pe-headers") }}

You can also access imported functions in two ways:

1. Using the *abstract* layer
2. Using the PE definition

{{ literalinclude("../../code/python/tuto_play_formats.py", "pe-imports") }}

For finer granularity regarding the location of imported functions in libraries,
or to access other fields of the PE imports, we can process the imports as
follows:

{{ literalinclude("../../code/python/tuto_play_formats.py", "pe-imports-detailed") }}

{{ cross_api }}
