# {fa}`solid fa-hand-holding-hand` Utilities

## Demangling

LIEF exposes a demangling API for the following formats:

::::{tabs}
:::{tab} {fa}`brands fa-windows` MSVC
**Input**

{{ literalinclude("../../../code/python/utilities.py", "demangle-msvc") }}

**Result**

```{code-block} text
void __cdecl h(int)
```
:::
:::{tab} {fa}`brands fa-rust` Rust
**Input**

{{ literalinclude("../../../code/python/utilities.py", "demangle-rust") }}

**Result**

```{code-block} text
foo::example_function
```
:::
:::{tab} {fa}`regular fa-file-code` Itanium C++
**Input**

{{ literalinclude("../../../code/python/utilities.py", "demangle-itanium") }}

**Result**

```{code-block} text
typeinfo name for lld::SpecificAlloc<lld::coff::TpiSource>
```
:::
:::{tab} {fa}`brands fa-swift` Swift/Obj-C
**Input**

{{ literalinclude("../../../code/python/utilities.py", "demangle-swift") }}

**Result**

```{code-block} text
type metadata for Foundation.Data._Representation
```
:::
::::

```{eval-rst}
.. doxygenfunction:: LIEF::demangle
```

```{eval-rst}
.. autofunction:: lief.demangle
```

{fa}`brands fa-rust` {rust:func}`lief::demangle`

## Extended Version

To check if the current build is an {ref}`extended <extended-intro>` version,
you can use:

```{eval-rst}
.. doxygenfunction:: LIEF::is_extended
```

```{eval-rst}
.. autodata:: lief._lief.__extended__
```

{rust:func}`lief::is_extended`

In C++, you can also check if `LIEF_EXTENDED` is defined:

```cpp
#include <LIEF/config.hpp>

#if defined(LIEF_EXTENDED)
// Extended version
#else
// Regular version
#endif
```

To get details about the version of the current extended build:

```{eval-rst}
.. doxygenfunction:: LIEF::extended_version_info
```

## Android Platform

```{eval-rst}
.. autofunction:: lief.Android.code_name
```

```{eval-rst}
.. autofunction:: lief.Android.version_string
```

```{eval-rst}
.. autoclass:: lief.Android.ANDROID_VERSIONS
  :members:
  :inherited-members:
  :undoc-members:
```

```{eval-rst}
.. doxygenfunction:: LIEF::Android::code_name
```

```{eval-rst}
.. doxygenfunction:: LIEF::Android::version_string
```

```{eval-rst}
.. doxygenenum:: LIEF::Android::ANDROID_VERSIONS
```

## Python Leaks

```{eval-rst}
.. autofunction:: lief.disable_leak_warning
```

## Helpers

The `lief.dump()` utility can be used to pretty-print a buffer.

For example:

{{ literalinclude("../../../code/python/utilities.py", "dump") }}

```{eval-rst}
.. autofunction:: lief.dump
```

```{eval-rst}
.. doxygenfunction:: LIEF::dump(const std::vector<uint8_t> &data, const std::string &title = "", const std::string &prefix = "", size_t limit = 0)
```

```{eval-rst}
.. doxygenfunction:: LIEF::dump(const uint8_t *buffer, size_t size, const std::string &title = "", const std::string &prefix = "", size_t limit = 0)
```

```{eval-rst}
.. doxygenfunction:: LIEF::dump(span<const uint8_t> data, const std::string &title = "", const std::string &prefix = "", size_t limit = 0)
```

- {fa}`brands fa-rust` {rust:func}`lief::dump`
- {fa}`brands fa-rust` {rust:func}`lief::dump_with_limit`

{{ cross_api }}
