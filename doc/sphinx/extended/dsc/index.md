(extended-dsc)=

# {fa}`solid fa-diagram-predecessor` Dyld Shared Cache

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

LIEF's Dyld shared cache support enables the inspection and extraction of
libraries from the Apple Dyld shared cache.

One can load a shared cache using the {sub-ref}`lief-dsc-load` function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dsc.py", "load", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dsc.cpp", "load", prepend="#include <LIEF/DyldSharedCache.hpp>") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dsc.rs", "load") }}
:::
::::

:::{warning}
{sub-ref}`lief-dsc-load` takes as input either a directory for loading the **whole**
shared cache or a set of files to load a subset of the cache.
:::

From this {sub-ref}`lief-dsc-dyldsharedcache` object, we can inspect the embedded
{sub-ref}`lief-dsc-dylib` as follows:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dsc.py", "libraries") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dsc.cpp", "libraries") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dsc.rs", "libraries") }}
:::
::::

It is worth mentioning that {sub-ref}`lief-dsc-dylib` exposes the {sub-ref}`lief-dsc-dylib-get`
method, which can be used to **extract** a {sub-ref}`lief-macho-binary` instance from
Dyld shared cache libraries:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dsc.py", "extract") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dsc.cpp", "extract") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dsc.rs", "extract") }}
:::
::::

Finally, we can leverage the {sub-ref}`lief-macho-binary-write` function to write back
the {sub-ref}`lief-macho-binary` object:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dsc.py", "write") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dsc.cpp", "write") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/dsc.rs", "write") }}
:::
::::

:::{warning}
By default, LIEF **does not** remove Dyld shared cache optimizations.
To remove some of these optimizations, you can check the {sub-ref}`lief-dsc-dylib-eopt`
structure.
:::

## {fa}`solid fa-stopwatch` Performance Considerations

Dyld shared cache files are quite large, meaning they cannot be processed in
the same way as standard {sub-ref}`lief-macho-binary` or {sub-ref}`lief-elf-binary` binaries.

The Dyld shared cache support in LIEF follows the principle:
*don't pay overhead for what you don't access*. This is the opposite of the
implementation of {sub-ref}`lief-pe-parse`, {sub-ref}`lief-macho-parse`, and {sub-ref}`lief-elf-parse`.

:::{note}
These functions parse all format structures (with decent performance)
because:

1. Most binary sizes are less than one gigabyte.
2. A complete representation is required for modifying binaries.
:::

From a technical perspective, LIEF uses a {cpp:class}`LIEF::FileStream` to
access Dyld shared cache structures on demand. Thus, in-memory consumption
is limited to the size of the structures being accessed. The drawback of
using {cpp:class}`~LIEF::FileStream` is that because it uses file-based access,
it takes more time compared to a {cpp:class}`LIEF::VectorStream`.

Additionally, LIEF's Dyld shared cache implementation **heavily** relies on
the iterator pattern to follow the principle: *don't pay overhead for what you don't access*.

For instance, {sub-ref}`lief-dsc-dyldsharedcache-libraries` returns an **iterator**
over the {sub-ref}`lief-dsc-dylib`. Therefore, if you don't iterate, you don't pay for the
access and parsing of the {sub-ref}`lief-dsc-dylib` objects.

Where possible, LIEF implements the random access iterator trait [^footnote-1]
so that we can programmatically do:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/dsc.py", "random-access") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/dsc.cpp", "random-access") }}
:::
::::

When extracting a {sub-ref}`lief-macho-binary` from a {sub-ref}`lief-dsc-dylib` object using
{sub-ref}`lief-dsc-dylib-get`, **the extraction can take a substantial amount of time**,
especially if certain deoptimizations are enabled (c.f. {sub-ref}`lief-dsc-dylib-eopt`).

For instance, {sub-ref}`lief-dsc-dylib-eopt-fix_branches` may require iterating over the
Dyld shared cache's stub islands several times. To improve overall performance,
LIEF provides a cache-based optimization that can be enabled and configured with:

- {sub-ref}`lief-dsc-enable_cache`
- {sub-ref}`lief-dsc-dyldsharedcache-enable_caching`

:::{admonition} When should you turn caching on?
:class: warning

You can **skip** LIEF's caching if:

- You don't plan to extract libraries from the shared cache.
- You plan to extract only one library from the shared cache and **only once**
- You don't want to have LIEF cache artifacts on your system.

For all other situations, you should turn on {sub-ref}`lief-dsc-enable_cache`.

**By default, the cache mechanism is not enabled.**
:::

[^footnote-1]: <https://en.cppreference.com/w/cpp/iterator/random_access_iterator>

## {fa}`solid fa-book-open-reader` References

- {github-ref}`arandomdev/DyldExtractor`
- {github-ref}`blacktop/ipsw`
- {github-ref}`apple-oss-distributions/dyld`
- <https://www.romainthomas.fr/post/24-09-apple-lockdown-dbi-lifting/>

{fa}`brands fa-python` {doc}`Python API <python>`

{fa}`regular fa-file-code` {doc}`C++ API <cpp>`

{fa}`brands fa-rust` Rust API: {rust:module}`lief::dsc`

{{ cross_api }}
