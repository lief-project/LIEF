---
description: Inspect mapped memory regions with LIEF Extended, calculate virtual address-space usage, and locate mappings by address or name.
---

(runtime_memory_layout)=

# {fa}`solid fa-map` Memory Layout

The {sub-ref}`lief-runtime-memorylayout` interface exposes the memory layout of
the **current** process: the regions that are mapped in its address space.
It is available in LIEF Extended on Linux, Android, macOS, and Windows.

## Enumerate mapped regions

{sub-ref}`lief-runtime-memory_layout` returns an iterator over these
regions, ordered by address:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/memory_layout.py", "iterate") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/memory_layout.cpp", "iterate") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/memory_layout.rs", "iterate") }}
:::
::::

For illustration, a Linux process running `/usr/bin/cat` could have this layout:

```{code-block} text
0x563668f9d000-0x563668f9f000 /usr/bin/cat
0x563668f9f000-0x563668fa6000 /usr/bin/cat
0x563668fa6000-0x563668fa9000 /usr/bin/cat
0x563668fa9000-0x563668faa000 /usr/bin/cat
0x563668faa000-0x563668fab000 /usr/bin/cat
0x56367cb52000-0x56367cb73000 [heap]
0x7f2d28e00000-0x7f2d29196000 /usr/lib/locale/locale-archive
0x7f2d291be000-0x7f2d29200000
0x7f2d29200000-0x7f2d29224000 /usr/lib/libc.so.6
[...]
0x7f2d29478000-0x7f2d2947a000 [vdso]
0x7f2d2947a000-0x7f2d2947b000 /lib64/ld-linux-x86-64.so.2
[...]
0x7ffd162f1000-0x7ffd16312000 [stack]
0xffffffffff600000-0xffffffffff601000 [vsyscall]
```

A {sub-ref}`lief-runtime-memorylayout-region` describes a half-open address range:
the start address is included, and the end address is excluded. Its name can be:

- the name or the path of the module mapped at this address
  (e.g. `/usr/lib/libc.so.6`);
- the identifier of a region that is not backed by a file
  (e.g. `[stack]`, `[heap]`, `[vdso]`);
- **empty**, for anonymous regions.

As shown in the output above, a module is not mapped as a single region: it
usually gets one region per set of permissions.

Names and mappings depend on the operating system and can change as the process
allocates memory or loads libraries. A region describes a mapping: it does not
own the mapped memory.

## {fa}`solid fa-magnifying-glass` Inspecting the layout

The following snippet iterates over the memory layout to:

- Compute the total mapped size
- Group that size by region name
- Locate the region containing a given address

These totals measure virtual address space. They are not resident-memory (RSS)
measurements, and grouping anonymous regions combines unrelated allocations.

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/memory_layout.py", "inspect") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/memory_layout.cpp", "inspect") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/memory_layout.rs", "inspect") }}
:::
::::

## {fa}`brands fa-linux` Linux / {fa}`brands fa-android` Android

On Linux and Android, named mappings such as `[stack]` and `[heap]` can be located
when present. They do not account for every thread stack or allocator-managed
allocation:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/memory_layout.py", "stack-heap") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/memory_layout.cpp", "stack-heap") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/memory_layout.rs", "stack-heap") }}
:::
::::

```text
[heap]: 0x56367cb52000-0x56367cb73000
[stack]: 0x7ffd162f1000-0x7ffd16312000
```

## {fa}`brands fa-apple` macOS

On macOS, the layout includes the individual regions within nested memory maps,
including the dyld shared cache. LIEF tries to provide meaningful names for _anonymous_ regions
associated with the dyld shared cache, the stack, ...:

```text
[0000000111e9c000, 0000000111f28000]: /private/tmp/LIEF/main/lief/_lief_extended.so:__DATA
[0000000111f28000, 0000000112020000]: /private/tmp/LIEF/main/lief/_lief_extended.so
[000000014f600000, 000000014f604000]: [heap]
[000000016ed08000, 000000016ed0c000]: [stack]
[000000016ed0c000, 000000016fd0c000]: [stack]
[0000000180000000, 000000018ed58000]: <anonymous>
[000000018ed58000, 000000018ede0000]: [dyld shared cache: __TEXT]
[000000018ede0000, 00000001f4000000]: [dyld shared cache: __TEXT]
[00000001f4000000, 00000001f45d8000]: [dyld shared cache: __TEXT]
[00000001f45d8000, 00000001f45dc000]: [dyld shared cache: __TEXT]
[00000001f45dc000, 00000001f6900000]: [dyld shared cache: __DATA_CONST]
[00000001f6900000, 00000001f8000000]: <anonymous>
[00000001f8000000, 00000001f8900000]: <anonymous>
```

## {fa}`brands fa-windows` Windows

On Windows, the layout includes committed pages and reserved address ranges,
including stack, TEB/PEB regions:

```text
[0000000000127000, 0000000000182000]: <anonymous>
[0000000000190000, 0000000000193000]: C:\Windows\System32\l_intl.nls
[00000000001a0000, 00000000001b1000]: C:\Windows\System32\C_1252.NLS
[00000000001c0000, 00000000001d1000]: C:\Windows\System32\C_850.NLS
[00000000001e0000, 00000000001e3000]: [pagefile]
[00000000001f0000, 00000000001f4000]: <anonymous>
[0000000000200000, 000000000037f000]: <anonymous>
[000000000037f000, 0000000000388000]: [peb/teb]
[0000000000388000, 0000000000400000]: <anonymous>
[0000000000400000, 0000000000639000]: [stack]
[000000007ffe0000, 000000007ffe1000]: [shared-user-data]
[00007ff6ae6d0000, 00007ff6ae6d1000]: C:\Python314\python.exe
[00007ff6ae6d1000, 00007ff6ae6d2000]: C:\Python314\python.exe
[00007ff6ae6d2000, 00007ff6ae6d3000]: C:\Python314\python.exe
[00007ff6ae6d3000, 00007ff6ae6d4000]: C:\Python314\python.exe
```

{{ cross_api }}
