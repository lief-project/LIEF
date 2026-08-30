(runtime_memory_layout)=

# {fa}`solid fa-map` Memory Layout

The {sub-ref}`lief-runtime-memorylayout` interface exposes the memory layout of
the **current** process: the regions that are mapped in its address space.

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

For a process running `/usr/bin/cat`, this prints:

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

A {sub-ref}`lief-runtime-memorylayout-region` is a contiguous range of memory
described by its address range and the name can be either:

- the name or the path of the module mapped at this address
  (e.g. `/usr/lib/libc.so.6`);
- the identifier of a region that is not backed by a file
  (e.g. `[stack]`, `[heap]`, `[vdso]`);
- **empty**, for anonymous regions.

As shown in the output above, a module is not mapped as a single region: it
usually gets one region per set of permissions.

## {fa}`solid fa-magnifying-glass` Inspecting the layout

The following snippet iterates over the memory layout to

- compute how much memory is mapped
- the footprint of each module
- the region that backs a given address

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

On Linux and Android, the kernel names the regions that back the stack and the
heap of the process, so both can be located by name:

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

{{ cross_api }}
