(extended-assembler)=

# {fa}`solid fa-user-secret` Assembler

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

In addition to standard file format modifications, it may be necessary to patch
code with custom assembly. This functionality is available through the
{sub-ref}`lief-assemble` function:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/assembler.py", "disassemble-assemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/assembler.cpp", "disassemble-assemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/assembler.rs", "disassemble-assemble") }}
:::
::::

:::{warning}
The assembler works well for `AArch64/ARM64E`, `x86/x86-64`, and `RISC-V`
but support for other architectures is currently limited.
:::

## Technical Details

Similar to the {ref}`disassembler <extended-disassembler>`, this assembler is
based on the LLVM MC layer.

The assembly text is consumed by the `llvm::MCAsmParser` object, and we
*intercept* the raw generated assembly bytes from the `llvm::MCObjectWriter`.

We also resolve `llvm::MCFixup` for a vast majority of the generated fixups.
An important feature introduced in LIEF 0.17.0 is support for resolving symbols
or labels **on the fly**.

(extended-assembler-contextual-patching)=

## Contextual Assembly Patching

Given assembly code and a target address, we might want to use a **context**
to resolve symbols referenced in the assembly listing.

For example, consider the following patch:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/assembler.py", "context-error") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/assembler.cpp", "context-error") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/assembler.rs", "context-error") }}
:::
::::

In this example, `a_custom_function` is undefined, so the assembler engine
cannot resolve it and raises the following error:

```text
warning: Fixup not resolved:
    call a_custom_function
```

LIEF exposes a {sub-ref}`lief-asm-AssemblerConfig` interface that can be used to
configure the engine and to **dynamically** resolve symbols used in the assembly
listing:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/assembler.py", "config-resolver", emphasize_lines="1-9,19") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/assembler.cpp", "config-resolver", emphasize_lines="1-9,11,19") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/assembler.rs", "config-resolver", emphasize_lines="3-12,20") }}
:::
::::

This interface can be used to wrap a context, such as a generic
{sub-ref}`lief-abstract-binary`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/assembler.py", "config-target", prepend="import lief", emphasize_lines="6,10-13,16") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/assembler.cpp", "config-target", emphasize_lines="4-6,9-12,22") }}
:::
::::

The Rust bindings do not offer the same flexibility to capture the
{sub-ref}`lief-abstract-binary`. Nevertheless, the closure associated with the
{rust:member}`lief::assembly::AssemblerConfig::symbol_resolver [struct]`
can capture most of its context:

::::{tabs}
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/assembler.rs", "config-target", emphasize_lines="5-12") }}
:::
::::

## Use Cases

Patching code with the assembler is a fast alternative to editing raw bytes by
hand: it is useful for bypassing a check while reverse engineering,
hot-patching a bug in a shipped executable, or inserting instrumentation.

### Disabling an Instruction

To strip a single instruction like a call to a telemetry or anti-debugging
routine *without* shifting the rest of the
function we can overwrite it with as many `nop` bytes as it occupied. Pairing the
{ref}`disassembler <extended-disassembler>` with {sub-ref}`lief-assemble` lets you
do this:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/assembler.py", "nop-out") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/assembler.cpp", "nop-out") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/assembler.rs", "nop-out") }}
:::
::::

:::{note}
The snippets above assume `x86/x86-64`, where a `nop` is a single byte,
so `inst.size` of them fill the slot exactly. On fixed-width instruction set such as
`AArch64` every instruction is 4 bytes, so we would emit `inst.size / 4` instead.
:::

## In-Memory Assembler

In addition to patching binaries on disk or within standard file formats, the
assembly engine is also available for JIT compilation and in-memory operations.
This is exposed through the runtime API {sub-ref}`lief-runtime-assemble`, as detailed in the
{ref}`Runtime Memory <runtime_memory>` documentation.

{fa}`brands fa-python` {doc}`Python API <python>`

{fa}`regular fa-file-code` {doc}`C++ API <cpp>`

{fa}`brands fa-rust` {doc}`Rust API <rust>`

{{ cross_api }}
