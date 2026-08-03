(extended-disassembler)=

# {fa}`solid fa-dna` Disassembler

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp/index
  python/index
  rust
```

## Introduction

LIEF Extended provides a user-friendly API for disassembling code within various
parts of executable formats for the following architectures:
x86/x86-64, ARM, AArch64, RISC-V, MIPS, PowerPC, and eBPF.

You can begin disassembling code within a binary using the {sub-ref}`lief-disassemble`
function, which is exposed in the abstraction layer:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/disassembler.py", "disassemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/disassembler.cpp", "disassemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/disassembler.rs", "disassemble") }}
:::
::::

From a design perspective, the disassembler returns a *lazy* iterator,
yielding a {sub-ref}`lief-asm-instruction` instance as it evaluates the
instruction at each address.

Consequently, when calling `elf.disassemble_address(0x400)`, no disassembly
occurs until the iterator is advanced.

Instructions are represented by the {sub-ref}`lief-asm-instruction` object,
which is extended by architecture-specific objects:

- {sub-ref}`lief-asm-x86-instruction`
- {sub-ref}`lief-asm-arm-instruction`
- {sub-ref}`lief-asm-aarch64-instruction`
- {sub-ref}`lief-asm-powerpc-instruction`
- {sub-ref}`lief-asm-mips-instruction`
- {sub-ref}`lief-asm-riscv-instruction`
- {sub-ref}`lief-asm-ebpf-instruction`

In Python, you can check the effective type of
a {class}`lief.assembly.Instruction` with `isinstance(...)`:

{{ literalinclude("../../../code/python/disassembler.py", "downcast") }}

In C++, downcasting is performed using the function:
{cpp:func}`LIEF::assembly::Instruction::as`:

{{ literalinclude("../../../code/cpp/disassembler.cpp", "downcast") }}

In Rust, instructions are represented by the enum {rust:enum}`lief::assembly::Instructions`.
Thus, you can write:

{{ literalinclude("../../../code/rust/src/disassembler.rs", "downcast") }}

:::{note}
You can also check the assembler documentation here: {ref}`Assembler <extended-assembler>`
:::

For the `x86/x86-64` and `AArch64` architectures, you can also iterate
over an instruction's operands:

::::{tabs}
:::{tab} {fa}`solid fa-microchip` AArch64
{{ literalinclude("../../../code/python/disassembler.py", "operands-aarch64", prepend="import lief") }}
:::
:::{tab} {fa}`solid fa-microchip` x86/x86-64
{{ literalinclude("../../../code/python/disassembler.py", "operands-x86", prepend="import lief") }}
:::
::::

You can check the documentation of these architectures for more details about
the exposed API.

## x86/x86-64

On x86/x86-64, {sub-ref}`lief-asm-x86-instruction` also exposes an API to inspect and
rewrite the `LOCK` prefix of an instruction:

- {sub-ref}`lief-assembly-x86-Instruction-has_lock_prefix`
- {sub-ref}`lief-assembly-x86-Instruction-is_lockable`
- {sub-ref}`lief-assembly-x86-Instruction-is_atomic`
- {sub-ref}`lief-assembly-x86-Instruction-lock`
- {sub-ref}`lief-assembly-x86-Instruction-unlock`

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/disassembler.py", "x86-lock", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/disassembler.cpp", "x86-lock") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/disassembler.rs", "x86-lock") }}
:::
::::

## Use Cases

### DWARF Function

In addition to the regular {sub-ref}`lief-disassemble` API, you can use
{sub-ref}`lief-dwarf-function-instructions` to disassemble a {ref}`DWARF <extended-dwarf>`
function.

:::{warning}
{sub-ref}`lief-dwarf-function-instructions` only works if the DWARF debug info
is **embedded** in the binary. This is the default behavior for
{ref}`ELF <format-elf>` binaries, but this is not the case for Mach-O
`.dSYM` files.
:::

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/disassembler.py", "dwarf-func", prepend="import lief") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/disassembler.cpp", "dwarf-func") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/disassembler.rs", "dwarf-func") }}
:::
::::

### Dyld Shared Cache

A disassembly API is also provided for the {sub-ref}`lief-dsc-dyldsharedcache` object
via {sub-ref}`lief-dsc-dyldsharedcache-disassemble`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../code/python/disassembler.py", "dsc-disassemble") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../code/cpp/disassembler.cpp", "dsc-disassemble") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../code/rust/src/disassembler.rs", "dsc-disassemble") }}
:::
::::

### COFF Support

The {sub-ref}`lief-coff-Binary` interface does not inherit from the generic {sub-ref}`lief-abstract-binary`,
but it also exposes an API to disassemble code in COFF object files: {sub-ref}`lief-coff-binary-disassemble`.

For more details, please check the {ref}`COFF Disassembler <format-coff-disassembler>` section

### In-Memory Disassembler

The disassembler is also available for analyzing code directly in the memory of
the running process. This functionality is exposed through the runtime API
{sub-ref}`lief-runtime-disassemble`, as detailed in the {ref}`Runtime Memory <runtime_memory>`
documentation.

## Technical Details

The disassembler is based on LLVM's MC layer, which is known to be efficient and
accurate for disassembling code. This LLVM MC layer is already used by
other projects like [capstone](https://www.capstone-engine.org/) or, more
recently, [Nyxstone](https://github.com/emproof-com/nyxstone).

Compared to Capstone, LIEF uses a mainstream LLVM version with limited
modifications to the MC layer. On the other hand, it does not expose a C API,
supports fewer architectures than Capstone, and does not expose a standalone API.

:::{note}
The current LLVM version is {sub-ref}`lief-llvm-version`.
:::

Unlike Nyxstone's disassembler, LIEF hides LLVM from the public API,
meaning that LLVM does not need to be installed on the system.
On the other hand, it does not expose a standalone API.

The major difference between LIEF's disassembler and other projects is that
it **does not expose a standalone API** for disassembling arbitrary code.
The disassembler is bound to the object from which the API is
exposed ({sub-ref}`lief-abstract-binary`, {sub-ref}`lief-dwarf-function`,
{sub-ref}`lief-dsc-dyldsharedcache-disassemble`, etc.).

{fa}`brands fa-python` {doc}`Python API <python/index>`

{fa}`regular fa-file-code` {doc}`C++ API <cpp/index>`

{fa}`brands fa-rust` Rust API: {rust:module}`lief::assembly`

{{ cross_api }}
