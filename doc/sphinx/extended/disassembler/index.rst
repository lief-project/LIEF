.. _extended-disassembler:

:fa:`solid fa-dna` Disassembler
-------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp/index
  python/index
  rust

----

Introduction
************

LIEF Extended provides a user-friendly API for disassembling code within various
parts of executable formats for the following architectures:
x86/x86-64, ARM, AArch64, RISC-V, MIPS, PowerPC, and eBPF.

You can begin disassembling code within a binary using the |lief-disassemble|
function, which is exposed in the abstraction layer:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :start-after: lief-doc: disassemble-start
        :end-before: lief-doc: disassemble-end
        :dedent:

   .. tab:: :fa:`regular fa-file-code` C++

      .. literalinclude:: ../../../code/cpp/disassembler.cpp
        :language: cpp
        :start-after: lief-doc: disassemble-start
        :end-before: lief-doc: disassemble-end
        :dedent:

   .. tab:: :fa:`brands fa-rust` Rust

      .. literalinclude:: ../../../code/rust/src/disassembler.rs
        :language: rust
        :start-after: lief-doc: disassemble-start
        :end-before: lief-doc: disassemble-end
        :dedent:

From a design perspective, the disassembler returns a *lazy* iterator,
yielding a |lief-asm-instruction| instance as it evaluates the
instruction at each address.

Consequently, when calling ``elf.disassemble_address(0x400)``, no disassembly
occurs until the iterator is advanced.

Instructions are represented by the |lief-asm-instruction| object,
which is extended by architecture-specific objects:

- |lief-asm-x86-instruction|
- |lief-asm-arm-instruction|
- |lief-asm-aarch64-instruction|
- |lief-asm-powerpc-instruction|
- |lief-asm-mips-instruction|
- |lief-asm-riscv-instruction|
- |lief-asm-ebpf-instruction|

In Python, you can check the effective type of
a :class:`lief.assembly.Instruction` with ``isinstance(...)``:

.. literalinclude:: ../../../code/python/disassembler.py
  :language: python
  :start-after: lief-doc: downcast-start
  :end-before: lief-doc: downcast-end
  :dedent:

In C++, downcasting is performed using the function:
:cpp:func:`LIEF::assembly::Instruction::as`:

.. literalinclude:: ../../../code/cpp/disassembler.cpp
  :language: cpp
  :start-after: lief-doc: downcast-start
  :end-before: lief-doc: downcast-end
  :dedent:

In Rust, instructions are represented by the enum :rust:enum:`lief::assembly::Instructions`.
Thus, you can write:

.. literalinclude:: ../../../code/rust/src/disassembler.rs
  :language: rust
  :start-after: lief-doc: downcast-start
  :end-before: lief-doc: downcast-end
  :dedent:

.. note::

   You can also check the assembler documentation here: :ref:`Assembler <extended-assembler>`

For the ``x86/x86-64`` and ``AArch64`` architectures, you can also iterate
over an instruction's operands:

.. tabs::

   .. tab:: :fa:`solid fa-microchip` AArch64

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :prepend: import lief
        :start-after: lief-doc: operands-aarch64-start
        :end-before: lief-doc: operands-aarch64-end
        :dedent:

   .. tab:: :fa:`solid fa-microchip` x86/x86-64

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :prepend: import lief
        :start-after: lief-doc: operands-x86-start
        :end-before: lief-doc: operands-x86-end
        :dedent:

You can check the documentation of these architectures for more details about
the exposed API.

x86/x86-64
**********

On x86/x86-64, |lief-asm-x86-instruction| also exposes an API to inspect and
rewrite the ``LOCK`` prefix of an instruction:

- |lief-assembly-x86-Instruction-has_lock_prefix|
- |lief-assembly-x86-Instruction-is_lockable|
- |lief-assembly-x86-Instruction-is_atomic|
- |lief-assembly-x86-Instruction-lock|
- |lief-assembly-x86-Instruction-unlock|

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :prepend: import lief
        :start-after: lief-doc: x86-lock-start
        :end-before: lief-doc: x86-lock-end
        :dedent:

   .. tab:: :fa:`regular fa-file-code` C++

      .. literalinclude:: ../../../code/cpp/disassembler.cpp
        :language: cpp
        :start-after: lief-doc: x86-lock-start
        :end-before: lief-doc: x86-lock-end
        :dedent:

   .. tab:: :fa:`brands fa-rust` Rust

      .. literalinclude:: ../../../code/rust/src/disassembler.rs
        :language: rust
        :start-after: lief-doc: x86-lock-start
        :end-before: lief-doc: x86-lock-end
        :dedent:

Use Cases
*********

DWARF Function
~~~~~~~~~~~~~~

In addition to the regular |lief-disassemble| API, you can use
|lief-dwarf-function-instructions| to disassemble a :ref:`DWARF <extended-dwarf>`
function.

.. warning::

  |lief-dwarf-function-instructions| only works if the DWARF debug info
  is **embedded** in the binary. This is the default behavior for
  :ref:`ELF <format-elf>` binaries, but this is not the case for Mach-O
  ``.dSYM`` files.

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :prepend: import lief
        :start-after: lief-doc: dwarf-func-start
        :end-before: lief-doc: dwarf-func-end
        :dedent:


   .. tab:: :fa:`regular fa-file-code` C++

      .. literalinclude:: ../../../code/cpp/disassembler.cpp
        :language: cpp
        :start-after: lief-doc: dwarf-func-start
        :end-before: lief-doc: dwarf-func-end
        :dedent:

   .. tab:: :fa:`brands fa-rust` Rust

      .. literalinclude:: ../../../code/rust/src/disassembler.rs
        :language: rust
        :start-after: lief-doc: dwarf-func-start
        :end-before: lief-doc: dwarf-func-end
        :dedent:

Dyld Shared Cache
~~~~~~~~~~~~~~~~~

A disassembly API is also provided for the |lief-dsc-dyldsharedcache| object
via |lief-dsc-dyldsharedcache-disassemble|:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. literalinclude:: ../../../code/python/disassembler.py
        :language: python
        :start-after: lief-doc: dsc-disassemble-start
        :end-before: lief-doc: dsc-disassemble-end
        :dedent:

    .. tab:: :fa:`regular fa-file-code` C++

      .. literalinclude:: ../../../code/cpp/disassembler.cpp
        :language: cpp
        :start-after: lief-doc: dsc-disassemble-start
        :end-before: lief-doc: dsc-disassemble-end
        :dedent:

    .. tab:: :fa:`brands fa-rust` Rust

      .. literalinclude:: ../../../code/rust/src/disassembler.rs
        :language: rust
        :start-after: lief-doc: dsc-disassemble-start
        :end-before: lief-doc: dsc-disassemble-end
        :dedent:

COFF Support
~~~~~~~~~~~~

The |lief-coff-Binary| interface does not inherit from the generic |lief-abstract-binary|,
but it also exposes an API to disassemble code in COFF object files: |lief-coff-binary-disassemble|.

For more details, please check the :ref:`COFF Disassembler <format-coff-disassembler>` section

In-Memory Disassembler
~~~~~~~~~~~~~~~~~~~~~~

The disassembler is also available for analyzing code directly in the memory of
the running process. This functionality is exposed through the runtime API
|lief-runtime-disassemble|, as detailed in the :ref:`Runtime Memory <runtime_memory>`
documentation.

Technical Details
*****************

The disassembler is based on LLVM's MC layer, which is known to be efficient and
accurate for disassembling code. This LLVM MC layer is already used by
other projects like `capstone <https://www.capstone-engine.org/>`_ or, more
recently, `Nyxstone <https://github.com/emproof-com/nyxstone>`_.

Compared to Capstone, LIEF uses a mainstream LLVM version with limited
modifications to the MC layer. On the other hand, it does not expose a C API,
supports fewer architectures than Capstone, and does not expose a standalone API.

.. note::

  The current LLVM version is |lief-llvm-version|.

Unlike Nyxstone's disassembler, LIEF hides LLVM from the public API,
meaning that LLVM does not need to be installed on the system.
On the other hand, it does not expose a standalone API.

The major difference between LIEF's disassembler and other projects is that
it **does not expose a standalone API** for disassembling arbitrary code.
The disassembler is bound to the object from which the API is
exposed (|lief-abstract-binary|, |lief-dwarf-function|,
|lief-dsc-dyldsharedcache-disassemble|, etc.).

:fa:`brands fa-python` :doc:`Python API <python/index>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp/index>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::assembly`

.. include:: ../../_cross_api.rst
