.. _extended-assembler:

:fa:`solid fa-user-secret` Assembler
-------------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

In addition to regular file formats modifications, we might want to patch code with
custom assembly. This functionality is available thanks to the |lief-assemble|
function:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/hello")

        syscall_addresses = [
          inst.address for inst in elf.disassemble(0x400090) if inst.is_syscall
        ]

        for syscall_addr in syscall_addresses:
            elf.assemble(syscall_addr, """
            mov x1, x0;
            str x1, [x2, #8];
            """)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto elf = LIEF::ELF::Parser::parse("/bin/hello");

        std::vector<uint64_t> syscall_addresses =
            elf->disassemble(0x400090)
          | std::view::filter([] (const std::unique_ptr<LIEF::assembly::Instruction> I) {
              return I->is_syscall();
            })
          | std::view::transform([] (const std::unique_ptr<LIEF::assembly::Instruction> I) {
              return I->address();
            })
          | std::ranges::to<std::vector>();

        for (uint64_t addr : syscall_addresses) {
          elf->assemble(addr, R"asm(
            mov x1, x0;
            str x1, [x2, #8];
          )asm");
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf = lief::elf::Binary::parse("/bin/hello");

        let syscall_addresses =
            elf.disassemble(0x400090)
               .filter(|I| I.is_syscall())
               .transform(|I| I.address())
               .collect::<Vec<u64>>();

        for addr in syscall_addresses {
            elf.assemble(addr, r#"
              mov x1, x0;
              str x1, [x2, #8];
            "#);
        }

.. warning::

  The assembler is working decently for ``AArch64/ARM64E`` and ``x86/x86-64`` but
  the support is highly limited for the other architectures.

Technical Details
*****************

In the same way that the :ref:`disassembler <extended-disassembler>` is based on
the LLVM MC layer, this assembler is also based on this component of LLVM.

The assembly text is consumed by the ``llvm::MCAsmParser`` object and we *intercept*
the raw generated assembly bytes from the ``llvm::MCObjectWriter``.

Currently, ``llvm::MCFixup`` are not resolved such as if an assembly instruction
needs some kind of relocation, you can get a warning and the issued bytes be
corrupted:

.. code-block:: python

  import lief

  macho = lief.MachO.parse("my-ios-app").take(lief.MachO.Header.CPU_TYPE.ARM64)
  macho.assemble(0x01665c, "bl _my_function")

.. code-block:: text

  warning: Fixup not resolved: bl _my_function

LIEF is going to progressively support these fixups and more **importantly**,
it will provide the *binary* context of |lief-abstract-binary| to the assembler.

This means that we the binary defines the symbol ``_my_function``, the assembly
engine will be aware of this symbol and could be used in your assembly listing:

.. code-block::

  ldr x0, =_my_function;
  mov x1, #0xAABB;
  str x1, [x0];
  bl _my_function

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` :doc:`Rust API <rust>`

.. include:: ../../_cross_api.rst
