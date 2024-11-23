.. _extended-disassembler:

:fa:`solid fa-dna` Disassembler
-------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

LIEF extended is exposing a user-friendly API to disassemble code in different
places of executable formats.

You can start disassembling code within a binary by using the |lief-disassemble|
functions exposed in the abstraction layer:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/hello")
        for inst in elf.disassemble(0x400120):
            print(inst)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto pe = LIEF::PE::Parser::parse("cmd.exe");
        for (const auto& inst : pe->disassemble("_WinRT")) {
          std::cout << inst->to_string() << '\n';
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let elf = lief::elf::Binary::parse("/bin/ls");
        for inst in elf.disassemble_address(0x400) {
            println!("{}", inst.to_string());
        }

From a design perspective, the disassembler returns a *lazy* iterator which
outputs a |lief-asm-instruction| instance when it evaluates the
instruction at the address associated with the iterator's position.

Thus, when calling ``elf.disassemble_address(0x400)``, nothing is disassembled
until the iterator is processed.

Technical Details
*****************

The disassembler is based on the LLVM's MC layer which is known to be efficient and
accurate for disassembling code. This MC layer of LLVM has already been used by
other projects like `capstone <https://www.capstone-engine.org/>`_ or more
recently `Nyxstone <https://github.com/emproof-com/nyxstone>`_.

Compared to Capstone, LIEF uses a mainstream LLVM version without any modification
on the MC layer. On the other hand, it does not expose a C API, supports fewer
architectures than Capstone, and does not expose a standalone API.

Compared to Nyxstone's disassembler, LLVM is *hidden* from the public API
which means that LLVM does not need to be installed on the system. On the other
hand, it does not expose a standalone API.

The major difference between LIEF's disassembler and the other projects is that
it **does not expose a standalone API** to disassemble
arbitrary code. The disassembler is bound to the object from which the API is
exposed (|lief-abstract-binary|, |lief-dwarf-function|, ...).

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::assembly`

.. include:: ../../_cross_api.rst
