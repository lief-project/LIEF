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

LIEF extended exposes a user-friendly API to disassemble code in different
places of executable formats for the following architectures:
x86/x86-64, ARM, AArch64, RISC-V, Mips, PowerPC, eBPF.

You can start disassembling code within a binary by using the |lief-disassemble|
functions that is exposed in the abstraction layer:

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/hello")

        inst: lief.assembly.Instruction = ...

        for inst in elf.disassemble(0x400120):
            print(inst)

   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto pe = LIEF::PE::Parser::parse("cmd.exe");

        std::unique_ptr<LIEF::assembly::Instruction> inst;

        for (inst : pe->disassemble("_WinRT")) {
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

An instruction is represented by the object: |lief-asm-instruction| which is
extended by the following objects for each supported architecture:

- |lief-asm-x86-instruction|
- |lief-asm-arm-instruction|
- |lief-asm-aarch64-instruction|
- |lief-asm-powerpc-instruction|
- |lief-asm-mips-instruction|
- |lief-asm-riscv-instruction|
- |lief-asm-ebpf-instruction|

In Python, one can check the effective type of
a :class:`lief.assembly.Instruction` with ``isinstance(...)``:

.. code-block:: python

   inst: lief.assembly.Instruction = ...

   if isinstance(inst, lief.assembly.riscv.Instruction):
      opcode: lief.assemble.riscv.OPCODE = inst.opcode

In C++, downcasting can be done using the function:
:cpp:func:`LIEF::assembly::Instruction::as`:

.. code-block:: cpp

  std::unique_ptr<LIEF::assembly::Instruction> inst = ...;

  if (const auto* riscv_inst = inst->as<LIEF::assembly::riscv::Instruction>())
  {
    LIEF::assembly::riscv::OPCODE opcode = riscv_inst->opcode();
  }

In Rust, instructions are represented by the enum :rust:enum:`lief::assembly::Instructions`.
Thus, you can write:

.. code-block:: rust

  fn check_opcode(inst: &lief::assembly::Instructions) {
    if let lief::assembly::Instructions::RiscV(riscv) = inst {
      println!("{:?}", riscv.opcode());
    }
  }

.. note::

   You can also check the assembler documentation here: :ref:`Assembler <extended-assembler>`

For the architectures ``x86/x86-64`` and ``AArch64`` we can also iterate over
the instruction's operands:

.. tabs::

   .. tab:: :fa:`solid fa-microchip` AArch64

      .. code-block:: python

        import lief

        inst: lief.assembly.aarch64.Instruction

        for inst in macho.disassemble(0x400120):
            print(inst)
            # Check inst properties
            if inst.is_branch:
                print(f"Resolved: {inst.branch_target}")

            for idx, operand in enumerate(inst.operands):
                if isinstance(operand, lief.assembly.aarch64.operands.Register):
                    print(f"op[{idx}]: REG - {operand.value}")
                if isinstance(operand, lief.assembly.aarch64.operands.Memory):
                    print(f"op[{idx}]: MEM - {operand.base}")
                if isinstance(operand, lief.assembly.aarch64.operands.PCRelative):
                    print(f"op[{idx}]: PCR - {operand.value}")
                if isinstance(operand, lief.assembly.aarch64.operands.Immediate):
                    print(f"op[{idx}]: IMM - {operand.value}")

   .. tab:: :fa:`solid fa-microchip` x86/x86-64

      .. code-block:: python

        import lief

        inst: lief.assembly.x86.Instruction

        for inst in elf.disassemble(0x1000200):
            print(inst)
            # Check inst properties
            if inst.is_branch:
                print(f"Resolved: {inst.branch_target}")

            for idx, operand in enumerate(inst.operands):
                if isinstance(operand, lief.assembly.x86.operands.Register):
                    print(f"op[{idx}]: REG - {operand.value}")
                if isinstance(operand, lief.assembly.x86.operands.Memory):
                    print(f"op[{idx}]: MEM - {operand.base}")
                if isinstance(operand, lief.assembly.x86.operands.PCRelative):
                    print(f"op[{idx}]: PCR - {operand.value}")
                if isinstance(operand, lief.assembly.x86.operands.Immediate):
                    print(f"op[{idx}]: IMM - {operand.value}")

You can check the documentation of these architectures for more details about
the exposed API.

Use Cases
*********

DWARF Function
~~~~~~~~~~~~~~

In addition to the regular |lief-disassemble| API, one can use |lief-dwarf-function-instructions|
to disassemble a :ref:`DWARF <extended-dwarf>` function.

.. warning::

  |lief-dwarf-function-instructions| is only working if the DWARF debug info
  is **embedded** in the binary. This is the default behavior for
  :ref:`ELF <format-elf>` binaries but this is not the case for Mach-O ``.dSYM`` files.

.. tabs::

   .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        elf = lief.ELF.parse("/bin/hello")

        main = elf.debug_info.find_function("main")

        for inst in .instructions:
            print(inst)


   .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto elf = LIEF::ELF::Parser::parse("/bin/hello");

        if (const auto* dwarf = elf->debug_info()->as<LIEF::dwarf::DebugInfo>())
        {
          std::unique_ptr<LIEF::dwarf::Function> _main = dwarf->find_function("main");
          for (const auto& inst : _main->instructions()) {
            std::cout << inst->to_string() << '\n';
          }
        }

   .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let elf = lief::elf::Binary::parse("/bin/ls");
        if let Some(lief::DebugInfo::Dwarf(dwarf)) = elf.debug_info() {
            if Some(func) = dwarf.find_function("main") {
                for inst in func.instructions() {
                    println!("{}", inst.to_string());
                }
            }
        }

Dyld Shared Cache
~~~~~~~~~~~~~~~~~

A disassembling API is also provided for the |lief-dsc-dyldsharedcache| object:
|lief-dsc-dyldsharedcache-disassemble|:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        dyld_cache: lief.dsc.DylibSharedCache = lief.dsc.load("macos-15.0.1/")

        for inst in dyld_cache.disassemble(0x1886f4a44):
            print(inst)

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/DyldSharedCache.hpp>

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache = LIEF::dsc::load("macos-15.0.1/")

        for (const auto& inst : dyld_cache->disassemble(0x1886f4a44)) {
          std::cout << inst->to_string() << '\n';
        }

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dyld_cache = lief::dsc::load_from_path("macos-15.0.1/", "");

        for inst in dyld_cache.disassemble(0x1886f4a44) {
            println!("{}", inst.to_string());
        }

Technical Details
*****************

The disassembler is based on the LLVM's MC layer which is known to be efficient and
accurate for disassembling code. This LLVM's MC layer has already been used by
other projects like `capstone <https://www.capstone-engine.org/>`_ or more
recently `Nyxstone <https://github.com/emproof-com/nyxstone>`_.

Compared to Capstone, LIEF uses a mainstream LLVM version with limited modifications
on the MC layer. On the other hand, it does not expose a C API, supports fewer
architectures than Capstone, and does not expose a standalone API.

.. note::

  The current LLVM version is |lief-llvm-version|.

Compared to Nyxstone's disassembler, LLVM is *hidden* from the public API
which means that LLVM does not need to be installed on the system. On the other
hand, it does not expose a standalone API.

The major difference between LIEF's disassembler and the other projects is that
it **does not expose a standalone API** to disassemble
arbitrary code. The disassembler is bound to the object from which the API is
exposed (|lief-abstract-binary|, |lief-dwarf-function|, |lief-dsc-dyldsharedcache-disassemble|, ...).

:fa:`brands fa-python` :doc:`Python API <python/index>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp/index>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::assembly`

.. include:: ../../_cross_api.rst
