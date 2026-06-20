:fa:`solid fa-microchip` RISC-V
--------------------------------

Instruction
************

.. lief-inheritance:: lief._lief.assembly.riscv.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2

.. autoclass:: lief.assembly.riscv.Instruction

Opcodes
*******

See: ``lief.assembly.riscv.OPCODE``


Operands
********

.. lief-inheritance:: lief._lief.assembly.riscv.Operand
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2

.. autoclass:: lief.assembly.riscv.Operand

Immediate
~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.riscv.operands.Immediate
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2

.. autoclass:: lief.assembly.riscv.operands.Immediate

Register
~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.riscv.operands.Register
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2

.. autoclass:: lief.assembly.riscv.operands.Register

Memory
~~~~~~

.. lief-inheritance:: lief._lief.assembly.riscv.operands.Memory
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2

.. autoclass:: lief.assembly.riscv.operands.Memory

PCRelative
~~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.riscv.operands.PCRelative
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2

.. autoclass:: lief.assembly.riscv.operands.PCRelative
