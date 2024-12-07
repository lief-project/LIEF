:fa:`solid fa-microchip` AArch64
--------------------------------

Instruction
************

.. lief-inheritance:: lief._lief.assembly.aarch64.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2

.. autoclass:: lief.assembly.aarch64.Instruction

Opcodes
*******

See: ``lief.assembly.aarch64.OPCODE``


Operands
********

.. lief-inheritance:: lief._lief.assembly.aarch64.Operand
  :top-classes: lief._lief.assembly.aarch64.Operand
  :parts: 2

.. autoclass:: lief.assembly.aarch64.Operand

Immediate
~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.aarch64.operands.Immediate
  :top-classes: lief._lief.assembly.aarch64.Operand
  :parts: 2

.. autoclass:: lief.assembly.aarch64.operands.Immediate

Register
~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.aarch64.operands.Register
  :top-classes: lief._lief.assembly.aarch64.Operand
  :parts: 2

.. autoclass:: lief.assembly.aarch64.operands.Register

Memory
~~~~~~

.. lief-inheritance:: lief._lief.assembly.aarch64.operands.Memory
  :top-classes: lief._lief.assembly.aarch64.Operand
  :parts: 2

.. autoclass:: lief.assembly.aarch64.operands.Memory

PCRelative
~~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.aarch64.operands.PCRelative
  :top-classes: lief._lief.assembly.aarch64.Operand
  :parts: 2

.. autoclass:: lief.assembly.aarch64.operands.PCRelative
