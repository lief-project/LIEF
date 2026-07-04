:fa:`solid fa-microchip` Mips
-----------------------------

Instruction
************

.. lief-inheritance:: lief._lief.assembly.mips.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2

.. autoclass:: lief.assembly.mips.Instruction

Opcodes
*******

See: ``lief.assembly.mips.OPCODE``


Operands
********

.. lief-inheritance:: lief._lief.assembly.mips.Operand
  :top-classes: lief._lief.assembly.mips.Operand
  :parts: 2

.. autoclass:: lief.assembly.mips.Operand

Immediate
~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.mips.operands.Immediate
  :top-classes: lief._lief.assembly.mips.Operand
  :parts: 2

.. autoclass:: lief.assembly.mips.operands.Immediate

Register
~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.mips.operands.Register
  :top-classes: lief._lief.assembly.mips.Operand
  :parts: 2

.. autoclass:: lief.assembly.mips.operands.Register

Memory
~~~~~~

.. lief-inheritance:: lief._lief.assembly.mips.operands.Memory
  :top-classes: lief._lief.assembly.mips.Operand
  :parts: 2

.. autoclass:: lief.assembly.mips.operands.Memory

PCRelative
~~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.mips.operands.PCRelative
  :top-classes: lief._lief.assembly.mips.Operand
  :parts: 2

.. autoclass:: lief.assembly.mips.operands.PCRelative
