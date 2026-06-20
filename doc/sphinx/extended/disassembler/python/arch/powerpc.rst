:fa:`solid fa-microchip` PowerPC
--------------------------------

Instruction
************

.. lief-inheritance:: lief._lief.assembly.powerpc.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2

.. autoclass:: lief.assembly.powerpc.Instruction

Opcodes
*******

See: ``lief.assembly.powerpc.OPCODE``


Operands
********

.. lief-inheritance:: lief._lief.assembly.powerpc.Operand
  :top-classes: lief._lief.assembly.powerpc.Operand
  :parts: 2

.. autoclass:: lief.assembly.powerpc.Operand

Immediate
~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.powerpc.operands.Immediate
  :top-classes: lief._lief.assembly.powerpc.Operand
  :parts: 2

.. autoclass:: lief.assembly.powerpc.operands.Immediate

Register
~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.powerpc.operands.Register
  :top-classes: lief._lief.assembly.powerpc.Operand
  :parts: 2

.. autoclass:: lief.assembly.powerpc.operands.Register

Memory
~~~~~~

.. lief-inheritance:: lief._lief.assembly.powerpc.operands.Memory
  :top-classes: lief._lief.assembly.powerpc.Operand
  :parts: 2

.. autoclass:: lief.assembly.powerpc.operands.Memory

PCRelative
~~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.powerpc.operands.PCRelative
  :top-classes: lief._lief.assembly.powerpc.Operand
  :parts: 2

.. autoclass:: lief.assembly.powerpc.operands.PCRelative
