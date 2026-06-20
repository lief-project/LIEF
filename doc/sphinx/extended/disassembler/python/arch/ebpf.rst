:fa:`solid fa-microchip` eBPF
-----------------------------

Instruction
************

.. lief-inheritance:: lief._lief.assembly.ebpf.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2

.. autoclass:: lief.assembly.ebpf.Instruction

Opcodes
*******

See: ``lief.assembly.ebpf.OPCODE``


Operands
********

.. lief-inheritance:: lief._lief.assembly.ebpf.Operand
  :top-classes: lief._lief.assembly.ebpf.Operand
  :parts: 2

.. autoclass:: lief.assembly.ebpf.Operand

Immediate
~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.ebpf.operands.Immediate
  :top-classes: lief._lief.assembly.ebpf.Operand
  :parts: 2

.. autoclass:: lief.assembly.ebpf.operands.Immediate

Register
~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.ebpf.operands.Register
  :top-classes: lief._lief.assembly.ebpf.Operand
  :parts: 2

.. autoclass:: lief.assembly.ebpf.operands.Register

Memory
~~~~~~

.. lief-inheritance:: lief._lief.assembly.ebpf.operands.Memory
  :top-classes: lief._lief.assembly.ebpf.Operand
  :parts: 2

.. autoclass:: lief.assembly.ebpf.operands.Memory

PCRelative
~~~~~~~~~~

.. lief-inheritance:: lief._lief.assembly.ebpf.operands.PCRelative
  :top-classes: lief._lief.assembly.ebpf.Operand
  :parts: 2

.. autoclass:: lief.assembly.ebpf.operands.PCRelative
