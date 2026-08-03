# {fa}`solid fa-microchip` RISC-V

## Instruction

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.Instruction
  :top-classes: lief._lief.assembly.Instruction
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.Instruction
```

## Opcodes

See: `lief.assembly.riscv.OPCODE`

## Operands

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.Operand
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.Operand
```

### Immediate

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.operands.Immediate
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.operands.Immediate
```

### Register

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.operands.Register
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.operands.Register
```

### Memory

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.operands.Memory
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.operands.Memory
```

### PCRelative

```{eval-rst}
.. lief-inheritance:: lief._lief.assembly.riscv.operands.PCRelative
  :top-classes: lief._lief.assembly.riscv.Operand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.assembly.riscv.operands.PCRelative
```
