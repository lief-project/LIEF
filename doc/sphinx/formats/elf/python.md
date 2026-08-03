# {fa}`brands fa-python` Python

## Parser

```{eval-rst}
.. autofunction:: lief.ELF.parse
```

```{eval-rst}
.. autoclass:: lief.ELF.ParserConfig
```

______________________________________________________________________

## Binary

```{eval-rst}
.. autoclass:: lief.ELF.Binary
```

______________________________________________________________________

## Header

```{eval-rst}
.. autoclass:: lief.ELF.Header
```

______________________________________________________________________

## Section

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.Section
  :top-classes: lief._lief.Section
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.Section
```

______________________________________________________________________

## Segment

```{eval-rst}
.. autoclass:: lief.ELF.Segment
```

______________________________________________________________________

## Dynamic Entry

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntry
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntry
```

______________________________________________________________________

## Dynamic Entry Library

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryLibrary
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryLibrary
```

______________________________________________________________________

## Dynamic Shared Object

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicSharedObject
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicSharedObject
```

______________________________________________________________________

## Dynamic Entry Run Path

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryRunPath
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryRunPath
```

______________________________________________________________________

## Dynamic Entry RPath

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryRpath
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryRpath
```

______________________________________________________________________

## Dynamic Entry Array

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryArray
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryArray
```

______________________________________________________________________

## Dynamic Entry Flags

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryFlags
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryFlags

```

______________________________________________________________________

## Dynamic Entry Auxiliary

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryAuxiliary
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryAuxiliary
```

______________________________________________________________________

## Dynamic Entry Filter

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.DynamicEntryFilter
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.DynamicEntryFilter
```

______________________________________________________________________

## Relocations

```{eval-rst}
.. autoclass:: lief.ELF.Relocation
```

______________________________________________________________________

## Symbol

```{eval-rst}
.. autoclass:: lief.ELF.Symbol
```

______________________________________________________________________

## Symbol Version

```{eval-rst}
.. autoclass:: lief.ELF.SymbolVersion
```

______________________________________________________________________

## Symbol Version Auxiliary

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.SymbolVersionAux
  :top-classes: lief._lief.SymbolVersionAux
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.SymbolVersionAux
```

______________________________________________________________________

## Symbol Version Definition

```{eval-rst}
.. autoclass:: lief.ELF.SymbolVersionDefinition
```

______________________________________________________________________

## Symbol Version Requirement

```{eval-rst}
.. autoclass:: lief.ELF.SymbolVersionRequirement
```

______________________________________________________________________

## Symbol Version Auxiliary Requirement

```{eval-rst}
.. autoclass:: lief.ELF.SymbolVersionAuxRequirement
```

______________________________________________________________________

## GNU Hash table

```{eval-rst}
.. autoclass:: lief.ELF.GnuHash
```

______________________________________________________________________

## SYSV Hash table

```{eval-rst}
.. autoclass:: lief.ELF.SysvHash
```

______________________________________________________________________

## Note

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.Note
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.Note
```

______________________________________________________________________

## Core PrPsInfo

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.CorePrPsInfo
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.CorePrPsInfo
```

______________________________________________________________________

## Core PrStatus

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.CorePrStatus
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.CorePrStatus
```

______________________________________________________________________

## Core File

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.CoreFile
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.CoreFile
```

______________________________________________________________________

## Core Siginfo

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.CoreSigInfo
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.CoreSigInfo
```

______________________________________________________________________

## Core Auxiliary Vector

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.CoreAuxv
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.CoreAuxv
```

______________________________________________________________________

## Android Ident

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.AndroidIdent
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.AndroidIdent
```

______________________________________________________________________

## QNX Stack

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.QNXStack
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.QNXStack
```

______________________________________________________________________

## Note ABI

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.NoteAbi
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.NoteAbi
```

______________________________________________________________________

## Note Gnu Property

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.NoteGnuProperty
  :top-classes: lief._lief.ELF.Note
  :parts: 2
```

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.NoteGnuProperty.Property
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 3
```

```{eval-rst}
.. autoclass:: lief.ELF.NoteGnuProperty
```

______________________________________________________________________

## Generic

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.Generic
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.Generic
```

______________________________________________________________________

## AArch64 Feature

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.AArch64Feature
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.AArch64Feature
```

______________________________________________________________________

## AArch64 PAuth

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.AArch64PAuth
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.AArch64PAuth
```

______________________________________________________________________

## Needed

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.Needed
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.Needed
```

______________________________________________________________________

## No Copy on Protected

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.NoteNoCopyOnProtected
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.NoteNoCopyOnProtected
```

______________________________________________________________________

## Stack Size

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.StackSize
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.StackSize
```

______________________________________________________________________

## X86 Feature

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.X86Features
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.X86Features
```

______________________________________________________________________

## X86 ISA

```{eval-rst}
.. lief-inheritance:: lief._lief.ELF.X86ISA
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.ELF.X86ISA
```

______________________________________________________________________

## Builder

```{eval-rst}
.. autoclass:: lief.ELF.Builder
```

## Enums

### Architectures

```{eval-rst}
.. autoclass:: lief.ELF.ARCH

```

### Processor Flags

```{eval-rst}
.. autoclass:: lief.ELF.PROCESSOR_FLAGS

```

## Utilities

```{eval-rst}
.. autofunction:: lief.ELF.check_layout
```

```{eval-rst}
.. autofunction:: lief.is_elf
```
