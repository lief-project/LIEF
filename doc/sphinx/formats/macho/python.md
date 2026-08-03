# {fa}`brands fa-python` Python

## Parser

```{eval-rst}
.. autofunction:: lief.MachO.parse
```

```{eval-rst}
.. autoclass:: lief.MachO.ParserConfig
```

{{ literalinclude("../../../code/python/macho.py", "parse-config") }}

______________________________________________________________________

## FatBinary

```{eval-rst}
.. autoclass:: lief.MachO.FatBinary
```

______________________________________________________________________

(python-macho-binary-api-ref)=

## Binary

```{eval-rst}
.. autoclass:: lief.MachO.Binary
```

______________________________________________________________________

## Header

```{eval-rst}
.. autoclass:: lief.MachO.Header
```

______________________________________________________________________

## Section

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.Section
  :top-classes: lief._lief.Section
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.Section
```

______________________________________________________________________

## ThreadLocalVariables

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.ThreadLocalVariables
  :top-classes: lief._lief.MachO.Section
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.ThreadLocalVariables
```

______________________________________________________________________

## SegmentCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.SegmentCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.SegmentCommand
```

______________________________________________________________________

## LoadCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.LoadCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.LoadCommand
```

______________________________________________________________________

## DylibCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DylibCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DylibCommand

```

______________________________________________________________________

## DylinkerCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DylinkerCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DylinkerCommand

```

______________________________________________________________________

## UUIDCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.UUIDCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.UUIDCommand

```

______________________________________________________________________

## MainCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.MainCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.MainCommand
```

______________________________________________________________________

## NoteCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.NoteCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.NoteCommand
```

______________________________________________________________________

## Symbol

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.Symbol
  :top-classes: lief._lief.Symbol
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.Symbol
```

______________________________________________________________________

## Symbol Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DylinkerCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.SymbolCommand
```

______________________________________________________________________

## Dynamic Symbol Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DynamicSymbolCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.DynamicSymbolCommand
```

______________________________________________________________________

## Dyld Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DyldInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.DyldInfo
```

______________________________________________________________________

## Function starts

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.FunctionStarts
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.FunctionStarts
```

______________________________________________________________________

## Function Variants

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.FunctionVariants
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.FunctionVariants
```

______________________________________________________________________

## Function Variant Fixups

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.FunctionVariantFixups
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.FunctionVariantFixups
```

______________________________________________________________________

## Lazy Load Dylib Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.LazyLoadDylibInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.LazyLoadDylibInfo
```

______________________________________________________________________

## Source Version

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.SourceVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.MachO.SourceVersion
```

______________________________________________________________________

## Version Min

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.VersionMin
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.VersionMin
```

______________________________________________________________________

## Routine

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.Routine
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.Routine
```

______________________________________________________________________

## Relocation

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.Relocation
  :top-classes: lief._lief.Relocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.Relocation
```

______________________________________________________________________

## Relocation Object

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.RelocationObject
  :top-classes: lief._lief.Relocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.RelocationObject
```

______________________________________________________________________

## Relocation Dyld

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.RelocationDyld
  :top-classes: lief._lief.Relocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.RelocationDyld
```

______________________________________________________________________

## Relocation Fixup

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.RelocationFixup
  :top-classes: lief._lief.Relocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.RelocationFixup
```

______________________________________________________________________

## Binding Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.BindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.BindingInfo
```

______________________________________________________________________

## Dyld Binding Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DyldBindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DyldBindingInfo
```

______________________________________________________________________

## Chained Binding Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.ChainedBindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.ChainedBindingInfo
```

______________________________________________________________________

## Export Info

```{eval-rst}
.. autoclass:: lief.MachO.ExportInfo
```

______________________________________________________________________

## Thread Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.ThreadCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.ThreadCommand
```

______________________________________________________________________

## RPath Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.RPathCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.RPathCommand
```

______________________________________________________________________

## Code Signature

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.CodeSignature
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.CodeSignature
```

______________________________________________________________________

## Data In Code

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DataInCode
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DataInCode
```

______________________________________________________________________

## Data Code Entry

```{eval-rst}
.. autoclass:: lief.MachO.DataCodeEntry
```

______________________________________________________________________

## Segment Split Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.SegmentSplitInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.SegmentSplitInfo
```

______________________________________________________________________

## Sub Framework

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.SubFramework
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.SubFramework
```

______________________________________________________________________

## Sub Client

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.SubClient
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.SubClient
```

______________________________________________________________________

## Dyld Environment

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DyldEnvironment
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DyldEnvironment
```

______________________________________________________________________

## Encryption Info

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.EncryptionInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.EncryptionInfo
```

______________________________________________________________________

## Build Version

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.BuildVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.BuildVersion
```

______________________________________________________________________

## Build Tool Version

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.BuildToolVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.BuildToolVersion
```

______________________________________________________________________

## Fileset Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.FilesetCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.FilesetCommand
```

______________________________________________________________________

## DyldChainedFixups Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DyldChainedFixups
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DyldChainedFixups
```

______________________________________________________________________

## DyldExportsTrie Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.DyldExportsTrie
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.DyldExportsTrie
```

______________________________________________________________________

## Code Signature Dir Command

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.CodeSignatureDir
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.CodeSignatureDir
```

______________________________________________________________________

## Two Level Hints

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.TwoLevelHints
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.TwoLevelHints
```

______________________________________________________________________

## Linker Optimization Hint

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.LinkerOptHint
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.LinkerOptHint
```

______________________________________________________________________

## UnknownCommand

```{eval-rst}
.. lief-inheritance:: lief._lief.MachO.UnknownCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.MachO.UnknownCommand
```

______________________________________________________________________

## Stub

```{eval-rst}
.. autoclass:: lief.MachO.Stub
```

______________________________________________________________________

## Builder

```{eval-rst}
.. autoclass:: lief.MachO.Builder
```

______________________________________________________________________

## Utilities

```{eval-rst}
.. autofunction:: lief.MachO.check_layout
```

______________________________________________________________________

## Enums

### MACHO_TYPES

```{eval-rst}
.. autoclass:: lief.MachO.MACHO_TYPES
```

______________________________________________________________________

### X86_RELOCATION

```{eval-rst}
.. autoclass:: lief.MachO.X86_RELOCATION
```

______________________________________________________________________

### X86_64_RELOCATION

```{eval-rst}
.. autoclass:: lief.MachO.X86_64_RELOCATION
```

______________________________________________________________________

### PPC_RELOCATION

```{eval-rst}
.. autoclass:: lief.MachO.PPC_RELOCATION
```

______________________________________________________________________

### ARM_RELOCATION

```{eval-rst}
.. autoclass:: lief.MachO.ARM_RELOCATION
```

______________________________________________________________________

### ARM64_RELOCATION

```{eval-rst}
.. autoclass:: lief.MachO.ARM64_RELOCATION

```

### DYLD_CHAINED_FORMAT

```{eval-rst}
.. autoclass:: lief.MachO.DYLD_CHAINED_FORMAT
```

### DYLD_CHAINED_PTR_FORMAT

```{eval-rst}
.. autoclass:: lief.MachO.DYLD_CHAINED_PTR_FORMAT
```
