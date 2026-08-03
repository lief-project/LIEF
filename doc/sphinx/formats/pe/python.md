# {fa}`brands fa-python` Python

## Parser

```{eval-rst}
.. autofunction:: lief.PE.parse
```

```{eval-rst}
.. autoclass:: lief.PE.ParserConfig
```

## Binary

```{eval-rst}
.. autoclass:: lief.PE.Binary
```

______________________________________________________________________

## Dos Header

```{eval-rst}
.. autoclass:: lief.PE.DosHeader
```

______________________________________________________________________

## Header

```{eval-rst}
.. autoclass:: lief.PE.Header
```

______________________________________________________________________

## Optional Header

```{eval-rst}
.. autoclass:: lief.PE.OptionalHeader
```

______________________________________________________________________

## Data Directory

```{eval-rst}
.. autoclass:: lief.PE.DataDirectory
```

______________________________________________________________________

## Section

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.Section
  :top-classes: lief._lief.Section
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.Section
```

______________________________________________________________________

## Import

```{eval-rst}
.. autoclass:: lief.PE.Import
```

______________________________________________________________________

## Import Entry

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ImportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ImportEntry
```

______________________________________________________________________

## Delay Import

```{eval-rst}
.. autoclass:: lief.PE.DelayImport
```

______________________________________________________________________

## Delay Import Entry

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DelayImportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DelayImportEntry
```

______________________________________________________________________

## TLS

```{eval-rst}
.. autoclass:: lief.PE.TLS
```

______________________________________________________________________

## Relocation

```{eval-rst}
.. autoclass:: lief.PE.Relocation

```

______________________________________________________________________

## Relocation Entry

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.RelocationEntry
  :top-classes: lief._lief.Relocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.RelocationEntry
```

______________________________________________________________________

## Export

```{eval-rst}
.. autoclass:: lief.PE.Export
```

______________________________________________________________________

## Export Entry

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ExportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ExportEntry
```

______________________________________________________________________

## Signature

```{eval-rst}
.. autoclass:: lief.PE.Signature
```

______________________________________________________________________

## Signature Attribute

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.Attribute
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.Attribute
```

______________________________________________________________________

## Signature ContentType

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ContentType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ContentType
```

______________________________________________________________________

## Signature GenericType

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.GenericType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.GenericType
```

______________________________________________________________________

## Signature MsSpcNestedSignature

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.MsSpcNestedSignature
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.MsSpcNestedSignature
```

______________________________________________________________________

## Signature MsSpcStatementType

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.MsSpcStatementType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.MsSpcStatementType
```

______________________________________________________________________

## Signature PKCS9AtSequenceNumber

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.PKCS9AtSequenceNumber
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.PKCS9AtSequenceNumber
```

______________________________________________________________________

## Signature PKCS9CounterSignature

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.PKCS9CounterSignature
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.PKCS9CounterSignature
```

______________________________________________________________________

## Signature PKCS9MessageDigest

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.PKCS9MessageDigest
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.PKCS9MessageDigest
```

______________________________________________________________________

## Signature PKCS9SigningTime

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.PKCS9SigningTime
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.PKCS9SigningTime
```

______________________________________________________________________

## Signature SpcSpOpusInfo

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.SpcSpOpusInfo
  :top-classes: lief._lief.PE.Attribute
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.SpcSpOpusInfo
```

______________________________________________________________________

## Signature SpcIndirectData

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.SpcIndirectData
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.PE.SpcIndirectData
```

______________________________________________________________________

## GenericContent

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.GenericContent
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2

```

```{eval-rst}
.. autoclass:: lief.PE.GenericContent
```

______________________________________________________________________

## RsaInfo

```{eval-rst}
.. autoclass:: lief.PE.RsaInfo
```

______________________________________________________________________

## x509

```{eval-rst}
.. autoclass:: lief.PE.x509
```

______________________________________________________________________

## ContentInfo

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ContentInfo.Content
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ContentInfo
```

______________________________________________________________________

## SignerInfo

```{eval-rst}
.. autoclass:: lief.PE.SignerInfo
```

______________________________________________________________________

## MsCounterSign

```{eval-rst}
.. autoclass:: lief.PE.MsCounterSign
```

______________________________________________________________________

## PKCS9TSTInfo

```{eval-rst}
.. autoclass:: lief.PE.PKCS9TSTInfo
```

______________________________________________________________________

## MsManifestBinaryID

```{eval-rst}
.. autoclass:: lief.PE.MsManifestBinaryID
```

______________________________________________________________________

## SpcRelaxedPeMarkerCheck

```{eval-rst}
.. autoclass:: lief.PE.SpcRelaxedPeMarkerCheck
```

______________________________________________________________________

## SigningCertificateV2

```{eval-rst}
.. autoclass:: lief.PE.SigningCertificateV2
```

______________________________________________________________________

## Builder

```{eval-rst}
.. autoclass:: lief.PE.Builder
```

______________________________________________________________________

## Resource Node

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceNode
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceNode
```

______________________________________________________________________

## Resource Directory

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceDirectory
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceDirectory
```

______________________________________________________________________

## Resource Data

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceData
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceData
```

______________________________________________________________________

## Resources Manager

```{eval-rst}
.. autoclass:: lief.PE.ResourcesManager
```

______________________________________________________________________

## Resource Icon

```{eval-rst}
.. autoclass:: lief.PE.ResourceIcon
```

______________________________________________________________________

## Resource Dialog

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceDialog
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceDialog
```

______________________________________________________________________

## Resource Dialog -- Regular

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceDialogRegular
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceDialogRegular
```

______________________________________________________________________

## Resource Dialog -- Extended

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ResourceDialogExtended
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ResourceDialogExtended
```

______________________________________________________________________

## Resource Version

```{eval-rst}
.. autoclass:: lief.PE.ResourceVersion
```

______________________________________________________________________

## Resource Var File Info

```{eval-rst}
.. autoclass:: lief.PE.ResourceVarFileInfo
```

______________________________________________________________________

## Resource String File Info

```{eval-rst}
.. autoclass:: lief.PE.ResourceStringFileInfo
```

______________________________________________________________________

## Resource Var

```{eval-rst}
.. autoclass:: lief.PE.ResourceVar
```

______________________________________________________________________

## Resource String Table

```{eval-rst}
.. autoclass:: lief.PE.ResourceStringTable
```

______________________________________________________________________

## Resource Accelerator

```{eval-rst}
.. autoclass:: lief.PE.ResourceAccelerator
```

______________________________________________________________________

## Rich Header

```{eval-rst}
.. autoclass:: lief.PE.RichHeader
```

______________________________________________________________________

## Rich Entry

```{eval-rst}
.. autoclass:: lief.PE.RichEntry
```

______________________________________________________________________

## Debug

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.Debug
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.Debug
```

______________________________________________________________________

## Code View

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.CodeView
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.CodeView
```

______________________________________________________________________

## Code View PDB

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.CodeViewPDB
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.CodeViewPDB
```

______________________________________________________________________

## Code Integrity

```{eval-rst}
.. autoclass:: lief.PE.CodeIntegrity
```

______________________________________________________________________

## Pogo

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.Pogo
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.Pogo
```

______________________________________________________________________

## Pogo Entry

```{eval-rst}
.. autoclass:: lief.PE.PogoEntry
```

______________________________________________________________________

## Repro

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.Repro
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.Repro
```

______________________________________________________________________

## PDBChecksum

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.PDBChecksum
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.PDBChecksum
```

______________________________________________________________________

## VCFeature

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.VCFeature
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.VCFeature
```

______________________________________________________________________

## ExDllCharacteristics

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ExDllCharacteristics
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ExDllCharacteristics
```

______________________________________________________________________

## Frame Pointer Omission (FPO)

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.FPO
  :top-classes: lief._lief.PE.Debug
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.FPO
```

______________________________________________________________________

## Exception Info

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.ExceptionInfo
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.ExceptionInfo
```

______________________________________________________________________

## RuntimeFunctionX64

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.RuntimeFunctionX64
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.RuntimeFunctionX64
```

______________________________________________________________________

## unwind_x64 - Code

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.Code
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.Code
```

______________________________________________________________________

## unwind_x64 - Alloc

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.Alloc
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.Alloc
```

______________________________________________________________________

## unwind_x64 - PushNonVol

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.PushNonVol
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.PushNonVol
```

______________________________________________________________________

## unwind_x64 - PushMachFrame

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.PushMachFrame
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.PushMachFrame
```

______________________________________________________________________

## unwind_x64 - SetFPReg

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.SetFPReg
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.SetFPReg
```

______________________________________________________________________

## unwind_x64 - SaveNonVolatile

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.SaveNonVolatile
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.SaveNonVolatile
```

______________________________________________________________________

## unwind_x64 - SaveXMM128

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.SaveXMM128
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.SaveXMM128
```

______________________________________________________________________

## unwind_x64 - Epilog

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.Epilog
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.Epilog
```

______________________________________________________________________

## unwind_x64 - Spare

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_x64.Spare
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_x64.Spare
```

______________________________________________________________________

## RuntimeFunctionAArch64

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.RuntimeFunctionAArch64
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.RuntimeFunctionAArch64
```

## Runtime AArch64 (Packed) Function

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_aarch64.PackedFunction
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_aarch64.PackedFunction

```

## Runtime AArch64 (UnpackedFunction) Function

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.unwind_aarch64.UnpackedFunction
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.unwind_aarch64.UnpackedFunction
```

______________________________________________________________________

## Load Configuration

```{eval-rst}
.. autoclass:: lief.PE.LoadConfiguration
```

______________________________________________________________________

## CHPEMetadata

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.CHPEMetadata
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.CHPEMetadata
```

______________________________________________________________________

## CHPEMetadata (ARM64)

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.CHPEMetadataARM64
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.CHPEMetadataARM64
```

## CHPEMetadata (X86)

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.CHPEMetadataX86
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.CHPEMetadataX86
```

______________________________________________________________________

## DynamicRelocation

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicRelocation
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicRelocation
```

## DynamicRelocationV1

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicRelocationV1
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicRelocationV1
```

## DynamicRelocationV2

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicRelocationV2
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicRelocationV2
```

______________________________________________________________________

## DynamicFixup

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixup
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixup

```

## DynamicFixupControlTransfer

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixupControlTransfer
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixupControlTransfer
```

## DynamicFixupARM64Kernel

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixupARM64Kernel
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixupARM64Kernel
```

## DynamicFixupARM64X

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixupARM64X
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixupARM64X

```

## DynamicFixupGeneric

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixupGeneric
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixupGeneric
```

## DynamicFixupUnknown

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.DynamicFixupUnknown
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.DynamicFixupUnknown
```

## FunctionOverride

```{eval-rst}
.. lief-inheritance:: lief._lief.PE.FunctionOverride
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2
```

```{eval-rst}
.. autoclass:: lief.PE.FunctionOverride

```

## FunctionOverrideInfo

```{eval-rst}
.. autoclass:: lief.PE.FunctionOverrideInfo

```

______________________________________________________________________

## EnclaveConfiguration

```{eval-rst}
.. autoclass:: lief.PE.EnclaveConfiguration
```

______________________________________________________________________

## EnclaveImport

```{eval-rst}
.. autoclass:: lief.PE.EnclaveImport
```

______________________________________________________________________

## Volatile Metadata

```{eval-rst}
.. autoclass:: lief.PE.VolatileMetadata
```

______________________________________________________________________

## Utilities

```{eval-rst}
.. autofunction:: lief.PE.check_layout
```

```{eval-rst}
.. autofunction:: lief.is_pe
```

```{eval-rst}
.. autofunction:: lief.PE.get_type
```

```{eval-rst}
.. autofunction:: lief.PE.get_imphash
```

```{eval-rst}
.. autoclass:: lief.PE.IMPHASH_MODE
```

```{eval-rst}
.. autofunction:: lief.PE.resolve_ordinals
```

______________________________________________________________________

## Enums

### PE_TYPE

```{eval-rst}
.. autoclass:: lief.PE.PE_TYPE
```

______________________________________________________________________

### RESOURCE_LANGS

```{eval-rst}
.. autoclass:: lief.PE.RESOURCE_LANGS
```

### ACCELERATOR_CODES

```{eval-rst}
.. autoclass:: lief.PE.ACCELERATOR_CODES
```

______________________________________________________________________

### ALGORITHMS

```{eval-rst}
.. autoclass:: lief.PE.ALGORITHMS
```
