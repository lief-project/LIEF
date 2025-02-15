:fa:`brands fa-python` Python
------------------------------

Parser
*******

.. autofunction:: lief.PE.parse

.. autoclass:: lief.PE.ParserConfig

Binary
******

.. autoclass:: lief.PE.Binary

----------

Dos Header
**********

.. autoclass:: lief.PE.DosHeader

----------

Header
*******

.. autoclass:: lief.PE.Header

----------

Optional Header
***************

.. autoclass:: lief.PE.OptionalHeader

----------

Data Directory
**************

.. autoclass:: lief.PE.DataDirectory

----------

Section
*******

.. lief-inheritance:: lief._lief.PE.Section
  :top-classes: lief._lief.Section
  :parts: 2

.. autoclass:: lief.PE.Section

----------

Import
*******

.. autoclass:: lief.PE.Import

----------


Import Entry
************

.. lief-inheritance:: lief._lief.PE.ImportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.PE.ImportEntry

----------

Delay Import
************

.. autoclass:: lief.PE.DelayImport

----------

Delay Import Entry
******************

.. lief-inheritance:: lief._lief.PE.DelayImportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.PE.DelayImportEntry

----------

TLS
***

.. autoclass:: lief.PE.TLS

----------

Symbol
*******

.. lief-inheritance:: lief._lief.PE.Symbol
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.PE.Symbol

----------

AuxiliarySymbol
***************

.. lief-inheritance:: lief._lief.PE.AuxiliarySymbol
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliarySymbol

----------

AuxiliaryCLRToken
*****************

.. lief-inheritance:: lief._lief.PE.AuxiliaryCLRToken
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliarySymbol

----------

AuxiliaryFunctionDefinition
***************************

.. lief-inheritance:: lief._lief.PE.AuxiliaryFunctionDefinition
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliaryFunctionDefinition

----------

AuxiliaryWeakExternal
*********************

.. lief-inheritance:: lief._lief.PE.AuxiliaryWeakExternal
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliaryWeakExternal

----------

AuxiliarybfAndefSymbol
**********************

.. lief-inheritance:: lief._lief.PE.AuxiliarybfAndefSymbol
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliarybfAndefSymbol

----------

AuxiliarySectionDefinition
**************************

.. lief-inheritance:: lief._lief.PE.AuxiliarySectionDefinition
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliarySectionDefinition

----------

AuxiliaryFile
*************

.. lief-inheritance:: lief._lief.PE.AuxiliaryFile
  :top-classes: lief._lief.PE.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.PE.AuxiliaryFile

----------

Relocation
**********

.. autoclass:: lief.PE.Relocation


----------

Relocation Entry
****************

.. lief-inheritance:: lief._lief.PE.RelocationEntry
  :top-classes: lief._lief.Relocation
  :parts: 2

.. autoclass:: lief.PE.RelocationEntry

----------

Export
******

.. autoclass:: lief.PE.Export

----------

Export Entry
************

.. lief-inheritance:: lief._lief.PE.ExportEntry
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.PE.ExportEntry

----------

Signature
*********

.. autoclass:: lief.PE.Signature

----------

Signature Attribute
*******************

.. lief-inheritance:: lief._lief.PE.Attribute
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.Attribute

----------

Signature ContentType
*********************

.. lief-inheritance:: lief._lief.PE.ContentType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.ContentType

----------

Signature GenericType
*********************

.. lief-inheritance:: lief._lief.PE.GenericType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.GenericType

----------

Signature MsSpcNestedSignature
******************************

.. lief-inheritance:: lief._lief.PE.MsSpcNestedSignature
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.MsSpcNestedSignature

----------

Signature MsSpcStatementType
****************************

.. lief-inheritance:: lief._lief.PE.MsSpcStatementType
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.MsSpcStatementType

----------

Signature PKCS9AtSequenceNumber
*******************************

.. lief-inheritance:: lief._lief.PE.PKCS9AtSequenceNumber
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.PKCS9AtSequenceNumber

----------

Signature PKCS9CounterSignature
*******************************

.. lief-inheritance:: lief._lief.PE.PKCS9CounterSignature
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.PKCS9CounterSignature

----------

Signature PKCS9MessageDigest
****************************

.. lief-inheritance:: lief._lief.PE.PKCS9MessageDigest
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.PKCS9MessageDigest

----------

Signature PKCS9SigningTime
**************************

.. lief-inheritance:: lief._lief.PE.PKCS9SigningTime
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.PKCS9SigningTime

----------

Signature SpcSpOpusInfo
***********************

.. lief-inheritance:: lief._lief.PE.SpcSpOpusInfo
  :top-classes: lief._lief.PE.Attribute
  :parts: 2

.. autoclass:: lief.PE.SpcSpOpusInfo

----------

Signature SpcIndirectData
*************************

.. lief-inheritance:: lief._lief.PE.SpcIndirectData
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2


.. autoclass:: lief.PE.SpcIndirectData

----------

GenericContent
**************

.. lief-inheritance:: lief._lief.PE.GenericContent
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2


.. autoclass:: lief.PE.GenericContent

----------

RsaInfo
*******

.. autoclass:: lief.PE.RsaInfo

----------

x509
****

.. autoclass:: lief.PE.x509

----------

ContentInfo
***********

.. lief-inheritance:: lief._lief.PE.ContentInfo.Content
  :top-classes: lief._lief.PE.ContentInfo.Content
  :parts: 2

.. autoclass:: lief.PE.ContentInfo

----------


SignerInfo
**********

.. autoclass:: lief.PE.SignerInfo

----------

MsCounterSign
*************

.. autoclass:: lief.PE.MsCounterSign

----------


PKCS9TSTInfo
************

.. autoclass:: lief.PE.PKCS9TSTInfo

----------


MsManifestBinaryID
******************

.. autoclass:: lief.PE.MsManifestBinaryID

----------

SpcRelaxedPeMarkerCheck
***********************

.. autoclass:: lief.PE.SpcRelaxedPeMarkerCheck

----------

SigningCertificateV2
********************

.. autoclass:: lief.PE.SigningCertificateV2

----------


Builder
*******

.. autoclass:: lief.PE.Builder

----------

Resource Node
*************

.. lief-inheritance:: lief._lief.PE.ResourceNode
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2

.. autoclass:: lief.PE.ResourceNode

----------

Resource Directory
******************

.. lief-inheritance:: lief._lief.PE.ResourceDirectory
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2

.. autoclass:: lief.PE.ResourceDirectory

----------


Resource Data
*************

.. lief-inheritance:: lief._lief.PE.ResourceData
  :top-classes: lief._lief.PE.ResourceNode
  :parts: 2

.. autoclass:: lief.PE.ResourceData

----------

Resources Manager
*****************

.. autoclass:: lief.PE.ResourcesManager

----------

Resource Icon
*************

.. autoclass:: lief.PE.ResourceIcon

----------

Resource Dialog
***************

.. lief-inheritance:: lief._lief.PE.ResourceDialog
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2

.. autoclass:: lief.PE.ResourceDialog

----------

Resource Dialog -- Regular
**************************

.. lief-inheritance:: lief._lief.PE.ResourceDialogRegular
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2

.. autoclass:: lief.PE.ResourceDialogRegular

----------

Resource Dialog -- Extended
***************************

.. lief-inheritance:: lief._lief.PE.ResourceDialogExtended
  :top-classes: lief._lief.PE.ResourceDialog
  :parts: 2

.. autoclass:: lief.PE.ResourceDialogExtended

----------

Resource Version
****************

.. autoclass:: lief.PE.ResourceVersion

----------

Resource Var File Info
**********************

.. autoclass:: lief.PE.ResourceVarFileInfo

----------

Resource Var File Info
**********************

.. autoclass:: lief.PE.ResourceVarFileInfo

----------

Resource Var
************

.. autoclass:: lief.PE.ResourceVar

----------

Resource String Table
*********************

.. autoclass:: lief.PE.ResourceStringTable

----------

Resource Accelerator
********************

.. autoclass:: lief.PE.ResourceAccelerator

----------

Rich Header
***********

.. autoclass:: lief.PE.RichHeader

----------

Rich Entry
**********

.. autoclass:: lief.PE.RichEntry

----------

Debug
*****

.. lief-inheritance:: lief._lief.PE.Debug
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.Debug

----------


Code View
*********

.. lief-inheritance:: lief._lief.PE.CodeView
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.CodeView

----------

Code View PDB
**************

.. lief-inheritance:: lief._lief.PE.CodeViewPDB
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.CodeViewPDB

----------

Code Integrity
**************

.. autoclass:: lief.PE.CodeIntegrity

----------

Pogo
****

.. lief-inheritance:: lief._lief.PE.Pogo
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.Pogo

----------

Pogo Entry
**********

.. autoclass:: lief.PE.PogoEntry

----------

Repro
*****

.. lief-inheritance:: lief._lief.PE.Repro
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.Repro

----------

PDBChecksum
***********

.. lief-inheritance:: lief._lief.PE.PDBChecksum
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.PDBChecksum

----------


VCFeature
*********

.. lief-inheritance:: lief._lief.PE.VCFeature
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.VCFeature

----------

ExDllCharacteristics
********************

.. lief-inheritance:: lief._lief.PE.ExDllCharacteristics
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.ExDllCharacteristics

----------

Frame Pointer Omission (FPO)
****************************

.. lief-inheritance:: lief._lief.PE.FPO
  :top-classes: lief._lief.PE.Debug
  :parts: 2

.. autoclass:: lief.PE.FPO

----------

COFF String
***********

.. autoclass:: lief.PE.COFFString

----------

Exception Info
**************

.. lief-inheritance:: lief._lief.PE.ExceptionInfo
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2

.. autoclass:: lief.PE.ExceptionInfo

----------

RuntimeFunctionX64
******************

.. lief-inheritance:: lief._lief.PE.RuntimeFunctionX64
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2

.. autoclass:: lief.PE.RuntimeFunctionX64

----------

unwind_x64 - Code
*****************

.. lief-inheritance:: lief._lief.PE.unwind_x64.Code
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.Code

----------

unwind_x64 - Alloc
******************

.. lief-inheritance:: lief._lief.PE.unwind_x64.Alloc
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.Alloc

----------

unwind_x64 - PushNonVol
***********************

.. lief-inheritance:: lief._lief.PE.unwind_x64.PushNonVol
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.PushNonVol

----------

unwind_x64 - PushMachFrame
**************************

.. lief-inheritance:: lief._lief.PE.unwind_x64.PushMachFrame
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.PushMachFrame

----------

unwind_x64 - SetFPReg
*********************

.. lief-inheritance:: lief._lief.PE.unwind_x64.SetFPReg
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.SetFPReg

----------

unwind_x64 - SaveNonVolatile
****************************

.. lief-inheritance:: lief._lief.PE.unwind_x64.SaveNonVolatile
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.SaveNonVolatile

----------

unwind_x64 - SaveXMM128
***********************

.. lief-inheritance:: lief._lief.PE.unwind_x64.SaveXMM128
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.SaveXMM128

----------

unwind_x64 - Epilog
*******************

.. lief-inheritance:: lief._lief.PE.unwind_x64.Epilog
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.Epilog

----------

unwind_x64 - Spare
******************

.. lief-inheritance:: lief._lief.PE.unwind_x64.Spare
  :top-classes: lief._lief.PE.unwind_x64.Code
  :parts: 2

.. autoclass:: lief.PE.unwind_x64.Spare

----------

RuntimeFunctionAArch64
**********************

.. lief-inheritance:: lief._lief.PE.RuntimeFunctionAArch64
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2

.. autoclass:: lief.PE.RuntimeFunctionAArch64

Runtime AArch64 (Packed) Function
*********************************

.. lief-inheritance:: lief._lief.PE.unwind_aarch64.PackedFunction
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2

.. autoclass:: lief.PE.unwind_aarch64.PackedFunction


Runtime AArch64 (UnpackedFunction) Function
*******************************************

.. lief-inheritance:: lief._lief.PE.unwind_aarch64.UnpackedFunction
  :top-classes: lief._lief.PE.ExceptionInfo
  :parts: 2

.. autoclass:: lief.PE.unwind_aarch64.UnpackedFunction

----------

Load Configuration
******************

.. autoclass:: lief.PE.LoadConfiguration

----------

CHPEMetadata
************

.. lief-inheritance:: lief._lief.PE.CHPEMetadata
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2

.. autoclass:: lief.PE.CHPEMetadata

----------

CHPEMetadata (ARM64)
*********************

.. lief-inheritance:: lief._lief.PE.CHPEMetadataARM64
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2

.. autoclass:: lief.PE.CHPEMetadataARM64

CHPEMetadata (X86)
******************

.. lief-inheritance:: lief._lief.PE.CHPEMetadataX86
  :top-classes: lief._lief.PE.CHPEMetadata
  :parts: 2

.. autoclass:: lief.PE.CHPEMetadataX86

----------

DynamicRelocation
*****************

.. lief-inheritance:: lief._lief.PE.DynamicRelocation
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2

.. autoclass:: lief.PE.DynamicRelocation

DynamicRelocationV1
*******************

.. lief-inheritance:: lief._lief.PE.DynamicRelocationV1
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2

.. autoclass:: lief.PE.DynamicRelocationV1

DynamicRelocationV2
*******************

.. lief-inheritance:: lief._lief.PE.DynamicRelocationV2
  :top-classes: lief._lief.PE.DynamicRelocation
  :parts: 2

.. autoclass:: lief.PE.DynamicRelocationV2

----------

DynamicFixup
************

.. lief-inheritance:: lief._lief.PE.DynamicFixup
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixup


DynamicFixupControlTransfer
***************************

.. lief-inheritance:: lief._lief.PE.DynamicFixupControlTransfer
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixupControlTransfer

DynamicFixupARM64Kernel
***********************

.. lief-inheritance:: lief._lief.PE.DynamicFixupARM64Kernel
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixupARM64Kernel

DynamicFixupARM64X
******************

.. lief-inheritance:: lief._lief.PE.DynamicFixupARM64X
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixupARM64X


DynamicFixupGeneric
*******************

.. lief-inheritance:: lief._lief.PE.DynamicFixupGeneric
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixupGeneric

DynamicFixupUnknown
*******************

.. lief-inheritance:: lief._lief.PE.DynamicFixupUnknown
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.DynamicFixupUnknown

FunctionOverride
****************

.. lief-inheritance:: lief._lief.PE.FunctionOverride
  :top-classes: lief._lief.PE.DynamicFixup
  :parts: 2

.. autoclass:: lief.PE.FunctionOverride


FunctionOverrideInfo
********************

.. autoclass:: lief.PE.FunctionOverrideInfo


----------

EnclaveConfiguration
********************

.. autoclass:: lief.PE.EnclaveConfiguration

----------

EnclaveImport
*************

.. autoclass:: lief.PE.EnclaveImport

----------

Volatile Metadata
*****************

.. autoclass:: lief.PE.VolatileMetadata

----------

Utilities
*********

.. autofunction:: lief.is_pe

.. autofunction:: lief.PE.get_type

.. autofunction:: lief.PE.get_imphash

.. autoclass:: lief.PE.IMPHASH_MODE

.. autofunction:: lief.PE.resolve_ordinals

-----------

Enums
*****

PE_TYPE
~~~~~~~

.. autoclass:: lief.PE.PE_TYPE

----------

RESOURCE_LANGS
~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RESOURCE_LANGS

ACCELERATOR_CODES
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.ACCELERATOR_CODES

-----------

ALGORITHMS
~~~~~~~~~~

.. autoclass:: lief.PE.ALGORITHMS
