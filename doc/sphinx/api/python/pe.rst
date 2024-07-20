PE
--

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

.. autoclass:: lief.PE.ResourceDialog

----------

Resource Dialog Item
*********************

.. autoclass:: lief.PE.ResourceDialogItem

----------

Resource Version
****************

.. autoclass:: lief.PE.ResourceVersion

----------

Resource Fixed File Info
************************

.. autoclass:: lief.PE.ResourceFixedFileInfo

----------

Resource Var File Info
**********************

.. autoclass:: lief.PE.ResourceVarFileInfo

----------

Resource String File Info
*************************

.. autoclass:: lief.PE.ResourceStringFileInfo

----------

Lang code item
**************

.. autoclass:: lief.PE.LangCodeItem

----------

Resource String Table
*********************

.. autoclass:: lief.PE.ResourceStringTable

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

Load Configuration
******************

.. autoclass:: lief.PE.LoadConfiguration

Load Configuration V0
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV0
  :show-inheritance:

Load Configuration V1
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV1
  :show-inheritance:

Load Configuration V2
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV2
  :show-inheritance:

Load Configuration V3
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV3
  :show-inheritance:

Load Configuration V4
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV4
  :show-inheritance:

Load Configuration V5
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV5
  :show-inheritance:

Load Configuration V6
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV6
  :show-inheritance:

Load Configuration V7
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV7
  :show-inheritance:

Load Configuration V8
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV8
  :show-inheritance:

Load Configuration V9
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV9
  :show-inheritance:

Load Configuration V10
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV10
  :show-inheritance:

Load Configuration V11
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.LoadConfigurationV11
  :show-inheritance:

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

SECTION_TYPES
~~~~~~~~~~~~~

.. autoclass:: lief.PE.SECTION_TYPES

----------

SYMBOL_BASE_TYPES
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.SYMBOL_BASE_TYPES

----------

SYMBOL_COMPLEX_TYPES
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.SYMBOL_COMPLEX_TYPES

----------

SYMBOL_SECTION_NUMBER
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.SYMBOL_SECTION_NUMBER

----------

SYMBOL_STORAGE_CLASS
~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.SYMBOL_STORAGE_CLASS

----------

FIXED_VERSION_FILE_SUB_TYPES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.CODE_PAGES

----------

WINDOW_STYLES
~~~~~~~~~~~~~

.. autoclass:: lief.PE.WINDOW_STYLES

----------

EXTENDED_WINDOW_STYLES
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.EXTENDED_WINDOW_STYLES

----------

DIALOG_BOX_STYLES
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.DIALOG_BOX_STYLES

----------

FIXED_VERSION_OS
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.FIXED_VERSION_OS

----------

FIXED_VERSION_FILE_FLAGS
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.FIXED_VERSION_FILE_FLAGS

----------

FIXED_VERSION_FILE_TYPES
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.FIXED_VERSION_FILE_TYPES

----------

RESOURCE_LANGS
~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RESOURCE_LANGS

-----------

FIXED_VERSION_FILE_SUB_TYPES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.FIXED_VERSION_FILE_SUB_TYPES

----------

ALGORITHMS
~~~~~~~~~~

.. autoclass:: lief.PE.ALGORITHMS
