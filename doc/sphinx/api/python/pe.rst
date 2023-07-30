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

.. autoclass:: lief.PE.Section

----------


Import
*******

.. autoclass:: lief.PE.Import

----------


Import Entry
************

.. autoclass:: lief.PE.ImportEntry

----------

Delay Import
************

.. autoclass:: lief.PE.DelayImport

----------

Delay Import Entry
******************

.. autoclass:: lief.PE.DelayImportEntry

----------

TLS
***

.. autoclass:: lief.PE.TLS

----------

Symbol
*******

.. autoclass:: lief.PE.Symbol

----------

Relocation
**********

.. autoclass:: lief.PE.Relocation


----------

Relocation Entry
****************

.. autoclass:: lief.PE.RelocationEntry

----------

Export
******

.. autoclass:: lief.PE.Export

----------

Export Entry
************

.. autoclass:: lief.PE.ExportEntry

----------

Signature
*********

.. autoclass:: lief.PE.Signature

----------

Signature Attribute
*******************

.. autoclass:: lief.PE.Attribute

----------

Signature ContentType
*********************

.. autoclass:: lief.PE.ContentType

----------

Signature GenericType
*********************

.. autoclass:: lief.PE.GenericType

----------

Signature MsSpcNestedSignature
******************************

.. autoclass:: lief.PE.MsSpcNestedSignature

----------

Signature MsSpcStatementType
****************************

.. autoclass:: lief.PE.MsSpcStatementType

----------

Signature PKCS9AtSequenceNumber
*******************************

.. autoclass:: lief.PE.PKCS9AtSequenceNumber

----------

Signature PKCS9CounterSignature
*******************************

.. autoclass:: lief.PE.PKCS9CounterSignature

----------

Signature PKCS9MessageDigest
****************************

.. autoclass:: lief.PE.PKCS9MessageDigest

----------

Signature PKCS9SigningTime
**************************

.. autoclass:: lief.PE.PKCS9SigningTime

----------

Signature SpcSpOpusInfo
***********************

.. autoclass:: lief.PE.SpcSpOpusInfo

----------

Signature SpcIndirectData
*************************

.. autoclass:: lief.PE.SpcIndirectData

----------

Signature GenericType
*********************

.. autoclass:: lief.PE.GenericType

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

.. autoclass:: lief.PE.ContentInfo

----------


SignerInfo
**********

.. autoclass:: lief.PE.SignerInfo

----------

Builder
*******

.. autoclass:: lief.PE.Builder

----------

Resource Node
*************

.. autoclass:: lief.PE.ResourceNode

----------

Resource Directory
******************

.. autoclass:: lief.PE.ResourceDirectory

----------


Resource Data
*************

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

.. autoclass:: lief.PE.Debug

----------


Code View
*********

.. autoclass:: lief.PE.CodeView

----------

Code View PDB
**************

.. autoclass:: lief.PE.CodeViewPDB

----------

Code Integrity
**************

.. autoclass:: lief.PE.CodeIntegrity

----------

Pogo
****

.. autoclass:: lief.PE.Pogo

----------

Pogo Entry
**********

.. autoclass:: lief.PE.PogoEntry

----------

Repro
*****

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

RELOCATIONS_BASE_TYPES
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RELOCATIONS_BASE_TYPES

----------

RESOURCE_TYPES
~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RESOURCE_TYPES

----------

RESOURCE_LANGS
~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RESOURCE_LANGS

----------

RESOURCE_SUBLANGS
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.RESOURCE_SUBLANGS

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

FIXED_VERSION_FILE_SUB_TYPES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.FIXED_VERSION_FILE_SUB_TYPES

----------

WIN_VERSION
~~~~~~~~~~~

.. autoclass:: lief.PE.WIN_VERSION

----------

GUARD_CF_FLAGS
~~~~~~~~~~~~~~

.. autoclass:: lief.PE.GUARD_CF_FLAGS

----------

ALGORITHMS
~~~~~~~~~~

.. autoclass:: lief.PE.ALGORITHMS


SIG_ATTRIBUTE_TYPES
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.PE.SIG_ATTRIBUTE_TYPES
