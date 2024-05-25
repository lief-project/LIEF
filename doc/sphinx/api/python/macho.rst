MachO
-----


Parser
*******

.. autofunction:: lief.MachO.parse

.. autoclass:: lief.MachO.ParserConfig

.. code-block:: python

  fatbinary_1 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.deep)
  # or
  fatbinary_2 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.quick)


----------


FatBinary
*********

.. autoclass:: lief.MachO.FatBinary

----------


.. _python-macho-binary-api-ref:

Binary
******

.. autoclass:: lief.MachO.Binary

----------

Header
******

.. autoclass:: lief.MachO.Header

----------


Section
*******

.. lief-inheritance:: lief._lief.MachO.Section
  :top-classes: lief._lief.Section
  :parts: 2

.. autoclass:: lief.MachO.Section

----------


SegmentCommand
**************

.. lief-inheritance:: lief._lief.MachO.SegmentCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.SegmentCommand

----------


LoadCommand
***********

.. lief-inheritance:: lief._lief.MachO.LoadCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.LoadCommand

----------


DylibCommand
************

.. lief-inheritance:: lief._lief.MachO.DylibCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DylibCommand


----------

DylinkerCommand
***************

.. lief-inheritance:: lief._lief.MachO.DylinkerCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DylinkerCommand


----------

UUIDCommand
***********

.. lief-inheritance:: lief._lief.MachO.UUIDCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.UUIDCommand


----------


MainCommand
***********

.. lief-inheritance:: lief._lief.MachO.MainCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.MainCommand

----------


Symbol
******

.. lief-inheritance:: lief._lief.MachO.Symbol
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.MachO.Symbol

----------


Symbol Command
**************

.. lief-inheritance:: lief._lief.MachO.DylinkerCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.SymbolCommand

----------

Dynamic Symbol Command
**********************

.. lief-inheritance:: lief._lief.MachO.DynamicSymbolCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2


.. autoclass:: lief.MachO.DynamicSymbolCommand

----------

Dyld Info
*********

.. lief-inheritance:: lief._lief.MachO.DyldInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2


.. autoclass:: lief.MachO.DyldInfo

----------

Function starts
***************

.. lief-inheritance:: lief._lief.MachO.FunctionStarts
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2


.. autoclass:: lief.MachO.FunctionStarts

----------

Source Version
**************

.. lief-inheritance:: lief._lief.MachO.SourceVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2


.. autoclass:: lief.MachO.SourceVersion

----------


Version Min
***********

.. lief-inheritance:: lief._lief.MachO.VersionMin
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.VersionMin

----------


Relocation
**********

.. lief-inheritance:: lief._lief.MachO.Relocation
  :top-classes: lief._lief.Relocation
  :parts: 2

.. autoclass:: lief.MachO.Relocation

----------


Relocation Object
*****************

.. lief-inheritance:: lief._lief.MachO.RelocationObject
  :top-classes: lief._lief.Relocation
  :parts: 2

.. autoclass:: lief.MachO.RelocationObject

----------


Relocation Dyld
***************

.. lief-inheritance:: lief._lief.MachO.RelocationDyld
  :top-classes: lief._lief.Relocation
  :parts: 2

.. autoclass:: lief.MachO.RelocationDyld

----------

Relocation Fixup
****************

.. lief-inheritance:: lief._lief.MachO.RelocationFixup
  :top-classes: lief._lief.Relocation
  :parts: 2

.. autoclass:: lief.MachO.RelocationFixup

----------


Binding Info
************

.. lief-inheritance:: lief._lief.MachO.BindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2

.. autoclass:: lief.MachO.BindingInfo

----------

Dyld Binding Info
*****************

.. lief-inheritance:: lief._lief.MachO.DyldBindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2

.. autoclass:: lief.MachO.DyldBindingInfo

----------


Chained Binding Info
********************

.. lief-inheritance:: lief._lief.MachO.ChainedBindingInfo
  :top-classes: lief._lief.MachO.BindingInfo
  :parts: 2

.. autoclass:: lief.MachO.ChainedBindingInfo

----------


Export Info
***********

.. autoclass:: lief.MachO.ExportInfo

----------


Thread Command
**************

.. lief-inheritance:: lief._lief.MachO.ThreadCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.ThreadCommand

----------

RPath Command
*************

.. lief-inheritance:: lief._lief.MachO.RPathCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.RPathCommand

----------


Code Signature
**************

.. lief-inheritance:: lief._lief.MachO.CodeSignature
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.CodeSignature

----------

Data In Code
************

.. lief-inheritance:: lief._lief.MachO.DataInCode
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DataInCode

----------

Data Code Entry
***************

.. autoclass:: lief.MachO.DataCodeEntry

----------

Segment Split Info
******************

.. lief-inheritance:: lief._lief.MachO.SegmentSplitInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.SegmentSplitInfo

----------

Sub Framework
*************

.. lief-inheritance:: lief._lief.MachO.SubFramework
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.SubFramework

----------

Dyld Environment
****************

.. lief-inheritance:: lief._lief.MachO.DyldEnvironment
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DyldEnvironment

----------

Encryption Info
***************

.. lief-inheritance:: lief._lief.MachO.EncryptionInfo
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.EncryptionInfo

----------

Build Version
*************

.. lief-inheritance:: lief._lief.MachO.BuildVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.BuildVersion

----------

Build Tool Version
******************

.. lief-inheritance:: lief._lief.MachO.BuildToolVersion
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.BuildToolVersion

----------

Fileset Command
***************

.. lief-inheritance:: lief._lief.MachO.FilesetCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.FilesetCommand

----------

DyldChainedFixups Command
*************************

.. lief-inheritance:: lief._lief.MachO.DyldChainedFixups
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DyldChainedFixups

----------

DyldExportsTrie Command
***********************

.. lief-inheritance:: lief._lief.MachO.DyldExportsTrie
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.DyldExportsTrie

----------

Code Signature Dir Command
**************************

.. lief-inheritance:: lief._lief.MachO.CodeSignatureDir
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.CodeSignatureDir

----------

Two Level Hints
***************

.. lief-inheritance:: lief._lief.MachO.TwoLevelHints
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.TwoLevelHints

----------

Linker Optimization Hint
************************

.. lief-inheritance:: lief._lief.MachO.LinkerOptHint
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.LinkerOptHint

----------

UnknownCommand
**************

.. lief-inheritance:: lief._lief.MachO.UnknownCommand
  :top-classes: lief._lief.MachO.LoadCommand
  :parts: 2

.. autoclass:: lief.MachO.UnknownCommand

----------

Builder
*******

.. autoclass:: lief.MachO.Builder

----------

Enums
*****

MACHO_TYPES
~~~~~~~~~~~

.. autoclass:: lief.MachO.MACHO_TYPES

----------


X86_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.X86_RELOCATION

----------

X86_64_RELOCATION
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.X86_64_RELOCATION

----------


PPC_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.PPC_RELOCATION

----------


ARM_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.ARM_RELOCATION

----------

ARM64_RELOCATION
~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.ARM64_RELOCATION


DYLD_CHAINED_FORMAT
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_FORMAT

DYLD_CHAINED_PTR_FORMAT
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_PTR_FORMAT
