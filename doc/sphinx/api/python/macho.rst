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

.. autoclass:: lief.MachO.Section

----------


SegmentCommand
**************

.. autoclass:: lief.MachO.SegmentCommand

----------


LoadCommand
***********

.. autoclass:: lief.MachO.LoadCommand

----------


DylibCommand
************

.. autoclass:: lief.MachO.DylibCommand


----------

DylinkerCommand
***************

.. autoclass:: lief.MachO.DylinkerCommand


----------

UUIDCommand
***********

.. autoclass:: lief.MachO.UUIDCommand


----------


MainCommand
***********

.. autoclass:: lief.MachO.MainCommand

----------


Symbol
******

.. autoclass:: lief.MachO.Symbol

----------


Symbol Command
**************

.. autoclass:: lief.MachO.SymbolCommand

----------

Dynamic Symbol Command
**********************

.. autoclass:: lief.MachO.DynamicSymbolCommand

----------

Dyld Info
*********

.. autoclass:: lief.MachO.DyldInfo

----------

Function starts
***************

.. autoclass:: lief.MachO.FunctionStarts

----------

Source Version
**************

.. autoclass:: lief.MachO.SourceVersion

----------


Version Min
***********

.. autoclass:: lief.MachO.VersionMin

----------


Relocation
**********

.. autoclass:: lief.MachO.Relocation

----------


Relocation Object
*****************

.. autoclass:: lief.MachO.RelocationObject

----------


Relocation Dyld
***************

.. autoclass:: lief.MachO.RelocationDyld

----------

Relocation Fixup
****************

.. autoclass:: lief.MachO.RelocationFixup

----------


Binding Info
************

.. autoclass:: lief.MachO.BindingInfo

----------

Dyld Binding Info
*****************

.. autoclass:: lief.MachO.DyldBindingInfo

----------


Chained Binding Info
********************

.. autoclass:: lief.MachO.ChainedBindingInfo

----------


Export Info
***********

.. autoclass:: lief.MachO.ExportInfo

----------


Thread Command
**************

.. autoclass:: lief.MachO.ThreadCommand

----------

RPath Command
*************

.. autoclass:: lief.MachO.RPathCommand

----------


Code Signature
**************

.. autoclass:: lief.MachO.CodeSignature

----------

Data In Code
************

.. autoclass:: lief.MachO.DataInCode

----------

Data Code Entry
***************

.. autoclass:: lief.MachO.DataCodeEntry

----------

Segment Split Info
******************

.. autoclass:: lief.MachO.SegmentSplitInfo

----------

Sub Framework
*************

.. autoclass:: lief.MachO.SubFramework

----------

Dyld Environment
****************

.. autoclass:: lief.MachO.DyldEnvironment

----------

Encryption Info
***************

.. autoclass:: lief.MachO.EncryptionInfo

----------

Build Version
*************

.. autoclass:: lief.MachO.BuildVersion

----------

Build Tool Version
******************

.. autoclass:: lief.MachO.BuildToolVersion

----------

Fileset Command
***************

.. autoclass:: lief.MachO.FilesetCommand

----------

DyldChainedFixups Command
*************************

.. autoclass:: lief.MachO.DyldChainedFixups

----------

DyldExportsTrie Command
***********************

.. autoclass:: lief.MachO.DyldExportsTrie

----------

Code Signature Dir Command
**************************

.. autoclass:: lief.MachO.CodeSignatureDir

----------

Two Level Hints
***************

.. autoclass:: lief.MachO.TwoLevelHints

----------

Linker Optimization Hint
************************

.. autoclass:: lief.MachO.LinkerOptHint

----------

Builder
*******

.. autoclass:: lief.MachO.Builder

----------

Enums
*****


CPU_TYPES
~~~~~~~~~

.. autoclass:: lief.MachO.CPU_TYPES

----------


FILE_TYPES
~~~~~~~~~~

.. autoclass:: lief.MachO.FILE_TYPES

----------


HEADER_FLAGS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.HEADER_FLAGS

----------


LOAD_COMMAND_TYPES
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.LOAD_COMMAND_TYPES

----------


SECTION_TYPES
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SECTION_TYPES

----------


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


----------

RELOCATION_ORIGINS
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.RELOCATION_ORIGINS


----------

REBASE_TYPES
~~~~~~~~~~~~

.. autoclass:: lief.MachO.REBASE_TYPES



----------

BINDING_CLASS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.BINDING_CLASS


----------

REBASE_OPCODES
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.REBASE_OPCODES


----------

BIND_TYPES
~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_TYPES


----------

BIND_SPECIAL_DYLIB
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_SPECIAL_DYLIB


----------

BIND_OPCODES
~~~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_OPCODES


----------

EXPORT_SYMBOL_KINDS
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.EXPORT_SYMBOL_KINDS


----------

EXPORT_SYMBOL_FLAGS
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.EXPORT_SYMBOL_FLAGS


----------

VM_PROTECTIONS
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.VM_PROTECTIONS


----------

SYMBOL_ORIGINS
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SYMBOL_ORIGINS

----------

SECTION_FLAGS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SECTION_FLAGS

DYLD_CHAINED_FORMAT
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_FORMAT

DYLD_CHAINED_PTR_FORMAT
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_PTR_FORMAT

