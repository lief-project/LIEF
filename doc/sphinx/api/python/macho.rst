MachO
-----


Parser
*******

.. autofunction:: lief.MachO.parse

.. autoclass:: lief.MachO.ParserConfig
  :members:
  :inherited-members:
  :undoc-members:

.. code-block:: python

  fatbinary_1 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.deep)
  # or
  fatbinary_2 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.quick)


----------


FatBinary
*********

.. autoclass:: lief.MachO.FatBinary
  :members:
  :inherited-members:
  :undoc-members:

----------


.. _python-macho-binary-api-ref:

Binary
******

.. autoclass:: lief.MachO.Binary
  :members:
  :inherited-members:
  :undoc-members:

----------

Header
******

.. autoclass:: lief.MachO.Header
  :members:
  :inherited-members:
  :undoc-members:

----------


Section
*******

.. autoclass:: lief.MachO.Section
  :members:
  :inherited-members:
  :undoc-members:

----------


SegmentCommand
**************

.. autoclass:: lief.MachO.SegmentCommand
  :members:
  :inherited-members:
  :undoc-members:

----------


LoadCommand
***********

.. autoclass:: lief.MachO.LoadCommand
  :members:
  :inherited-members:
  :undoc-members:

----------


DylibCommand
************

.. autoclass:: lief.MachO.DylibCommand
  :members:
  :inherited-members:
  :undoc-members:


----------

DylinkerCommand
***************

.. autoclass:: lief.MachO.DylinkerCommand
  :members:
  :inherited-members:
  :undoc-members:


----------

UUIDCommand
***********

.. autoclass:: lief.MachO.UUIDCommand
  :members:
  :inherited-members:
  :undoc-members:


----------


MainCommand
***********

.. autoclass:: lief.MachO.MainCommand
  :members:
  :inherited-members:
  :undoc-members:

----------


Symbol
******

.. autoclass:: lief.MachO.Symbol
  :members:
  :inherited-members:
  :undoc-members:

----------


Symbol Command
**************

.. autoclass:: lief.MachO.SymbolCommand
  :members:
  :inherited-members:
  :undoc-members:

----------

Dynamic Symbol Command
**********************

.. autoclass:: lief.MachO.DynamicSymbolCommand
  :members:
  :inherited-members:
  :undoc-members:

----------

Dyld Info
*********

.. autoclass:: lief.MachO.DyldInfo
  :members:
  :inherited-members:
  :undoc-members:

----------

Function starts
***************

.. autoclass:: lief.MachO.FunctionStarts
  :members:
  :inherited-members:
  :undoc-members:

----------

Source Version
**************

.. autoclass:: lief.MachO.SourceVersion
  :members:
  :inherited-members:
  :undoc-members:

----------


Version Min
***********

.. autoclass:: lief.MachO.VersionMin
  :members:
  :inherited-members:
  :undoc-members:

----------


Relocation
**********

.. autoclass:: lief.MachO.Relocation
  :members:
  :inherited-members:
  :undoc-members:

----------


Relocation Object
*****************

.. autoclass:: lief.MachO.RelocationObject
  :members:
  :inherited-members:
  :undoc-members:

----------


Relocation Dyld
***************

.. autoclass:: lief.MachO.RelocationDyld
  :members:
  :inherited-members:
  :undoc-members:

----------

Relocation Fixup
****************

.. autoclass:: lief.MachO.RelocationFixup
  :members:
  :inherited-members:
  :undoc-members:

----------


Binding Info
************

.. autoclass:: lief.MachO.BindingInfo
  :members:
  :inherited-members:
  :undoc-members:

----------

Dyld Binding Info
*****************

.. autoclass:: lief.MachO.DyldBindingInfo
  :members:
  :inherited-members:
  :undoc-members:

----------


Chained Binding Info
********************

.. autoclass:: lief.MachO.ChainedBindingInfo
  :members:
  :inherited-members:
  :undoc-members:

----------


Export Info
***********

.. autoclass:: lief.MachO.ExportInfo
  :members:
  :inherited-members:
  :undoc-members:

----------


Thread Command
**************

.. autoclass:: lief.MachO.ThreadCommand
  :members:
  :inherited-members:
  :undoc-members:

----------

RPath Command
*************

.. autoclass:: lief.MachO.RPathCommand
   :members:
   :inherited-members:
   :undoc-members:

----------


Code Signature
**************

.. autoclass:: lief.MachO.CodeSignature
   :members:
   :inherited-members:
   :undoc-members:

----------

Data In Code
************

.. autoclass:: lief.MachO.DataInCode
   :members:
   :inherited-members:
   :undoc-members:

----------

Data Code Entry
***************

.. autoclass:: lief.MachO.DataCodeEntry
   :members:
   :inherited-members:
   :undoc-members:

----------

Segment Split Info
******************

.. autoclass:: lief.MachO.SegmentSplitInfo
   :members:
   :inherited-members:
   :undoc-members:

----------

Sub Framework
*************

.. autoclass:: lief.MachO.SubFramework
   :members:
   :inherited-members:
   :undoc-members:

----------

Dyld Environment
****************

.. autoclass:: lief.MachO.DyldEnvironment
   :members:
   :inherited-members:
   :undoc-members:

----------

Encryption Info
***************

.. autoclass:: lief.MachO.EncryptionInfo
   :members:
   :inherited-members:
   :undoc-members:

----------

Build Version
*************

.. autoclass:: lief.MachO.BuildVersion
   :members:
   :inherited-members:
   :undoc-members:

----------

Build Tool Version
******************

.. autoclass:: lief.MachO.BuildToolVersion
   :members:
   :inherited-members:
   :undoc-members:

----------

Fileset Command
***************

.. autoclass:: lief.MachO.FilesetCommand
   :members:
   :inherited-members:
   :undoc-members:

----------

DyldChainedFixups Command
*************************

.. autoclass:: lief.MachO.DyldChainedFixups
   :members:
   :inherited-members:
   :undoc-members:

----------

DyldExportsTrie Command
***********************

.. autoclass:: lief.MachO.DyldExportsTrie
   :members:
   :inherited-members:
   :undoc-members:

----------

Code Signature Dir Command
**************************

.. autoclass:: lief.MachO.CodeSignatureDir
   :members:
   :inherited-members:
   :undoc-members:

----------

Two Level Hints
***************

.. autoclass:: lief.MachO.TwoLevelHints
   :members:
   :inherited-members:
   :undoc-members:

----------

Linker Optimization Hint
************************

.. autoclass:: lief.MachO.LinkerOptHint
   :members:
   :inherited-members:
   :undoc-members:

----------

Builder
*******

.. autoclass:: lief.MachO.Builder
   :members:
   :inherited-members:
   :undoc-members:

----------

Enums
*****


CPU_TYPES
~~~~~~~~~

.. autoclass:: lief.MachO.CPU_TYPES
  :members:
  :inherited-members:
  :undoc-members:

----------


FILE_TYPES
~~~~~~~~~~

.. autoclass:: lief.MachO.FILE_TYPES
  :members:
  :inherited-members:
  :undoc-members:

----------


HEADER_FLAGS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.HEADER_FLAGS
  :members:
  :inherited-members:
  :undoc-members:

----------


LOAD_COMMAND_TYPES
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.LOAD_COMMAND_TYPES
  :members:
  :inherited-members:
  :undoc-members:

----------


SECTION_TYPES
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SECTION_TYPES
  :members:
  :inherited-members:
  :undoc-members:

----------


MACHO_TYPES
~~~~~~~~~~~

.. autoclass:: lief.MachO.MACHO_TYPES
  :members:
  :inherited-members:
  :undoc-members:

----------


X86_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.X86_RELOCATION
  :members:
  :inherited-members:
  :undoc-members:

----------


X86_64_RELOCATION
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.X86_64_RELOCATION
  :members:
  :inherited-members:
  :undoc-members:

----------


PPC_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.PPC_RELOCATION
  :members:
  :inherited-members:
  :undoc-members:

----------


ARM_RELOCATION
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.ARM_RELOCATION
  :members:
  :inherited-members:
  :undoc-members:

----------

ARM64_RELOCATION
~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.ARM64_RELOCATION
  :members:
  :inherited-members:
  :undoc-members:


----------

RELOCATION_ORIGINS
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.RELOCATION_ORIGINS
  :members:
  :inherited-members:
  :undoc-members:


----------

REBASE_TYPES
~~~~~~~~~~~~

.. autoclass:: lief.MachO.REBASE_TYPES
  :members:
  :inherited-members:
  :undoc-members:



----------

BINDING_CLASS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.BINDING_CLASS
  :members:
  :inherited-members:
  :undoc-members:


----------

REBASE_OPCODES
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.REBASE_OPCODES
  :members:
  :inherited-members:
  :undoc-members:


----------

BIND_TYPES
~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_TYPES
  :members:
  :inherited-members:
  :undoc-members:


----------

BIND_SPECIAL_DYLIB
~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_SPECIAL_DYLIB
  :members:
  :inherited-members:
  :undoc-members:


----------

BIND_OPCODES
~~~~~~~~~~~~

.. autoclass:: lief.MachO.BIND_OPCODES
  :members:
  :inherited-members:
  :undoc-members:


----------

EXPORT_SYMBOL_KINDS
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.EXPORT_SYMBOL_KINDS
  :members:
  :inherited-members:
  :undoc-members:


----------

EXPORT_SYMBOL_FLAGS
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.EXPORT_SYMBOL_FLAGS
  :members:
  :inherited-members:
  :undoc-members:


----------

VM_PROTECTIONS
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.VM_PROTECTIONS
  :members:
  :inherited-members:
  :undoc-members:


----------

SYMBOL_ORIGINS
~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SYMBOL_ORIGINS
  :members:
  :inherited-members:
  :undoc-members:

----------

SECTION_FLAGS
~~~~~~~~~~~~~

.. autoclass:: lief.MachO.SECTION_FLAGS
  :members:
  :inherited-members:
  :undoc-members:

DYLD_CHAINED_FORMAT
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_FORMAT
  :members:
  :inherited-members:
  :undoc-members:

DYLD_CHAINED_PTR_FORMAT
~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.MachO.DYLD_CHAINED_PTR_FORMAT
  :members:
  :inherited-members:
  :undoc-members:
