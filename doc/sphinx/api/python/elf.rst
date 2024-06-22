ELF
---

Parser
*******

.. autofunction:: lief.ELF.parse

.. autoclass:: lief.ELF.ParserConfig

----------

Binary
******

.. autoclass:: lief.ELF.Binary

----------

Header
******

.. autoclass:: lief.ELF.Header

----------

Section
*******

.. lief-inheritance:: lief._lief.ELF.Section
  :top-classes: lief._lief.Section
  :parts: 2

.. autoclass:: lief.ELF.Section

----------

Segment
*******

.. autoclass:: lief.ELF.Segment

----------

Dynamic Entry
*************

.. lief-inheritance:: lief._lief.ELF.DynamicEntry
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntry

----------

Dynamic Entry Library
*********************

.. lief-inheritance:: lief._lief.ELF.DynamicEntryLibrary
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntryLibrary

----------

Dynamic Shared Object
*********************

.. lief-inheritance:: lief._lief.ELF.DynamicSharedObject
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicSharedObject

----------

Dynamic Entry Run Path
**********************

.. lief-inheritance:: lief._lief.ELF.DynamicEntryRunPath
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntryRunPath

----------

Dynamic Entry RPath
*******************

.. lief-inheritance:: lief._lief.ELF.DynamicEntryRpath
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntryRpath

----------

Dynamic Entry Array
*******************

.. lief-inheritance:: lief._lief.ELF.DynamicEntryArray
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntryArray

----------

Dynamic Entry Flags
*******************

.. lief-inheritance:: lief._lief.ELF.DynamicEntryFlags
  :top-classes: lief._lief.ELF.DynamicEntry
  :parts: 2

.. autoclass:: lief.ELF.DynamicEntryFlags


----------

Relocations
***********

.. autoclass:: lief.ELF.Relocation

----------

Symbol
******

.. autoclass:: lief.ELF.Symbol

----------

Symbol Version
**************

.. autoclass:: lief.ELF.SymbolVersion

----------

Symbol Version Auxiliary
************************

.. lief-inheritance:: lief._lief.ELF.SymbolVersionAux
  :top-classes: lief._lief.SymbolVersionAux
  :parts: 2

.. autoclass:: lief.ELF.SymbolVersionAux

----------

Symbol Version Definition
*************************

.. autoclass:: lief.ELF.SymbolVersionDefinition

----------

Symbol Version Requirement
**************************

.. autoclass:: lief.ELF.SymbolVersionRequirement

----------

Symbol Version Auxiliary Requirement
************************************

.. autoclass:: lief.ELF.SymbolVersionAuxRequirement

----------

GNU Hash table
**************

.. autoclass:: lief.ELF.GnuHash

----------

SYSV Hash table
***************

.. autoclass:: lief.ELF.SysvHash

----------

Note
****

.. lief-inheritance:: lief._lief.ELF.Note
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.Note

----------

Core PrPsInfo
*************

.. lief-inheritance:: lief._lief.ELF.CorePrPsInfo
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.CorePrPsInfo

----------

Core PrStatus
*************

.. lief-inheritance:: lief._lief.ELF.CorePrStatus
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.CorePrStatus

----------

Core File
*********

.. lief-inheritance:: lief._lief.ELF.CoreFile
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.CoreFile

----------

Core Siginfo
************

.. lief-inheritance:: lief._lief.ELF.CoreSigInfo
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.CoreSigInfo

----------

Core Auxiliary Vector
*********************

.. lief-inheritance:: lief._lief.ELF.CoreAuxv
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.CoreAuxv

----------

Android Ident
*************

.. lief-inheritance:: lief._lief.ELF.AndroidIdent
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.AndroidIdent

----------

QNX Stack
*********

.. lief-inheritance:: lief._lief.ELF.QNXStack
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.QNXStack

----------

Note ABI
********

.. lief-inheritance:: lief._lief.ELF.NoteAbi
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. autoclass:: lief.ELF.NoteAbi

----------

Note Gnu Property
*****************

.. lief-inheritance:: lief._lief.ELF.NoteGnuProperty
  :top-classes: lief._lief.ELF.Note
  :parts: 2

.. lief-inheritance:: lief._lief.ELF.NoteGnuProperty.Property
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 3

.. autoclass:: lief.ELF.NoteGnuProperty

----------

Generic
*******

.. lief-inheritance:: lief._lief.ELF.Generic
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.Generic

----------

AArch64 Feature
***************

.. lief-inheritance:: lief._lief.ELF.AArch64Feature
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.AArch64Feature

----------

No Copy on Protected
********************

.. lief-inheritance:: lief._lief.ELF.NoteNoCopyOnProtected
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.NoteNoCopyOnProtected

----------

Stack Size
**********

.. lief-inheritance:: lief._lief.ELF.StackSize
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.StackSize

----------

X86 Feature
***********

.. lief-inheritance:: lief._lief.ELF.X86Features
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.X86Features

----------

X86 ISA
*******

.. lief-inheritance:: lief._lief.ELF.X86ISA
  :top-classes: lief._lief.ELF.NoteGnuProperty.Property
  :parts: 2

.. autoclass:: lief.ELF.X86ISA

----------

Builder
*******

.. autoclass:: lief.ELF.Builder

Enums
*****

Architectures
~~~~~~~~~~~~~

.. autoclass:: lief.ELF.ARCH


Processor Flags
~~~~~~~~~~~~~~~

.. autoclass:: lief.ELF.PROCESSOR_FLAGS
