ELF
---

Parser
*******

.. doxygenclass:: LIEF::ELF::Parser

.. doxygenstruct:: LIEF::ELF::ParserConfig

----------


Binary
******

.. doxygenclass:: LIEF::ELF::Binary

----------

Header
******

.. doxygenclass:: LIEF::ELF::Header

----------

Section
*******

.. doxygenclass:: LIEF::ELF::Section

----------

Segment
*******

.. doxygenclass:: LIEF::ELF::Segment

----------

Dynamic Entry
*************

.. doxygenclass:: LIEF::ELF::DynamicEntry

----------

Dynamic Entry Library
*********************

.. doxygenclass:: LIEF::ELF::DynamicEntryLibrary

----------

Dynamic Shared Object
*********************

.. doxygenclass:: LIEF::ELF::DynamicSharedObject

----------

Dynamic Entry Run Path
**********************

.. doxygenclass:: LIEF::ELF::DynamicEntryRunPath

----------

Dynamic Entry RPath
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryRpath

----------

Dynamic Entry Array
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryArray

----------

Dynamic Entry Flags
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryFlags

----------

Relocations
***********

.. doxygenclass:: LIEF::ELF::Relocation

----------

Symbol
******

.. doxygenclass:: LIEF::ELF::Symbol

----------

Symbol Version
**************

.. doxygenclass:: LIEF::ELF::SymbolVersion

----------

Symbol Version Auxiliary
************************

.. doxygenclass:: LIEF::ELF::SymbolVersionAux

----------

Symbol Version Definition
*************************

.. doxygenclass:: LIEF::ELF::SymbolVersionDefinition

----------

Symbol Version Requirement
**************************

.. doxygenclass:: LIEF::ELF::SymbolVersionRequirement

----------

Symbol Version Auxiliary Requirement
************************************

.. doxygenclass:: LIEF::ELF::SymbolVersionAuxRequirement

----------

GNU Hash table
**************

.. doxygenclass:: LIEF::ELF::GnuHash

----------

SYSV Hash table
***************

.. doxygenclass:: LIEF::ELF::SysvHash

----------

Note
****

.. doxygenclass:: LIEF::ELF::Note

----------


Core PrPsInfo
*************

.. doxygenclass:: LIEF::ELF::CorePrPsInfo

----------


Core File
*********

.. doxygenclass:: LIEF::ELF::CoreFile

----------

Core PrStatus
*************

.. doxygenclass:: LIEF::ELF::CorePrStatus

----------


Core Siginfo
*************

.. doxygenclass:: LIEF::ELF::CoreSigInfo

----------

Core Auxiliary Vector
*********************

.. doxygenclass:: LIEF::ELF::CoreAuxv

----------

Android Identity
****************

.. doxygenclass:: LIEF::ELF::AndroidIdent

----------

Note ABI
********

.. doxygenclass:: LIEF::ELF::NoteAbi

----------

Note Gnu Property
*****************

.. doxygenclass:: LIEF::ELF::NoteGnuProperty

----------

Generic
*******

.. doxygenclass:: LIEF::ELF::Generic

----------

AArch64 Feature
***************

.. doxygenclass:: LIEF::ELF::AArch64Feature

----------

No Copy on Protected
********************

.. doxygenclass:: LIEF::ELF::NoteNoCopyOnProtected

----------

Stack Size
**********

.. doxygenclass:: LIEF::ELF::StackSize

----------

X86 Feature
***********

.. doxygenclass:: LIEF::ELF::X86Features

----------

X86 ISA
*******

.. doxygenclass:: LIEF::ELF::X86ISA

----------

Builder
*******

.. doxygenclass:: LIEF::ELF::Builder

----------


Utilities
*********

.. doxygenfunction:: LIEF::ELF::is_elf(const std::string&)

.. doxygenfunction:: LIEF::ELF::is_elf(const std::vector<uint8_t>&)

----------



Enums
*****

Architectures
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ARCH

----------

Identity
~~~~~~~~

.. doxygenenum:: LIEF::ELF::IDENTITY

----------

Binary types
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::E_TYPE

----------

Version
~~~~~~~

.. doxygenenum:: LIEF::ELF::VERSION

----------

ELF Class
~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_CLASS

----------

ELF Data
~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_DATA

----------

ELF OS/ABI
~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::OS_ABI

----------

Symbol section index
~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SYMBOL_SECTION_INDEX

----------

Section types
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SECTION_TYPES

----------

Section flags
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SECTION_FLAGS

----------

Symbol bindings
~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SYMBOL_BINDINGS

----------

Symbol visibility
~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SYMBOL_VISIBILITY

----------

Symbol types
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SYMBOL_TYPES

----------


Segment types
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SEGMENT_TYPES

----------

Segment flags
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SEGMENT_FLAGS

----------

Dynamic tags
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::DYNAMIC_TAGS

----------

Dynamic flags
~~~~~~~~~~~~~
.. doxygenenum:: LIEF::ELF::DYNAMIC_FLAGS

----------

Dynamic flags 1
~~~~~~~~~~~~~~~
.. doxygenenum:: LIEF::ELF::DYNAMIC_FLAGS_1

----------

Dynamic symbols counting
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::DYNSYM_COUNT_METHODS

----------


Relocation purpose
~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOCATION_PURPOSES

----------

Relocations x86-64
~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_x86_64

----------


Relocations x86 (i386)
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_i386

----------

Relocations ARM
~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_ARM

----------

Relocations AARCH64
~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_AARCH64


Relocations MIPS
~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_MIPS


Relocations PPC
~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_POWERPC32


Relocations PPC64
~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_POWERPC64

