ELF
---

Parser
*******

.. doxygenclass:: LIEF::ELF::Parser
   :project: lief



----------


Binary
******

.. doxygenclass:: LIEF::ELF::Binary
   :project: lief

----------

Header
******

.. doxygenclass:: LIEF::ELF::Header
   :project: lief

----------

Section
*******

.. doxygenclass:: LIEF::ELF::Section
   :project: lief

----------

Segment
*******

.. doxygenclass:: LIEF::ELF::Segment
  :project: lief

----------

Dynamic Entry
*************

.. doxygenclass:: LIEF::ELF::DynamicEntry
   :project: lief

----------

Dynamic Entry Library
*********************

.. doxygenclass:: LIEF::ELF::DynamicEntryLibrary
   :project: lief

----------

Dynamic Shared Object
*********************

.. doxygenclass:: LIEF::ELF::DynamicSharedObject
   :project: lief

----------

Dynamic Entry Run Path
**********************

.. doxygenclass:: LIEF::ELF::DynamicEntryRunPath
   :project: lief

----------

Dynamic Entry RPath
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryRpath
   :project: lief

----------

Dynamic Entry Array
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryArray
   :project: lief

----------

Dynamic Entry Flags
*******************

.. doxygenclass:: LIEF::ELF::DynamicEntryFlags
   :project: lief

----------

Relocations
***********

.. doxygenclass:: LIEF::ELF::Relocation
   :project: lief

----------

Symbol
******

.. doxygenclass:: LIEF::ELF::Symbol
   :project: lief

----------

Symbol Version
**************

.. doxygenclass:: LIEF::ELF::SymbolVersion
   :project: lief

----------

Symbol Version Auxiliary
************************

.. doxygenclass:: LIEF::ELF::SymbolVersionAux
   :project: lief

----------

Symbol Version Definition
*************************

.. doxygenclass:: LIEF::ELF::SymbolVersionDefinition
   :project: lief

----------

Symbol Version Requirement
**************************

.. doxygenclass:: LIEF::ELF::SymbolVersionRequirement
   :project: lief

----------

Symbol Version Auxiliary Requirement
************************************

.. doxygenclass:: LIEF::ELF::SymbolVersionAuxRequirement
   :project: lief

----------

GNU Hash table
**************

.. doxygenclass:: LIEF::ELF::GnuHash
   :project: lief

----------

SYSV Hash table
***************

.. doxygenclass:: LIEF::ELF::SysvHash
   :project: lief

----------

Note
****

.. doxygenclass:: LIEF::ELF::Note
   :project: lief

----------


Note Details
************

.. doxygenclass:: LIEF::ELF::NoteDetails
   :project: lief

----------

Core PrPsInfo
*************

.. doxygenclass:: LIEF::ELF::CorePrPsInfo
   :project: lief

----------


Core File
*********

.. doxygenclass:: LIEF::ELF::CoreFile
   :project: lief

----------


Core File Entry
***************

.. doxygenstruct:: LIEF::ELF::CoreFileEntry
   :project: lief

----------

Core PrStatus
*************

.. doxygenclass:: LIEF::ELF::CorePrStatus
   :project: lief

----------


Core Siginfo
*************

.. doxygenclass:: LIEF::ELF::CoreSigInfo
   :project: lief

----------

Core Auxiliary Vector
*********************

.. doxygenclass:: LIEF::ELF::CoreAuxv
   :project: lief

----------

Android Note
************

.. doxygenclass:: LIEF::ELF::AndroidNote
   :project: lief

----------

Note ABI
********

.. doxygenclass:: LIEF::ELF::NoteAbi
   :project: lief

----------

Builder
*******

.. doxygenclass:: LIEF::ELF::Builder
   :project: lief

----------


Utilities
*********

.. doxygenfunction:: LIEF::ELF::is_elf(const std::string&)
  :project: lief

.. doxygenfunction:: LIEF::ELF::is_elf(const std::vector<uint8_t>&)
  :project: lief

----------



Enums
*****

Architectures
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ARCH
   :project: lief

----------

Identity
~~~~~~~~

.. doxygenenum:: LIEF::ELF::IDENTITY
   :project: lief

----------

Binary types
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::E_TYPE
   :project: lief

----------

Version
~~~~~~~

.. doxygenenum:: LIEF::ELF::VERSION
   :project: lief

----------

ELF Class
~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_CLASS
   :project: lief

----------

ELF Data
~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_DATA
   :project: lief

----------

ELF OS/ABI
~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::OS_ABI
   :project: lief

----------

Symbol section index
~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SYMBOL_SECTION_INDEX
   :project: lief

----------

Section types
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SECTION_TYPES
   :project: lief

----------

Section flags
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SECTION_FLAGS
   :project: lief

----------

Symbol bindings
~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SYMBOL_BINDINGS
   :project: lief

----------

Symbol visibility
~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SYMBOL_VISIBILITY
   :project: lief

----------

Symbol types
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SYMBOL_TYPES
   :project: lief

----------


Segment types
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::SEGMENT_TYPES
   :project: lief

----------

Segment flags
~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::ELF_SEGMENT_FLAGS
   :project: lief

----------

Dynamic tags
~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::DYNAMIC_TAGS
   :project: lief

----------

Dynamic flags
~~~~~~~~~~~~~
.. doxygenenum:: LIEF::ELF::DYNAMIC_FLAGS
   :project: lief

----------

Dynamic flags 1
~~~~~~~~~~~~~~~
.. doxygenenum:: LIEF::ELF::DYNAMIC_FLAGS_1
   :project: lief

----------

Dynamic symbols counting
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::DYNSYM_COUNT_METHODS
   :project: lief

----------


Note types
~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::NOTE_TYPES
   :project: lief

----------

Note Core types
~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::NOTE_TYPES_CORE
   :project: lief

----------


Note ABIs
~~~~~~~~~

.. doxygenenum:: LIEF::ELF::NOTE_ABIS
   :project: lief


----------


Relocation purpose
~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOCATION_PURPOSES
   :project: lief

----------

Relocations x86-64
~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_x86_64
   :project: lief

----------


Relocations x86 (i386)
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_i386
   :project: lief

----------

Relocations ARM
~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_ARM
   :project: lief

----------

Relocations AARCH64
~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_AARCH64
   :project: lief


Relocations MIPS
~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_MIPS
   :project: lief


Relocations PPC
~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_POWERPC32
   :project: lief


Relocations PPC64
~~~~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::ELF::RELOC_POWERPC64
   :project: lief
