MachO
-----

Parsers
*******

.. doxygenclass:: LIEF::MachO::Parser
   :project: lief


.. doxygenclass:: LIEF::MachO::BinaryParser
   :project: lief


.. doxygenclass:: LIEF::MachO::ParserConfig
   :project: lief

----------

FatBinary
*********

.. doxygenclass:: LIEF::MachO::FatBinary
   :project: lief

----------

Binary
******

.. doxygenclass:: LIEF::MachO::Binary
   :project: lief

----------

Header
******

.. doxygenclass:: LIEF::MachO::Header
   :project: lief


----------

Builder
*******

.. doxygenclass:: LIEF::MachO::Builder
   :project: lief

----------

DylibCommand
************

.. doxygenclass:: LIEF::MachO::DylibCommand
   :project: lief


----------

DylinkerCommand
****************

.. doxygenclass:: LIEF::MachO::DylinkerCommand
   :project: lief


----------


DynamicSymbolCommand
********************

.. doxygenclass:: LIEF::MachO::DynamicSymbolCommand
   :project: lief


----------

LoadCommand
***********

.. doxygenclass:: LIEF::MachO::LoadCommand
   :project: lief


----------

MainCommand
***********

.. doxygenclass:: LIEF::MachO::MainCommand
   :project: lief


----------

Section
*******

.. doxygenclass:: LIEF::MachO::Section
   :project: lief


----------

Symbol
******

.. doxygenclass:: LIEF::MachO::Symbol
   :project: lief


----------

SymbolCommand
*************

.. doxygenclass:: LIEF::MachO::SymbolCommand
   :project: lief


----------

UUIDCommand
***********

.. doxygenclass:: LIEF::MachO::UUIDCommand
   :project: lief

----------

Dyld Info
*********

.. doxygenclass:: LIEF::MachO::DyldInfo
   :project: lief


Function starts
***************

.. doxygenclass:: LIEF::MachO::FunctionStarts
   :project: lief


----------

Source Version
**************

.. doxygenclass:: LIEF::MachO::SourceVersion
   :project: lief

----------


Version Min
***********

.. doxygenclass:: LIEF::MachO::VersionMin
   :project: lief

----------

Relocation
**********

.. doxygenclass:: LIEF::MachO::Relocation
   :project: lief

----------


Relocation Object
*****************

.. doxygenclass:: LIEF::MachO::RelocationObject
   :project: lief

----------


Relocation Dyld
***************

.. doxygenclass:: LIEF::MachO::RelocationDyld
   :project: lief

----------


Binding Info
************

.. doxygenclass:: LIEF::MachO::BindingInfo
   :project: lief

----------


Export Info
***********

.. doxygenclass:: LIEF::MachO::ExportInfo
   :project: lief

----------


Thread Command
**************

.. doxygenclass:: LIEF::MachO::ThreadCommand
   :project: lief

----------

RPath Command
*************

.. doxygenclass:: LIEF::MachO::RPathCommand
   :project: lief

----------


Code Signature
**************

.. doxygenclass:: LIEF::MachO::CodeSignature
   :project: lief

----------

Data In Code
************

.. doxygenclass:: LIEF::MachO::DataInCode
   :project: lief

----------

Data Code Entry
****************

.. doxygenclass:: LIEF::MachO::DataCodeEntry
   :project: lief

.. doxygenenum:: LIEF::MachO::DataCodeEntry::TYPES
   :project: lief

----------

Segment Split Info
******************

.. doxygenclass:: LIEF::MachO::SegmentSplitInfo
   :project: lief

----------

Sub-Framework
*************

.. doxygenclass:: LIEF::MachO::SubFramework
   :project: lief

----------

Dyld Environment
****************

.. doxygenclass:: LIEF::MachO::DyldEnvironment
   :project: lief

----------

Utilities
*********

.. doxygenfunction:: LIEF::MachO::is_macho(const std::string &)
  :project: lief

.. doxygenfunction:: LIEF::MachO::is_macho(const std::vector< uint8_t > &)
  :project: lief

.. doxygenfunction:: LIEF::MachO::is_fat(const std::string &)
  :project: lief

.. doxygenfunction:: LIEF::MachO::is_64(const std::string &)
  :project: lief

.. doxygenfunction:: LIEF::MachO::decode_uleb128(const std::string &)
  :project: lief

----------


Enums
*****

.. doxygenenum:: LIEF::MachO::MACHO_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::FILE_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::HEADER_FLAGS
   :project: lief

.. doxygenenum:: LIEF::MachO::LOAD_COMMAND_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::MACHO_SEGMENTS_FLAGS
   :project: lief

.. doxygenenum:: LIEF::MachO::SECTION_FLAGS_HELPER
   :project: lief

.. doxygenenum:: LIEF::MachO::MACHO_SECTION_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::MACHO_SECTION_FLAGS
   :project: lief

.. doxygenenum:: LIEF::MachO::MACHO_SYMBOL_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::SYMBOL_DESCRIPTIONS
   :project: lief

.. doxygenenum:: LIEF::MachO::X86_RELOCATION
   :project: lief

.. doxygenenum:: LIEF::MachO::X86_64_RELOCATION
   :project: lief

.. doxygenenum:: LIEF::MachO::PPC_RELOCATION
   :project: lief

.. doxygenenum:: LIEF::MachO::ARM_RELOCATION
   :project: lief

.. doxygenenum:: LIEF::MachO::ARM64_RELOCATION
   :project: lief

.. doxygenenum:: LIEF::MachO::CPU_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::CPU_SUBTYPES_X86
   :project: lief

.. doxygenenum:: LIEF::MachO::RELOCATION_ORIGINS
   :project: lief

.. doxygenenum:: LIEF::MachO::REBASE_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::BINDING_CLASS
   :project: lief

.. doxygenenum:: LIEF::MachO::REBASE_OPCODES
   :project: lief

.. doxygenenum:: LIEF::MachO::BIND_TYPES
   :project: lief

.. doxygenenum:: LIEF::MachO::BIND_SPECIAL_DYLIB
   :project: lief

.. doxygenenum:: LIEF::MachO::BIND_OPCODES
   :project: lief

.. doxygenenum:: LIEF::MachO::EXPORT_SYMBOL_KINDS
   :project: lief

.. doxygenenum:: LIEF::MachO::VM_PROTECTIONS
   :project: lief

.. doxygenenum:: LIEF::MachO::SYMBOL_ORIGINS
   :project: lief

