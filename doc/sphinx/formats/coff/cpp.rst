:fa:`regular fa-file-code` C++
--------------------------------

Parser
******

.. doxygenclass:: LIEF::COFF::Parser

.. doxygenclass:: LIEF::COFF::ParserConfig

----------


Binary
******

.. doxygenclass:: LIEF::COFF::Binary

----------

Header
******

.. doxygenclass:: LIEF::COFF::Header

----------

Regular Header
**************

.. doxygenclass:: LIEF::COFF::RegularHeader

----------

BigOject Header
***************

.. doxygenclass:: LIEF::COFF::BigObjHeader

----------

Section
*******

.. doxygenclass:: LIEF::COFF::Section

----------

Relocation
**********

.. doxygenclass:: LIEF::COFF::Relocation

----------

String
******

.. doxygenclass:: LIEF::COFF::String

----------


Symbol
*******

.. doxygenclass:: LIEF::COFF::Symbol

----------

AuxiliarySymbol
***************

.. doxygenclass:: LIEF::COFF::AuxiliarySymbol

----------

AuxiliaryCLRToken
*****************

.. doxygenclass:: LIEF::COFF::AuxiliaryCLRToken

----------

AuxiliaryFunctionDefinition
***************************

.. doxygenclass:: LIEF::COFF::AuxiliaryFunctionDefinition

----------

AuxiliaryWeakExternal
*********************

.. doxygenclass:: LIEF::COFF::AuxiliaryWeakExternal

----------

AuxiliarybfAndefSymbol
**********************

.. doxygenclass:: LIEF::COFF::AuxiliarybfAndefSymbol

----------

AuxiliarySectionDefinition
**************************

.. doxygenclass:: LIEF::COFF::AuxiliarySectionDefinition

----------

AuxiliaryFile
*************

.. doxygenclass:: LIEF::COFF::AuxiliaryFile

----------

Utilities
*********

.. doxygenfunction:: LIEF::COFF::get_kind(BinaryStream &)

.. doxygenfunction:: LIEF::COFF::is_coff(BinaryStream &)

.. doxygenfunction:: LIEF::COFF::is_coff(const std::string &)

.. doxygenfunction:: LIEF::COFF::is_coff(const std::vector< uint8_t > &)

.. doxygenfunction:: LIEF::COFF::is_coff(const uint8_t *, size_t)

.. doxygenfunction:: LIEF::COFF::is_bigobj(BinaryStream &)

.. doxygenfunction:: LIEF::COFF::is_regular(BinaryStream &)
