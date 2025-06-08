:fa:`brands fa-python` Python
------------------------------

Parser
*******

.. autofunction:: lief.COFF.parse

.. autoclass:: lief.COFF.ParserConfig

Binary
******

.. autoclass:: lief.COFF.Binary

----------

Header
*******

.. lief-inheritance:: lief._lief.COFF.Header
  :top-classes: lief._lief.COFF.Header
  :parts: 2

.. autoclass:: lief.COFF.Header

----------

RegularHeader
*************

.. lief-inheritance:: lief._lief.COFF.RegularHeader
  :top-classes: lief._lief.COFF.Header
  :parts: 2

.. autoclass:: lief.COFF.RegularHeader

----------

BigObjHeader
************

.. lief-inheritance:: lief._lief.COFF.BigObjHeader
  :top-classes: lief._lief.COFF.Header
  :parts: 2

.. autoclass:: lief.COFF.BigObjHeader

----------

Section
*******

.. autoclass:: lief.COFF.Section

----------

Relocation
**********

.. autoclass:: lief.COFF.Relocation

----------

String
******

.. autoclass:: lief.COFF.String

----------

Symbol
*******

.. lief-inheritance:: lief._lief.COFF.Symbol
  :top-classes: lief._lief.Symbol
  :parts: 2

.. autoclass:: lief.COFF.Symbol

----------

AuxiliarySymbol
***************

.. lief-inheritance:: lief._lief.COFF.AuxiliarySymbol
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliarySymbol

----------

AuxiliaryCLRToken
*****************

.. lief-inheritance:: lief._lief.COFF.AuxiliaryCLRToken
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliarySymbol

----------

AuxiliaryFunctionDefinition
***************************

.. lief-inheritance:: lief._lief.COFF.AuxiliaryFunctionDefinition
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliaryFunctionDefinition

----------

AuxiliaryWeakExternal
*********************

.. lief-inheritance:: lief._lief.COFF.AuxiliaryWeakExternal
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliaryWeakExternal

----------

AuxiliarybfAndefSymbol
**********************

.. lief-inheritance:: lief._lief.COFF.AuxiliarybfAndefSymbol
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliarybfAndefSymbol

----------

AuxiliarySectionDefinition
**************************

.. lief-inheritance:: lief._lief.COFF.AuxiliarySectionDefinition
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliarySectionDefinition

----------

AuxiliaryFile
*************

.. lief-inheritance:: lief._lief.COFF.AuxiliaryFile
  :top-classes: lief._lief.COFF.AuxiliarySymbol
  :parts: 2

.. autoclass:: lief.COFF.AuxiliaryFile

Utilities
*********

.. autofunction:: lief.is_coff
