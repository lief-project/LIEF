.. _plugins-binaryninja-dwarf:

:fa:`solid fa-user-ninja` BinaryNinja - DWARF Plugin
----------------------------------------------------

Export as DWARF
~~~~~~~~~~~~~~~

.. admonition:: BinaryNinja builtin plugin
  :class: tip

  Binary Ninja already embeds a DWARF export plugin that exposes
  most of the functionalities provided by this plugin. However, this plugin
  exports additional information, such as stack variables and basic blocks.

To export DWARF information from a BinaryNinja's ``BinaryView`` representation,
one can go in the menu: ``Plugins > LIEF > Export as DWARF``

.. raw:: html

  <img style="max-width: 70%;" src="../../../_static/binaryninja/trigger-dwarf-plugin.webp" alt="BinaryNinja DWARF exporter" />
  <br />
  <br />

Support & Limitations
#####################

This extension tries to convert most of the information registered in a
BinaryView into DWARF structures, but this support can't be exhaustive
so here is an overview of what is exported and what is not.

**BinaryNinja::BinaryView**

- :fa-check:`check` Function
- :fa-check:`check` Data Variables
- :fa-check:`check` Types
- :xmark:`mark` Comments

**BinaryNinja::Function**

- :fa-check:`check` Name
- :fa-check:`check` Addresses range
- :fa-check:`check` Parameters
- :fa-check:`check` Type of parameters
- :fa-check:`check` Return type
- :fa-check:`check` Stack variables
- :fa-check:`check` Types of stack variables
- :fa-check:`check` Basic Blocks
- :xmark:`mark` Comments

**BinaryNinja::DataVariable**

- :fa-check:`check` Name
- :fa-check:`check` Type
- :fa-check:`check` Address
- :xmark:`mark` Comments

**BinaryNinja::Type**

- :fa-check:`check` ``BNTypeClass::VoidTypeClass``
- :fa-check:`check` ``BNTypeClass::BoolTypeClass``
- :fa-check:`check` ``BNTypeClass::IntegerTypeClass``
- :fa-check:`check` ``BNTypeClass::FloatTypeClass``
- :fa-check:`check` ``BNTypeClass::PointerTypeClass``
- :fa-check:`check` ``BNTypeClass::PointerTypeClass``
- :fa-check:`check` ``BNTypeClass::StructureTypeClass``

  - :fa-check:`check` ``BNTypeClass::ClassStructureType``
  - :fa-check:`check` ``BNTypeClass::UnionStructureType``
  - :fa-check:`check` ``BNTypeClass::StructStructureType``

- :fa-check:`check` ``BNTypeClass::EnumerationTypeClass``
- :fa-check:`check` ``BNTypeClass::NamedTypeReferenceClass``
- :fa-check:`check` ``BNTypeClass::ArrayTypeClass``
- :fa-check:`check` ``BNTypeClass::WideCharTypeClass``
- :fa-check:`check` ``BNTypeClass::FunctionTypeClass``
- :xmark:`mark` ``BNTypeClass::VarArgsTypeClass``
- :xmark:`mark` ``BNTypeClass::ValueTypeClass``

Any types not mentioned here are not supported.
