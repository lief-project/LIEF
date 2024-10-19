.. _debug-info:

:fa:`solid fa-magnifying-glass` Debug Info
------------------------------------------

:ref:`PDB <extended-pdb>` and :ref:`DWARF <extended-dwarf>` shares similar
traits which are abstracted by the following classes:

:fa:`regular fa-file-code` C++
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DebugInfo
*********

.. doxygenclass:: LIEF::DebugInfo

debug_location_t
****************

.. doxygenstruct:: LIEF::debug_location_t

----

:fa:`brands fa-python` Python
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


DebugInfo
*********

.. autoclass:: lief.DebugInfo


debug_location_t
****************

.. autoclass:: lief.debug_location_t

----

:fa:`brands fa-rust` Rust
~~~~~~~~~~~~~~~~~~~~~~~~~

- :rust:trait:`lief::generic::DebugInfo`

- :rust:struct:`lief::DebugLocation`

