.. _plugins-ghidra-analyzers-loadconfig:

:fa:`solid fa-object-ungroup` Ghidra - Analyzers - ``IMAGE_LOAD_CONFIG_DIRECTORY``
----------------------------------------------------------------------------------

This analyzer enhances the representation and underlying data of the PE
LoadConfiguration structure within Ghidra.

.. img-comparison::
  :left: img/loadconfig_before.svg
  :right: img/loadconfig_after.svg
  :width: 100%

The layout of this structure -- exposed in LIEF through the
|lief-pe-loadconfig| interface -- evolves frequently across new Windows releases.
As of today, Ghidra does not natively recognize many of the newer attributes
introduced in recent versions. By running this analyzer, you obtain a more
complete and accurate representation of these attributes along with their correct data types.

Beyond the Load Configuration, the analyzer also defines additional structures, such as
|lief-pe-chpe_metadata-arm64|, which provide valuable context for analyzing ARM64EC binaries.
These definitions make it easier to interpret the purpose of certain
functions and pointers, leading to deeper insights during reverse engineering.

.. img-comparison::
  :left: img/chpe_metadata_before.svg
  :right: img/chpe_metadata_after.svg
  :width: 100%


.. admonition:: BinaryNinja
  :class: tip

  BinaryNinja's LIEF plugin also provides this support: :ref:`plugins-binaryninja-analyzers-loadconfig`


.. include:: ../../../../_cross_api.rst
