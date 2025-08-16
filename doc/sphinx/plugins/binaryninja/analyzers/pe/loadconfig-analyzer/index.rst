.. _plugins-binaryninja-analyzers-loadconfig:

:fa:`solid fa-object-ungroup` LoadConfiguration
------------------------------------------------
This analyzer enhances the representation and underlying data of the PE
LoadConfiguration structure within BinaryNinja.

.. img-comparison::
  :left: img/loadconfig_before.svg
  :right: img/loadconfig_after.svg

The layout of this structure -- exposed in LIEF through the
|lief-pe-loadconfig| interface -- evolves frequently across new Windows releases.
By running this analyzer, you obtain a more complete and accurate representation
of these attributes along with their correct data types.

Beyond the Load Configuration, the analyzer also defines additional structures, such as
|lief-pe-chpe_metadata-arm64|, which provide valuable context for analyzing ARM64EC binaries.
These definitions make it easier to interpret the purpose of certain
functions and pointers, leading to deeper insights during reverse engineering.

.. img-comparison::
  :left: img/chpe_metadata_before.svg
  :right: img/chpe_metadata_after.svg

.. include:: ../../../../../_cross_api.rst
