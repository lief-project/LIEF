.. _plugins-binaryninja-analyzers-exceptions:

:fa:`solid fa-object-ungroup` BinaryNinja - Analyzers - Exceptions
------------------------------------------------------------------

This analyzer improves the representation and underlying data of PE exceptions
metadata, primarily for ARM64 and ARM64EC binaries.

.. img-comparison::
  :left: img/pdata_before.svg
  :right: img/pdata_after.svg

.. raw:: html

  <br />

.. img-comparison::
  :left: img/rdata_before.svg
  :right: img/rdata_after.svg

Additionally, it defines functions automatically based on the metadata of exceptions.
This results in a more accurate representation of the binary, as illustrated in this feature map:

.. img-comparison::
  :left: img/featmap_before.svg
  :right: img/featmap_after.svg
