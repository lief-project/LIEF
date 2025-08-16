.. _plugins-binaryninja-analyzers-relocations:

:fa:`solid fa-object-ungroup` Relocations
-----------------------------------------

This analyzer enhances support for binaries that use recent relocation formats
not recognized by BinaryNinja (e.g. ``DT_ANDROID_RELA, DT_RELR``).


For instance, here is a LIEF-based processing of ``DT_ANDROID_RELA``
relocations:

.. img-comparison::
  :left: img/array_before.svg
  :right: img/array_after.svg


Here is one for ``DT_RELR`` relocations:

.. img-comparison::
  :left: img/data_relro_before.svg
  :right: img/data_relro_after.svg

.. toctree::
  :caption: <i class="fa-solid fa-puzzle-piece">&nbsp;</i>See also
  :maxdepth: 1

  ../android-packed-relocations/index
  ../relative-relocations/index

.. include:: ../../../../../_cross_api.rst
