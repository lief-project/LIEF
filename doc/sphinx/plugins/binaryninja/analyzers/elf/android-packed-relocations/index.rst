.. _plugins-binaryninja-analyzers-android-packed-relocations:

:fa:`solid fa-object-ungroup` Android Packed Relocations
--------------------------------------------------------

This analyzer enhances the type definition of Android-specific relocation data
(``DT_ANDROID_RELA``)

.. img-comparison::
  :left: img/packed_before.svg
  :right: img/packed_after.svg

.. admonition:: Relocation
  :class: note

  Please note that the **processing** of these relocations is part of the
  :ref:`Relocations <plugins-binaryninja-analyzers-relocations>` analyzer.

.. include:: ../../../../../_cross_api.rst
