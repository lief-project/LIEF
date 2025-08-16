.. _plugins-binaryninja-analyzers-relative-relocations:

:fa:`solid fa-object-ungroup` Relative Relocations
--------------------------------------------------

This analyzer enhances the type definition of relative relocation data
(``DT_RELR``)

.. img-comparison::
  :left: img/rel_before.svg
  :right: img/rel_after.svg

.. admonition:: Relocation
  :class: note

  Please note that the **processing** of these relocations is part of the
  :ref:`Relocations <plugins-binaryninja-analyzers-relocations>` analyzer.

.. include:: ../../../../../_cross_api.rst
