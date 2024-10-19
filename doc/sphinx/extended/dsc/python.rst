:fa:`brands fa-python` Python
------------------------------

.. autofunction:: lief.dsc.load

Cache Processing
****************

.. warning::

   If you aim at extracting several libraries from a dyld shared cache, it is
   **highly** recommended to enable caching. Otherwise, performances can be
   impacted.

.. autofunction:: lief.dsc.enable_cache

DyldSharedCache
***************

.. autoclass:: lief.dsc.DyldSharedCache


Dylib
*****

.. autoclass:: lief.dsc.Dylib

MappingInfo
***********

.. autoclass:: lief.dsc.MappingInfo

SubCache
********

.. autoclass:: lief.dsc.SubCache

