:fa:`regular fa-file-code` C++
--------------------------------

.. note::

   You can also find the Doxygen documentation here: `here <../../doxygen/>`_

.. doxygenfunction:: LIEF::dsc::load(const std::string &path, const std::string &arch = "")

.. doxygenfunction:: LIEF::dsc::load(const std::vector<std::string> &files)

Cache Processing
****************

.. warning::

   If you aim at extracting several libraries from a dyld shared cache, it is
   **highly** recommended to enable caching. Otherwise, performances can be
   impacted.

.. doxygenfunction:: LIEF::dsc::enable_cache()

.. doxygenfunction:: LIEF::dsc::enable_cache(const std::string &dir)


DyldSharedCache
***************

.. doxygenclass:: LIEF::dsc::DyldSharedCache


Dylib
*****

.. doxygenclass:: LIEF::dsc::Dylib


MappingInfo
***********

.. doxygenclass:: LIEF::dsc::MappingInfo


SubCache
********

.. doxygenclass:: LIEF::dsc::SubCache
