.. _cpp-api-ref:

C++
===

.. toctree::
  :maxdepth: 2

  abstract.rst
  elf.rst
  pe.rst
  macho.rst
  oat.rst
  dex.rst
  vdex.rst
  art.rst


.. toctree::
  :caption: Platforms
  :maxdepth: 2

  platforms/android.rst

Exceptions
----------

.. doxygenclass:: LIEF::exception
   :project: lief

.. doxygenclass:: LIEF::bad_file
   :project: lief

.. doxygenclass:: LIEF::bad_format
   :project: lief

.. doxygenclass:: LIEF::not_implemented
   :project: lief

.. doxygenclass:: LIEF::not_supported
   :project: lief

.. doxygenclass:: LIEF::integrity_error
   :project: lief

.. doxygenclass:: LIEF::read_out_of_bound
   :project: lief

.. doxygenclass:: LIEF::not_found
   :project: lief

.. doxygenclass:: LIEF::corrupted
   :project: lief

.. doxygenclass:: LIEF::conversion_error
   :project: lief

.. doxygenclass:: LIEF::type_error
   :project: lief

.. doxygenclass:: LIEF::builder_error
   :project: lief

.. doxygenclass:: LIEF::parser_error
   :project: lief

.. doxygenclass:: LIEF::pe_error
   :project: lief

.. doxygenclass:: LIEF::pe_bad_section_name
   :project: lief


Iterators
---------

.. doxygenclass:: LIEF::ref_iterator
   :project: lief

.. doxygenclass:: LIEF::const_ref_iterator
   :project: lief

.. doxygenclass:: LIEF::filter_iterator
   :project: lief

.. doxygenclass:: LIEF::const_filter_iterator
   :project: lief

Logging
-------

.. doxygenclass:: LIEF::Logger
   :project: lief

Logging levels
~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::LOGGING_LEVEL
   :project: lief



































