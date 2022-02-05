.. _cpp-api-ref:

C++
===

The original Doxygen documentation is also available `here <../../doxygen/>`_

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

.. _cpp-api-error-handling:

Error Handling
--------------

.. doxygentypedef:: LIEF::result
   :project: lief

.. doxygenfunction:: LIEF::as_lief_err
   :project: lief

.. doxygenenum:: lief_errors
   :project: lief

.. doxygentypedef:: LIEF::ok_error_t
   :project: lief

.. doxygenfunction:: LIEF::ok
   :project: lief

.. doxygenstruct:: LIEF::ok_t
   :project: lief

See also the section :ref:`err_handling`

Exceptions
----------

.. warning::

   Exceptions will be progressively removed as explained in :ref:`err_handling`

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

.. doxygentypedef:: LIEF::const_ref_iterator
   :project: lief

.. doxygenclass:: LIEF::filter_iterator
   :project: lief

.. doxygentypedef:: LIEF::const_filter_iterator
   :project: lief

Logging
-------

.. doxygenfunction:: LIEF::logging::disable
   :project: lief

.. doxygenfunction:: LIEF::logging::enable
   :project: lief

.. doxygenfunction:: LIEF::logging::set_level
   :project: lief

Logging levels
~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::logging::LOGGING_LEVEL
   :project: lief



































