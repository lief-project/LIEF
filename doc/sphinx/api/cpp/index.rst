.. _cpp-api-ref:

:fa:`regular fa-file-code` C++
==============================

.. note::

   You can also find the Doxygen documentation `here <../../doxygen/>`_


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

.. doxygenfunction:: LIEF::logging::set_path
   :project: lief

Logging levels
~~~~~~~~~~~~~~

.. doxygenenum:: LIEF::logging::LEVEL
   :project: lief



































