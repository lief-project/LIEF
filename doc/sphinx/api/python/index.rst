.. _python-api-ref:

Python
======

.. toctree::
  :caption: Common
  :maxdepth: 1

  utilities.rst
  abstract.rst

.. toctree::
  :caption: Formats specific
  :maxdepth: 2

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

exception
~~~~~~~~~

.. autoclass:: lief.exception
  :members:
  :inherited-members:
  :undoc-members:

----------

bad_file
~~~~~~~~

.. autoclass:: lief.bad_file
  :members:
  :inherited-members:
  :undoc-members:

----------

bad_format
~~~~~~~~~~

.. autoclass:: lief.bad_format
  :members:
  :inherited-members:
  :undoc-members:

----------

not_implemented
~~~~~~~~~~~~~~~

.. autoclass:: lief.not_implemented
  :members:
  :inherited-members:
  :undoc-members:

----------

not_supported
~~~~~~~~~~~~~

.. autoclass:: lief.not_supported
  :members:
  :inherited-members:
  :undoc-members:

----------

integrity_error
~~~~~~~~~~~~~~~

.. autoclass:: lief.integrity_error
  :members:
  :inherited-members:
  :undoc-members:

----------

read_out_of_bound
~~~~~~~~~~~~~~~~~

.. autoclass:: lief.read_out_of_bound
  :members:
  :inherited-members:
  :undoc-members:

----------

not_found
~~~~~~~~~

.. autoclass:: lief.not_found
  :members:
  :inherited-members:
  :undoc-members:

----------

corrupted
~~~~~~~~~

.. autoclass:: lief.corrupted
  :members:
  :inherited-members:
  :undoc-members:

----------

conversion_error
~~~~~~~~~~~~~~~~

.. autoclass:: lief.conversion_error
  :members:
  :inherited-members:
  :undoc-members:

----------

type_error
~~~~~~~~~~

.. autoclass:: lief.type_error
  :members:
  :inherited-members:
  :undoc-members:

----------

builder_error
~~~~~~~~~~~~~

.. autoclass:: lief.builder_error
  :members:
  :inherited-members:
  :undoc-members:

----------

parser_error
~~~~~~~~~~~~

.. autoclass:: lief.parser_error
  :members:
  :inherited-members:
  :undoc-members:

----------

pe_error
~~~~~~~~

.. autoclass:: lief.pe_error
  :members:
  :inherited-members:
  :undoc-members:

----------

pe_bad_section_name
~~~~~~~~~~~~~~~~~~~

.. autoclass:: lief.pe_bad_section_name
  :members:
  :inherited-members:
  :undoc-members:


Logging
-------

.. autoclass:: lief.Logger
  :members:
  :inherited-members:
  :undoc-members:

Logging levels
~~~~~~~~~~~~~~

.. autoclass:: lief.LOGGING_LEVEL
  :members:
  :inherited-members:
  :undoc-members:
