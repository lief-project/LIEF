:fa:`solid fa-hand-holding-hand` Utilities
--------------------------------------------

Demangling
~~~~~~~~~~~

.. doxygenfunction:: LIEF::demangle

.. autofunction:: lief.demangle

Is Extended?
~~~~~~~~~~~~

To check if the current build is an :ref:`extended <extended-intro>` version
you can use:

.. doxygenfunction:: LIEF::is_extended

.. autodata:: lief._lief.__extended__

:rust:func:`lief::is_extended`

In C++ you can also check if the ``LIEF_EXTENDED`` is defined:

.. code-block:: cpp

   #include <LIEF/config.hpp>

   #if defined(LIEF_EXTENDED)
   // Extended version
   #else
   // Regular version
   #endif

Android Platform
~~~~~~~~~~~~~~~~~

.. autofunction:: lief.Android.code_name

.. autofunction:: lief.Android.version_string

.. autoclass:: lief.Android.ANDROID_VERSIONS
  :members:
  :inherited-members:
  :undoc-members:

.. doxygenfunction:: LIEF::Android::code_name

.. doxygenfunction:: LIEF::Android::version_string

.. doxygenenum:: LIEF::Android::ANDROID_VERSIONS

Python Leaks
~~~~~~~~~~~~~

.. autofunction:: lief.disable_leak_warning
