:fa:`solid fa-hand-holding-hand` Utilities
--------------------------------------------

Demangling
~~~~~~~~~~~

LIEF exposes a demangling API for the following formats:


.. tabs::

  .. tab:: :fa:`brands fa-windows` MSVC

    **Input**

    .. code-block:: python

      lief.demangle("?h@@YAXH@Z")

    **Result**

    .. code-block:: text

      void __cdecl h(int)

  .. tab:: :fa:`brands fa-rust` Rust

    **Input**

    .. code-block:: python

      lief.demangle("_RNvCskwGfYPst2Cb_3foo16example_function")

    **Result**

    .. code-block:: text

      foo::example_function

  .. tab:: :fa:`regular fa-file-code` Itanium C++

    **Input**

    .. code-block:: python

      lief.demangle("_ZTSN3lld13SpecificAllocINS_4coff9TpiSourceEEE")

    **Result**

    .. code-block:: text

      typeinfo name for lld::SpecificAlloc<lld::coff::TpiSource>

  .. tab:: :fa:`brands fa-swift` Swift/Obj-C

    **Input**

    .. code-block:: python

      lief.demangle("_$s10Foundation4DataV15_RepresentationON")

    **Result**

    .. code-block:: text

      type metadata for Foundation.Data._Representation


.. doxygenfunction:: LIEF::demangle

.. autofunction:: lief.demangle

:fa:`brands fa-rust` :rust:func:`lief::demangle`

Extended Version
~~~~~~~~~~~~~~~~

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

To get details about the version of the current extended build:

.. doxygenfunction:: LIEF::extended_version_info

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
