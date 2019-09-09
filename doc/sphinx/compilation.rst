Compilation
===========

To be compiled **LIEF** needs at least the following requirements:

 - C++11 compiler (GCC, Clang, MSVC..)
 - CMake
 - Python (for bindings)

To build the documentation:

 - Doxygen (= ``1.8.10``)
 - Sphinx (with ``sphinx_rtd_theme`` module)
 - breathe (>= ``4.5.0``)


Libraries only (SDK)
--------------------

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF.git
  $ cd LIEF
  $ mkdir build
  $ cd build
  $ cmake -DLIEF_PYTHON_API=off -DCMAKE_BUILD_TYPE=Release ..
  $ cmake --build . --target LIB_LIEF --config Release

.. warning::

   On Windows one can choose the CRT to use by setting the ``LIEF_USE_CRT_<RELEASE;DEBUG;..>`` variable:

   .. code-block:: console

      $ cmake -DCMAKE_BUILD_TYPE=Release -DLIEF_USE_CRT_RELEASE=MT ..

   For Debug, you should set the CRT to **MTd**:

   .. code-block::

      $ cmake -DCMAKE_BUILD_TYPE=Debug -DLIEF_USE_CRT_DEBUG=MTd ..
      $ cmake --build . --target LIB_LIEF --config Debug



Library and Python bindings
---------------------------

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF.git
  $ cd LIEF
  $ mkdir build
  $ cd build
  $ cmake -DLIEF_PYTHON_API=on -DPYTHON_VERSION=3.6 -DCMAKE_BUILD_TYPE=Release ..
  $ cmake --build . --target LIB_LIEF --config Release
  $ cmake --build . --target pyLIEF --config Release

.. warning::

  Depending on your Python version, CMake could not
  find the right Python library to link against.

  We suggest to explicitly define path to the Python library,
  Python include directory and Python executable.

  .. code-block:: console

    $ cmake .. \
      -DPYTHON_VERSION=3.5 \
      -DPYTHON_INCLUDE_DIR:PATH=/usr/include/python3.5m \
      -DPYTHON_LIBRARY:FILEPATH=/usr/lib/libpython3.so \
      -DPYTHON_BINARY:FILEPATH=/usr/bin/python3.5


If you want to enable tests, add ``-DLIEF_TESTS=on`` during the CMake configuration step.

The Doxygen documentation will be located at ``build/doc/doxygen/html`` and the sphinx documentation at ``build/doc/sphinx-doc``

CMake Options
-------------

.. literalinclude:: ../../../cmake/LIEFOptions.cmake

Docker
------

See the `Dockerlief <https://github.com/lief-project/Dockerlief>`_ repo.




