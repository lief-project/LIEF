.. role:: strike
   :class: strike

Compilation
===========

To compile **LIEF**, you need at least the following requirements:

- C++14 compiler (GCC, Clang, MSVC..)
- CMake
- Python >= 3.6 (for bindings)

To build the documentation:

- Doxygen (= ``1.8.10``, the CI uses ``1.8.20``)
- Sphinx (with ``sphinx_rtd_theme`` module)
- breathe (>= ``4.25.1``)


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
  $ python ./setup.py [--ninja] build install [--user]

.. note::

  You can speed-up the compilation by installing `ccache <https://ccache.dev/>`_ or `sccache <https://github.com/mozilla/sccache>`_

If you want to enable tests, you can add ``--lief-test`` after ``setup.py``.

CMake Options
-------------

.. literalinclude:: ../../cmake/LIEFOptions.cmake

Docker
------


See `liefproject <https://hub.docker.com/u/liefproject>`_ on Dockerhub

.. container:: strike

  See the `Dockerlief <https://github.com/lief-project/Dockerlief>`_ repo.




