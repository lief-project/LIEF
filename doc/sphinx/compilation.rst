.. role:: strike
   :class: strike

Compilation
===========

To compile **LIEF**, you need at least the following requirements:

- C++14 compiler (GCC, Clang, MSVC..)
- CMake
- Python >= 3.6 (for the bindings)

To build the documentation:

- Doxygen (= ``1.8.10``, the CI uses ``1.8.20``)
- Sphinx (with ``sphinx_rtd_theme`` module)
- breathe (>= ``4.25.1``)


.. note::

  A compilation from scratch with all the options enabled can take ~30 minutes on a regular laptop.

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

.. _lief_debug:

Debugging
---------

By default, LIEF is compiled with ``CMAKE_BUILD_TYPE`` set to ``Release``. One can change this behavior
by setting either ``RelWithDebInfo`` or ``Debug`` during the cmake's configuration step:

.. code-block:: console

   $ cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo [...] ..

On the other hand, Python bindings can also be compiled with debug information by using
the ``--debug`` flag:

.. code-block:: console

   $ python ./setup.py build --debug


.. note::

  When developing on LIEF, you can use:

  .. code-block:: console

   $ python ./setup [--ninja] build --debug develop --user

  Compared to the ``install`` command, ``develop`` creates a ``.egg-link``
  that links to the native LIEF library currently presents in you build directory.

  The ``--user`` flag is used to avoid creating the ``.egg-link`` system-wide (i.e. ``/usr/lib/python3.9/site-packages``).
  Instead, it links the ``.egg-link`` in the user's local dir (e.g. ``~/.local/lib/python3.9/site-packages``)

Continuous Integration
----------------------

LIEF uses different CI (Github Action, AppVeyor, ...) to test and release nightly builds. The configuration
of these CI can also be a good source of information for the compilation process.
In particular, `scripts/docker/travis-linux-sdk.sh <https://github.com/lief-project/LIEF/blob/master/scripts/docker/travis-linux-sdk.sh>`_
contains the build process to generate the **Linux x86-64 SDK**.

The ``build_script`` section of `.appveyor.yml <https://github.com/lief-project/LIEF/blob/master/.appveyor.yml>`_
contains the logic for generating **Windows Python wheels and the SDK**.

For **OSX & iOS**, the CI configs `.github/workflows/ios.yml <https://github.com/lief-project/LIEF/blob/master/.github/workflows/ios.yml>`_
and `.github/workflows/osx.yml <https://github.com/lief-project/LIEF/blob/master/.github/workflows/osx.yml>`_
to compile (and cross-compile) LIEF for these platforms.

CMake Options
-------------

.. literalinclude:: ../../cmake/LIEFOptions.cmake

Docker
------


See `liefproject <https://hub.docker.com/u/liefproject>`_ on Dockerhub

.. container:: strike

  See the `Dockerlief <https://github.com/lief-project/Dockerlief>`_ repo.




