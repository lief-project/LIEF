.. role:: strike
   :class: strike

.. _compilation_ref:

:fa:`solid fa-laptop-code` Compilation
======================================

To compile **LIEF**, you need at least the following requirements:

- C++17 compiler (GCC, Clang, MSVC...)
- CMake
- Python >= 3.9 (for the bindings)

.. note::

  A compilation from scratch with all the options enabled can take ~20 minutes on a regular laptop.

Libraries only (SDK)
--------------------

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF.git
  $ cd LIEF
  $ mkdir build
  $ cd build
  $ cmake -DCMAKE_BUILD_TYPE=Release ..
  $ cmake --build . --target LIB_LIEF --config Release

.. warning::

   On Windows, you can choose the CRT to use by setting the ``CMAKE_MSVC_RUNTIME_LIBRARY`` variable:

   .. code-block:: console

      $ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ..

   For Debug, you should set the CRT to **MTd**:

   .. code-block:: console

      $ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebug ..
      $ cmake --build . --target LIB_LIEF --config Debug

Python bindings
---------------

.. note::

  Since LIEF 0.13.0, `setup.py` has moved from the project root directory
  to the `api/python` directory.

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF.git
  $ cd LIEF/api/python
  $ pip install [-e] [--user] .
  # Or
  $ pip install [-e] api/python

.. note::

  You can speed up the compilation by installing `ccache <https://ccache.dev/>`_
  or `sccache <https://github.com/mozilla/sccache>`_.

You can tweak the compilation by setting the environment variable ``PYLIEF_CONF``
to a TOML configuration file. By default, the Python bindings use ``config-default.toml``
in the Python binding directory:


.. code-block:: toml

  [lief.build]
  type          = "Release"
  cache         = true
  ninja         = true
  parallel-jobs = 0

  [lief.formats]
  elf     = true
  pe      = false
  macho   = true
  ...

.. code-block:: console

   $ PYLIEF_CONF=/tmp/my-custom.toml pip install .

.. _lief_debug:

Debugging
---------

By default, LIEF is compiled with ``CMAKE_BUILD_TYPE`` set to ``Release``. You can change this behavior
by setting it to either ``RelWithDebInfo`` or ``Debug`` during CMake's configuration step:

.. code-block:: console

   $ cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo [...] ..

Alternatively, Python bindings can also be compiled with debug information
by changing the ``type`` in the `[lief.build]` section of `config-default.toml`:

.. code-block:: toml

  [lief.build]
  type = "RelWithDebInfo"

.. note::

  When developing LIEF, you can use:

  .. code-block:: console

    $ PYLIEF_CONF=~/lief-debug.toml pip install [-e] api/python

  With `lief-debug.toml` set to:

  .. code-block:: toml

    [lief.build]
    type = "RelWithDebInfo"
    ...

    [lief.logging]
    enabled = true
    debug   = true

.. _lief_third_party:

Third Party
-----------

LIEF relies on a few external projects, and we try to limit the dependencies in the public headers
as much as possible. This table summarizes these dependencies and their scope. ``internal`` means
that it is required to compile LIEF, but not to use it. ``external`` means that it is required for both.

+------------------------------------------+--------------+--------------------------------------------+
| Dependency                               | Scope        | Purpose                                    |
+==========================================+==============+============================================+
| :github-ref:`tcbrindle/span`             | ``external`` | C++11 span interface                       |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`TartanLlama/expected`       | ``external`` | Error handling (see: :ref:`err_handling` ) |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`gabime/spdlog`              | ``internal`` | Logging                                    |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`Mbed-TLS/mbedtls`           | ``internal`` | ASN.1 parser / Hash functions              |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`nemtrif/utfcpp`             | ``internal`` | Unicode support (for PE and DEX files)     |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`nlohmann/json`              | ``internal`` | Serialize LIEF's object into JSON          |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`wjakob/nanobind`            | ``internal`` | Python bindings                            |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`serge-sans-paille/frozen`   | ``internal`` | ``constexpr`` containers                   |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`IOActive/Melkor_ELF_Fuzzer` | ``internal`` | ELF Fuzzing                                |
+------------------------------------------+--------------+--------------------------------------------+
| :github-ref:`catchorg/Catch2`            | ``internal`` | Unit Testing                               |
+------------------------------------------+--------------+--------------------------------------------+

With the exception of MbedTLS, all these dependencies are header-only. By default, they are embedded
and managed by LIEF to ease compilation and integration.

Nevertheless, package managers often require linking against system libraries rather than using
vendored dependencies [#ref_issue]_ [#ref_vcpk]_.

To address this requirement, you can control the integration of LIEF's dependencies using the following
CMake options:

  * ``LIEF_OPT_NLOHMANN_JSON_EXTERNAL``
  * ``LIEF_OPT_UTFCPP_EXTERNAL``
  * ``LIEF_OPT_MBEDTLS_EXTERNAL``
  * ``LIEF_EXTERNAL_SPDLOG``
  * ``LIEF_OPT_FROZEN_EXTERNAL``
  * ``LIEF_OPT_EXTERNAL_SPAN/LIEF_EXTERNAL_SPAN_DIR``
  * ``LIEF_OPT_EXTERNAL_EXPECTED``
  * ``LIEF_OPT_NANOBIND_EXTERNAL``

By setting these flags, LIEF resolves the dependencies using CMake's ``find_package(...)``, which
relies on ``<DEPS>_DIR`` to locate the package.

For example, LIEF can be compiled with the following configuration:

.. code-block:: console

   $ cmake .. -GNinja                                                                        \
              -DLIEF_OPT_NLOHMANN_JSON_EXTERNAL=ON                                           \
              -Dnlohmann_json_DIR=/lief-third-party/json/install/lib/cmake/nlohmann_json \
              -DLIEF_OPT_MBEDTLS_EXTERNAL=on                                             \
              -DMbedTLS_DIR=/lief-third-party/mbedtls/install/cmake

.. warning::

   As mentioned previously, MbedTLS is not header-only. This means that if it is *externalized*, the static
   version of LIEF will not include the MbedTLS object files, and the end user will have to manually link
   ``LIEF.a`` with a provided version of MbedTLS.

.. [#ref_issue] https://github.com/lief-project/LIEF/issues/605
.. [#ref_vcpk] https://learn.microsoft.com/en-us/vcpkg/contributing/maintainer-guide#do-not-use-vendored-dependencies

Continuous Integration
----------------------

LIEF uses GitHub Actions to test and release nightly builds. The configuration
of this CI can also be a good source of information for the compilation process.
In particular, `scripts/docker/linux-sdk-x64 <https://github.com/lief-project/LIEF/blob/main/scripts/docker/linux-sdk-x64>`_
contains the build process to generate the **Linux x86-64 SDK**.

On Windows, the SDK is built with the following Python script:
`scripts/windows/package_sdk.py <https://github.com/lief-project/LIEF/blob/main/scripts/windows/package_sdk.py>`_

For **OSX & iOS**, refer to the CI configs `.github/workflows/ios.yml <https://github.com/lief-project/LIEF/blob/main/.github/workflows/ios.yml>`_
and `.github/workflows/osx.yml <https://github.com/lief-project/LIEF/blob/main/.github/workflows/osx.yml>`_
to see how LIEF is compiled (and cross-compiled) for these platforms.

CMake Options
-------------

.. literalinclude:: ../../cmake/LIEFOptions.cmake

Docker
------

See `liefproject <https://hub.docker.com/u/liefproject>`_ on Dockerhub
