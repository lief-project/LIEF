.. role:: strike
   :class: strike

.. _compilation_ref:

Compilation
===========

To compile **LIEF**, you need at least the following requirements:

- C++17 compiler (GCC, Clang, MSVC..)
- CMake
- Python >= 3.8 (for the bindings)

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

   On Windows one can choose the CRT to use by setting the ``CMAKE_MSVC_RUNTIME_LIBRARY`` variable:

   .. code-block:: console

      $ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ..

   For Debug, you should set the CRT to **MTd**:

   .. code-block::

      $ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebug ..
      $ cmake --build . --target LIB_LIEF --config Debug

Python bindings
---------------

.. note::

  Since LIEF 0.13.0 the `setup.py` has moved from the project root directory
  to the `api/python` directory.

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF.git
  $ cd LIEF/api/python
  $ pip install [-e] [--user] .
  # Or
  $ pip install [-e] api/python

.. note::

  You can speed-up the compilation by installing `ccache <https://ccache.dev/>`_
  or `sccache <https://github.com/mozilla/sccache>`_

One can tweak the compilation by setting the environment variable ``PYLIEF_CONF``
to a Toml configuration file. By default, the Python bindings are using ``config-default.toml``
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

By default, LIEF is compiled with ``CMAKE_BUILD_TYPE`` set to ``Release``. One can change this behavior
by setting either ``RelWithDebInfo`` or ``Debug`` during the cmake's configuration step:

.. code-block:: console

   $ cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo [...] ..

On the other hand, Python bindings can also be compiled with debug information
by changing the `type` in the section `[lief.build]` of `config-default.toml`:

.. code-block:: toml

  [lief.build]
  type = "RelWithDebInfo"

.. note::

  When developing on LIEF, you can use:

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

LIEF relies on few external projects and we try to limit as much as possible
the dependencies in the public headers. This table summarizes these
dependencies and their scope. ``internal`` means that it is required to compile
LIEF but it is not required to use LIEF. ``external`` means that it is required for both.

+-----------------------------------+--------------+--------------------------------------------+
| Dependency                        | Scope        | Purpose                                    |
+-----------------------------------+--------------+--------------------------------------------+
| `tcb/span <span_ref>`_            | ``external`` | C++11 span interface                       |
+-----------------------------------+--------------+--------------------------------------------+
| `TL Expected <tl_ref>`_           | ``external`` | Error handling (see: :ref:`err_handling` ) |
+-----------------------------------+--------------+--------------------------------------------+
| `spdlog <spdlog_ref>`_            | ``internal`` | Logging                                    |
+-----------------------------------+--------------+--------------------------------------------+
| `MbedTLS <mbedtls_ref>`_          | ``internal`` | ASN.1 parser / Hash functions              |
+-----------------------------------+--------------+--------------------------------------------+
| `utfcpp <utfcpp_ref>`_            | ``internal`` | Unicode support (for PE and DEX files)     |
+-----------------------------------+--------------+--------------------------------------------+
| `json <json_ref>`_                | ``internal`` | Serialize LIEF's object into JSON          |
+-----------------------------------+--------------+--------------------------------------------+
| `nanobind <nanobind_ref>`_        | ``internal`` | Python bindings                            |
+-----------------------------------+--------------+--------------------------------------------+
| `Frozen <frozen_ref>`_            | ``internal`` | ``constexpr`` containers                   |
+-----------------------------------+--------------+--------------------------------------------+
| `Catch2 <catch_ref>`_             | ``internal`` | Testing                                    |
+-----------------------------------+--------------+--------------------------------------------+
| `Melkor ELF Fuzzer <melkor_ref>`_ | ``internal`` | ELF Fuzzing                                |
+-----------------------------------+--------------+--------------------------------------------+

.. _tl_ref: https://github.com/TartanLlama/expected
.. _span_ref: https://github.com/tcbrindle/span
.. _spdlog_ref: https://github.com/gabime/spdlog
.. _mbedtls_ref: https://github.com/Mbed-TLS/mbedtls
.. _utfcpp_ref: https://github.com/nemtrif/utfcpp
.. _json_ref: https://github.com/nlohmann/json
.. _nanobind_ref: https://github.com/wjakob/nanobind
.. _frozen_ref: https://github.com/serge-sans-paille/frozen
.. _melkor_ref: https://github.com/IOActive/Melkor_ELF_Fuzzer

Except MbedTLS, all these dependencies are header-only and they are by default embedded/managed by LIEF such as it
eases the compilation and the integration.

Nevertheless, packages manager might require to not self-use/embed external dependencies [#ref_issue]_ [#ref_vcpk]_.

To address this requirement, the user can control the integration of LIEF's dependencies using the following
cmake's options:

  * ``LIEF_OPT_NLOHMANN_JSON_EXTERNAL``
  * ``LIEF_OPT_UTFCPP_EXTERNAL``
  * ``LIEF_OPT_MBEDTLS_EXTERNAL``
  * ``LIEF_EXTERNAL_SPDLOG``
  * ``LIEF_OPT_FROZEN_EXTERNAL``
  * ``LIEF_OPT_EXTERNAL_SPAN/LIEF_EXTERNAL_SPAN_DIR``
  * ``LIEF_OPT_EXTERNAL_EXPECTED``
  * ``LIEF_OPT_NANOBIND_EXTERNAL``

By setting these flags, LIEF resolves the dependencies with CMake ``find_package(...)`` which
is aware of ``<DEPS>_DIR`` to find the package.

As a result, LIEF can be, for instance, compiled with the following configuration:

.. code-block:: console

   $ cmake .. -GNinja \
              -DLIEF_OPT_NLOHMANN_JSON_EXTERNAL=ON \
              -Dnlohmann_json_DIR=/lief-third-party/json/install/lib/cmake/nlohmann_json \
              -DLIEF_OPT_MBEDTLS_EXTERNAL=on \
              -DMbedTLS_DIR=/lief-third-party/mbedtls/install/cmake

.. warning::

   As mentioned previously, MbedTLS is not header-only which means that if it is *externalized* the static
   version of LIEF won't include the MbedTLS object files and the end user will have to link again ``LIEF.a``
   with a provided version of MbedTLS.

.. [#ref_issue] https://github.com/lief-project/LIEF/issues/605
.. [#ref_vcpk] https://learn.microsoft.com/en-us/vcpkg/contributing/maintainer-guide#do-not-use-vendored-dependencies

Continuous Integration
----------------------

LIEF uses CI Github Action to test and release nightly builds. The configuration
of this CI can also be a good source of information for the compilation process.
In particular, `scripts/docker/linux-sdk-x64 <https://github.com/lief-project/LIEF/blob/main/scripts/docker/linux-sdk-x64>`_
contains the build process to generate the **Linux x86-64 SDK**.

On Windows, the SDK is built with the following Python script:
`scripts/windows/package_sdk.py <https://github.com/lief-project/LIEF/blob/main/scripts/windows/package_sdk.py>`_

For **OSX & iOS**, the CI configs `.github/workflows/ios.yml <https://github.com/lief-project/LIEF/blob/main/.github/workflows/ios.yml>`_
and `.github/workflows/osx.yml <https://github.com/lief-project/LIEF/blob/main/.github/workflows/osx.yml>`_
to compile (and cross-compile) LIEF for these platforms.

CMake Options
-------------

.. literalinclude:: ../../cmake/LIEFOptions.cmake

Docker
------

See `liefproject <https://hub.docker.com/u/liefproject>`_ on Dockerhub
