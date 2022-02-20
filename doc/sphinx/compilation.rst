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
| `Boost Leaf <leaf_ref>`_          | ``external`` | Error handling (see: :ref:`err_handling` ) |
+-----------------------------------+--------------+--------------------------------------------+
| `spdlog <spdlog_ref>`_            | ``internal`` | Logging                                    |
+-----------------------------------+--------------+--------------------------------------------+
| `MbedTLS <mbedtls_ref>`_          | ``internal`` | ASN.1 parser / Hash functions              |
+-----------------------------------+--------------+--------------------------------------------+
| `utfcpp <utfcpp_ref>`_            | ``internal`` | Unicode support (for PE and DEX files)     |
+-----------------------------------+--------------+--------------------------------------------+
| `json <json_ref>`_                | ``internal`` | Serialize LIEF's object into JSON          |
+-----------------------------------+--------------+--------------------------------------------+
| `pybind11 <pybind11_ref>`_        | ``internal`` | Python bindings                            |
+-----------------------------------+--------------+--------------------------------------------+
| `Frozen <frozen_ref>`_            | ``internal`` | ``constexpr`` containers                   |
+-----------------------------------+--------------+--------------------------------------------+
| `Catch2 <catch_ref>`_             | ``internal`` | Testing                                    |
+-----------------------------------+--------------+--------------------------------------------+
| `Melkor ELF Fuzzer <melkor_ref>`_ | ``internal`` | ELF Fuzzing                                |
+-----------------------------------+--------------+--------------------------------------------+

.. _span_ref: https://github.com/tcbrindle/span
.. _spdlog_ref: https://github.com/gabime/spdlog
.. _mbedtls_ref: https://github.com/ARMmbed/mbedtls
.. _leaf_ref: https://github.com/boostorg/leaf
.. _utfcpp_ref: https://github.com/nemtrif/utfcpp
.. _json_ref: https://github.com/nlohmann/json
.. _pybind11_ref: https://github.com/pybind/pybind11
.. _frozen_ref: https://github.com/serge-sans-paille/frozen
.. _melkor_ref: https://github.com/IOActive/Melkor_ELF_Fuzzer

Except MbedTLS, all these dependencies are header-only and they are by default embedded/managed by LIEF such as it
eases the compilation and the integration.

Nevertheless, packages manager might require to not self-use/embed external dependencies [#ref_issue]_ [#ref_vcpk]_.

To address this requirement, the user can control the integration of LIEF's dependencies using the following
cmake's options:

  * ``LIEF_OPT_NLOHMANN_JSON_EXTERNAL``
  * ``LIEF_OPT_EXTERNAL_LEAF`` / ``LIEF_EXTERNAL_LEAF_DIR``
  * ``LIEF_OPT_UTFCPP_EXTERNAL``
  * ``LIEF_OPT_MBEDTLS_EXTERNAL``
  * ``LIEF_EXTERNAL_SPDLOG``
  * ``LIEF_OPT_FROZEN_EXTERNAL``
  * ``LIEF_OPT_EXTERNAL_SPAN/LIEF_EXTERNAL_SPAN_DIR``
  * ``LIEF_OPT_PYBIND11_EXTERNAL``

By setting these flags, LIEF resolves the dependencies with CMake ``find_package(...)`` which
is aware of ``<DEPS>_DIR`` to find the package. Boost's Leaf does not provide
CMake files that can be resolved with ``find_package`` so the user can provide ``LIEF_EXTERNAL_LEAF_DIR`` instead,
which must point to the directory that contains ``boost/leaf``.

As a result, LIEF can be, for instance, compiled with the following configuration:

.. code-block:: console

   $ cmake .. -GNinja \
              -DLIEF_OPT_NLOHMANN_JSON_EXTERNAL=ON \
              -Dnlohmann_json_DIR=/lief-third-party/json/install/lib/cmake/nlohmann_json \
              -DLIEF_OPT_MBEDTLS_EXTERNAL=on \
              -DMbedTLS_DIR=/lief-third-party/mbedtls/install/cmake \
              -DLIEF_OPT_EXTERNAL_LEAF=on \
              -DLIEF_EXTERNAL_LEAF_DIR=/lief-third-party/leaf/include/cmake

.. warning::

   As mentioned previously, MbedTLS is not header-only which means that if it is *externalized* the static
   version of LIEF won't include the MbedTLS object files and the end user will have to link again ``LIEF.a``
   with a provided version of MbedTLS.

.. [#ref_issue] https://github.com/lief-project/LIEF/issues/605
.. [#ref_vcpk] https://github.com/microsoft/vcpkg/blob/master/docs/maintainers/maintainer-guide.md#do-not-use-vendored-dependencies

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




