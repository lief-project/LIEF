.. _extended-intro:

:fa:`cubes` What is LIEF Extended?
----------------------------------

Introduction
************

*LIEF extended* is an enhanced version of LIEF that contains additional features
like the support of Dyld shared cache, Objective-C metadata, PDB, and DWARF.

Whilst the main version of LIEF is focused on (only) providing support for
ELF, PE, and Mach-O, LIEF extended aims at providing other functionalities that
were not originally designed to be integrated into LIEF.

You can find the differences between both versions in this table:

+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| Module                                      | Regular Version   | Extended Version  | Note                                               |
+=============================================+===================+===================+====================================================+
| :ref:`ELF <format-elf>`                     | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`PE <format-pe>`                       | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`Mach-O <format-macho>`                | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`DEX <format-dex>`                     | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`OAT <format-oat>`                     | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`VDEX <format-vdex>`                   | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`ART <format-art>`                     | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`PDB <extended-pdb>`                   | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM :ref:`[1] <extended-llvm>`   |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`DWARF <extended-dwarf>`               | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM :ref:`[1] <extended-llvm>`   |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`ObjC <extended-objc>`                 | :xmark:`mark`     | :fa-check:`check` | Support based on :github-ref:`romainthomas/iCDump` |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`Dyld Shared Cache <extended-dsc>`     | :xmark:`mark`     | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`Disassembler <extended-disassembler>` | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM :ref:`[1] <extended-llvm>`   |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`Assembler <extended-assembler>`       | :xmark:`mark`     | :fa-check:`check` | Support based on LLVM :ref:`[1] <extended-llvm>`   |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+

To access the extended version, you must **oauth-login** with **GitHub** here: |lief-extended-url|.

Once logged in, you can download the package of your choice
(e.g. LIEF Extended - Python 3.10 for macOS arm64)

Versioning
**********

LIEF extended uses a slightly different versioning scheme compared to the
regular LIEF packages.

First off, **every extended package** is based on the current ``main`` branch
of LIEF. If you need an (extended) build for a specific commit or tag,
please contact |lief-extended-email|.

In Python, you can check the commit of LIEF being used in the extended version
with:

.. code-block:: bash

  # Make sure it's the extended version
  $ python -c "import lief;print(lief.__extended__)"

  # Print LIEF's main commit
  $ python -c "import lief;print(lief.__LIEF_MAIN_COMMIT__)"

With the C++/Rust SDK you can call: |lief-extended-version-info| to
get details about the current version.

The additional features exposed by LIEF-extended are not always represented in
a public commit while still being git-versioned. An incremental build number is
attached to represent instal changes not associated with a (public) commit.

For instance, the version ``0.16.0.2380`` contains 10 commits more compared to the
version ``0.16.0.2370``.

Python Wheels
*************

Python packages are delivered as a wheel for the required platform/version
(e.g. ``lief_extended-0.16.0.post2370-cp312-cp312-win_amd64.whl``).

One can install this wheel with pip using either:

.. code-block:: console

  $ venv\Scripts\python.exe -m pip install C:\Users\tmp\lief_extended-0.16.0.post2370-cp312-cp312-win_amd64.whl

Or

.. code-block:: console

  $ venv\Scripts\python.exe -m pip install --find-links C:\Users\tmp\ lief_extended

You can check that LIEF extended is correctly installed with:

.. code-block:: console

  $ python -c "import lief;print(lief.__extended__)"
  True

C++ SDK
*******

The C++ SDK is delivered as a ``.zip/.tar.gz`` archive which contains:

- A compiled shared library (``libLIEF.so``, ``LIEF.dll``, ``libLIEF.dylib``)
- Header files
- CMake helper files

Compared to the regular version, this SDK **does not** ship a static version of
LIEF, and the shared library is compiled with all the extended functionalities.

Here is, for instance, the layout for the macOS arm64 SDK:

.. code-block:: text

  LIEF-extended-sdk-0.16.0.2378-Darwin-arm64/
    lib/libLIEF.dylib
    lib/cmake/LIEF/lief-extended-config-version.cmake
    include/[...]

Rust SDK
********

The Rust SDK is also delivered as a ``.zip/.tar.gz`` archive that contains all the
files needed to be used with the :ref:`LIEF_RUST_PRECOMPILED <lief-rust-precompiled>`
environment variable described in the :ref:`Rust <lief_rust_bindings>` section.

Once the archive is extracted, you just have to set the environment variable
``LIEF_RUST_PRECOMPILED`` to the extracted path:

.. code-block:: console

  $ tar xzvf LIEF-extended-rust-0.16.0.2378-Linux-x86_64.tar.gz
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/rs/
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/rs/autocxx-autocxx_ffi-gen.rs
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/libLIEF.so
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/liblief-sys.a

  $ export LIEF_RUST_PRECOMPILED=$(pwd)/LIEF-extended-rust-0.16.0.2378-Linux-x86_64

Then, you can enjoy all extended features in Rust:

.. code-block:: console

  $ cargo build my-lief-extended-projet

.. _extended-llvm:

LIEF Extended & LLVM
********************


LIEF extended relies on LLVM for some of its functionalities like the
:ref:`disassembler <extended-disassembler>` and the
:ref:`DWARF <extended-dwarf>`/:ref:`PDB <extended-pdb>` support.

The LLVM version used by LIEF is fully based on the upstream version and integrated
into LIEF extended such that users don't have to deal with the compilation of LLVM
or its integration.

.. note::

  LIEF is currently using LLVM |lief-llvm-version|.

Whenever it's possible and suitable, bug fixes and enhancements have been
PR-submitted to the LLVM project:

- :llvm-pr:`119057`
- :llvm-pr:`119056`
- :llvm-pr:`116480`
- :llvm-pr:`116479`
- :llvm-pr:`97954`


.. include:: ../_cross_api.rst
