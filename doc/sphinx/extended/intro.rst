.. _extended-intro:

:fa:`cubes` What is LIEF Extended?
----------------------------------

Introduction
************

*LIEF Extended* is an enhanced version of LIEF, providing additional features
such as support for the Dyld shared cache, Objective-C metadata, PDB, and DWARF.

While the main version of LIEF focuses on providing support for
ELF, PE, and Mach-O, LIEF Extended aims to provide functionality that
was not originally intended for integration into the core LIEF project.

You can find the differences between the two versions in this table:

+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| Module                                      | Regular Version   | Extended Version  | Note                                               |
+=============================================+===================+===================+====================================================+
| :ref:`ELF <format-elf>`                     | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`PE <format-pe>`                       | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`Mach-O <format-macho>`                | :fa-check:`check` | :fa-check:`check` |                                                    |
+---------------------------------------------+-------------------+-------------------+----------------------------------------------------+
| :ref:`COFF <format-coff>`                   | :fa-check:`check` | :fa-check:`check` |                                                    |
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


.. raw:: html

  <div class="card shadow-light">
    <div class="card-body">
      <h5 class="card-title"><i class="fab fa-github text-darkblue  mr-2"></i>Get Access</h5>
      <p class="card-text">To access the extended version, you must <b>oauth-login</b> with <b>GitHub</b> here:</p>
      <a href="https://extended.lief.re/" target="_blank" class="btn btn-pink text-uppercase-bold-sm shadow-sm mx-2 hover-lift-light"><i class="fa-solid fa-cubes mr-2"></i>LIEF Extended</a>
    </div>
  </div>
  <br />

To access the extended version, you must **oauth-login** with **GitHub** here: |lief-extended-url|.

Once logged in, you can download the package of your choice
(e.g., LIEF Extended - Python 3.10 for macOS arm64).


.. admonition:: Email
  :class: warning

  If you don't receive the download email, you can download the package directly
  from your **History** section.

Versioning
**********

LIEF Extended uses a slightly different versioning scheme than regular LIEF packages.

First, **every extended package** is based on the current ``main`` branch
of LIEF. If you need an (extended) build for a specific commit or tag,
please contact |lief-extended-email|.

In Python, you can check the commit of LIEF being used in the extended version
with:

.. code-block:: bash

  # Make sure it's the extended version
  $ python -c "import lief;print(lief.__extended__)"

  # Print LIEF's main commit
  $ python -c "import lief;print(lief.__LIEF_MAIN_COMMIT__)"

With the C++/Rust SDK, you can call |lief-extended-version-info| to
get details about the current version.

Additional features exposed by LIEF Extended are not always represented in
a public commit while still being git-versioned. An incremental build number is
used to represent internal changes not associated with a public commit.

For example, version ``0.16.0.2380`` includes 10 more commits than
version ``0.16.0.2370``.

Python Wheels
*************

Python packages are delivered as a wheel for the required platform/version
(e.g., ``lief_extended-0.16.0.post2370-cp312-cp312-win_amd64.whl``).

You can install this wheel using pip in one of the following ways:

.. code-block:: console

  $ venv\Scripts\python.exe -m pip install C:\Users\tmp\lief_extended-0.16.0.post2370-cp312-cp312-win_amd64.whl

Or

.. code-block:: console

  $ venv\Scripts\python.exe -m pip install --find-links C:\Users\tmp\ lief_extended

You can verify that LIEF Extended is correctly installed with:

.. code-block:: console

  $ python -c "import lief;print(lief.__extended__)"
  True

C++ SDK
*******

The C++ SDK is delivered as a ``.zip/.tar.gz`` archive containing:

- A compiled shared library (``libLIEF.so``, ``LIEF.dll``, ``libLIEF.dylib``)
- Header files
- CMake helper files

Compared to the regular version, this SDK **does not** ship a static version of
LIEF, and the shared library is compiled with all extended features.

Here is the layout for the macOS arm64 SDK, for example:

.. code-block:: text

  LIEF-extended-sdk-0.16.0.2378-Darwin-arm64/
    lib/libLIEF.dylib
    lib/cmake/LIEF/lief-extended-config-version.cmake
    include/[...]

Rust SDK
********

The Rust SDK is also delivered as a ``.zip/.tar.gz`` archive containing all the
files needed for use with the ``LIEF_RUST_PRECOMPILED`` environment variable,
as described in the :ref:`Rust <lief_rust_bindings>` section.

Once the archive is extracted, you just have to set the ``LIEF_RUST_PRECOMPILED``
environment variable to the extracted path:

.. code-block:: console

  $ tar xzvf LIEF-extended-rust-0.16.0.2378-Linux-x86_64.tar.gz
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/rs/
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/rs/autocxx-autocxx_ffi-gen.rs
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/libLIEF.so
    LIEF-extended-rust-0.16.0.2378-Linux-x86_64/lib/liblief-sys.a

  $ export LIEF_RUST_PRECOMPILED=$(pwd)/LIEF-extended-rust-0.16.0.2378-Linux-x86_64

You can then use all the extended features in Rust:

.. code-block:: console

  $ cargo build my-lief-extended-project

.. _extended-llvm:

LIEF Extended & LLVM
********************


LIEF Extended relies on LLVM for certain features, such as the
:ref:`disassembler <extended-disassembler>` and
:ref:`DWARF <extended-dwarf>`/:ref:`PDB <extended-pdb>` support.

The LLVM version used by LIEF is based on the upstream version and integrated
into LIEF Extended so that users do not have to handle LLVM compilation or
integration.

.. note::

  LIEF is currently using LLVM |lief-llvm-version|.

Whenever possible and appropriate, bug fixes and enhancements have been
submitted as PRs to the LLVM project:

- :llvm-pr:`119057`
- :llvm-pr:`119056`
- :llvm-pr:`116480`
- :llvm-pr:`116479`
- :llvm-pr:`97954`


.. include:: ../_cross_api.rst
