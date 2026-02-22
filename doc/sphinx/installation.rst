:fa:`solid fa-gears` Installation and Integration
=================================================

:fa:`regular fa-file-code` SDK
------------------------------

For each platform supported by LIEF, the SDK packages contain:

* static and shared libraries
* headers
* compiled examples

Nightly builds can be downloaded at: https://lief.s3-website.fr-par.scw.cloud/latest/sdk,
while official releases are available on the GitHub releases page:
https://github.com/lief-project/LIEF/releases.

:fa:`brands fa-python` Python
-----------------------------

Nightly Python wheels are uploaded for **each commit** on the main branch to an
S3 bucket. They can be installed using:

.. code-block:: console

  $ pip install [--user] --index-url https://lief.s3-website.fr-par.scw.cloud/latest lief

For tagged releases, the wheels are uploaded to PyPI and can be installed using:

.. code-block:: console

  $ pip install lief

You can also compile and install from source as follows:

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF
  $ pip install LIEF/api/python
  # Or pip+git:
  $ pip install git+https://github.com/lief-project/LIEF.git#subdirectory=api/python

For more details about the compilation options, see the :ref:`compilation_ref` section.

:fa:`brands fa-rust` Rust
-------------------------

You can add LIEF as a dependency in a Rust project as follows:

.. code-block:: toml

  # For nightly build
  [dependencies]
  lief = { git = "https://github.com/lief-project/LIEF", branch = "main" }

  # For a tagged release
  [dependencies]
  lief = "0.17.4"

You can find more details in the :ref:`Rust API section <lief_rust_bindings>`.

CMake Integration
-----------------

There are a few ways to integrate LIEF as a dependency into another project.
The following methods are listed in order of preference according to CMake best practices.
These snippets show basic examples; please refer to the official CMake documentation
for questions related to more complex project setups.

find_package()
**************

Using `CMake find_package() <https://cmake.org/cmake/help/v3.0/command/find_package.html>`_:

.. literalinclude:: ../../examples/cmake/find_package/CMakeLists.txt
   :language: cmake
   :lines: 5-12

To integrate this within a project:

.. literalinclude:: ../../examples/cmake/find_package/CMakeLists.txt
   :language: cmake
   :lines: 13-

For the compilation:

.. include:: ../../examples/cmake/find_package/README.rst
   :start-line: 3

A *full* example is available in the ``examples/cmake/find_package`` directory.

add_subdirectory() or FetchContent
**********************************

First, set up the options you want to set as default for the LIEF project:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 7-19

Using `CMake add_subdirectory() <https://cmake.org/cmake/help/v3.0/command/add_subdirectory.html>`_
to add LIEF as a submodule from a source directory:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 21-28

If you are using CMake 3.11 or later, you can use the
`CMake FetchContent module <https://cmake.org/cmake/help/v3.11/module/FetchContent.html>`_
to download or specify a LIEF source directory outside the current directory:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 33-61

To integrate this within a project:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 65-

For the compilation:

.. include:: ../../examples/cmake/add_subdirectory/README.rst
   :start-line: 3

A *full* example is available in the ``examples/cmake/add_subdirectory`` directory.

External Project
****************

If you don't want to use LIEF as a submodule or upgrade to CMake 3.11,
you can use `CMake External Project <https://cmake.org/cmake/help/v3.0/module/ExternalProject.html>`_
to set up your project as a `*superbuild* <https://www.kitware.com/cmake-superbuilds-git-submodules>`_:

.. literalinclude:: ../../examples/cmake/external_project/CMakeLists.txt
   :language: cmake
   :lines: 1-41

To integrate this with a main ``HelloLIEF`` project located in a subdirectory
(which looks exactly like the ``find_package()`` example shown earlier):

.. literalinclude:: ../../examples/cmake/external_project/CMakeLists.txt
   :language: cmake
   :lines: 44-

For the compilation:

.. include:: ../../examples/cmake/external_project/README.rst
   :start-line: 3

A *full* example is available in the ``examples/cmake/external_project`` directory.

Visual Studio Integration
-------------------------

Given a pre-compiled version of the LIEF SDK (e.g., ``LIEF-0.17.4-win64.zip``):

.. code-block:: text

  .
  ├── bin
  │   ├── pe_reader.exe
  │   └── vdex_reader.exe
  ├── include
  │   └── LIEF
  ├── lib
  │   ├── LIEF.dll
  │   ├── LIEF.lib
  │   └── pkgconfig
  └── share
      └── LIEF

You should add the ``include/`` directory to the compiler search path:
``Configuration Properties > C/C++ > General > Additional Include Directories``
and add either ``LIEF.lib`` or ``LIEF.dll`` during the linking step:

``Configuration Properties > Linker > Input > Additional Dependencies``

.. warning::

   ``LIEF.dll`` is compiled with the ``/MD`` flag (``MultiThreadedDLL``) while
   ``LIEF.lib`` is compiled with the ``/MT`` flag (``MultiThreaded``).

   If this configuration is not suitable for your project, you can compile LIEF
   with your required runtime.

Xcode Integration
-----------------

Similar to Visual Studio, you should configure the Xcode project to include
LIEF's ``include/`` and ``lib/`` directories:

- ``include/``:  ``Build Settings > Search Paths > Header Search Paths``
- ``lib/``:  ``Build Settings > Search Paths > Library Search Paths``

Then, you can add ``libLIEF.lib`` or ``libLIEF.dylib`` to the list of libraries to link against:

``Build Phases > Link Binary With Libraries``
