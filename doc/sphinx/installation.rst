Installation and Integration
============================

SDK
---

For each platform supported by LIEF, SDK packages contain:

* static and shared libraries
* headers
* compiled examples

Nightly build can be downloaded on: https://lief.s3-website.fr-par.scw.cloud/latest/sdk
while releases are available on Github release page:
https://github.com/lief-project/LIEF/releases.

Python
------

Nightly Python wheels are uploaded for **each commit** on the main branch in a
S3 bucket. They can be installed through:

.. code-block:: console

  $ pip install [--user] --index-url https://lief.s3-website.fr-par.scw.cloud/latest lief

For tagged releases, the wheels are uploaded on PyPI and can by installed through:

.. code-block:: console

  $ pip install lief

One can also compile and install from source as follows

.. code-block:: console

  $ git clone https://github.com/lief-project/LIEF
  $ pip install LIEF/api/python
  # Or pip+git:
  $ pip install git+https://github.com/lief-project/LIEF.git#subdirectory=api/python

For more details about the compilation options, see the :ref:`compilation_ref` section.


CMake Integration
-----------------

There are a few ways to integrate LIEF as a dependency in another project.
The different methods are listed in order of preference and CMake best practice.
These listings are only to show basic examples. Please refer to the CMake
documentation for questions related to more complex project setup.

find_package()
**************

Using `CMake find_package() <https://cmake.org/cmake/help/v3.0/command/find_package.html>`_:

.. literalinclude:: ../../examples/cmake/find_package/CMakeLists.txt
   :language: cmake
   :lines: 5-12

And now, to be integrated within a project:

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

Using `CMake add_subdirectory() <https://cmake.org/cmake/help/v3.0/command/add_subdirectory.html>`_ to add a submodule LIEF source directory:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 21-28

If we are using a CMake version greater than or equal to 3.11, we can use `CMake FetchContent module <https://cmake.org/cmake/help/v3.11/module/FetchContent.html>`_ to download or specify a LIEF source directory outside of the current directory:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 33-61

And now, to be integrated within a project:

.. literalinclude:: ../../examples/cmake/add_subdirectory/CMakeLists.txt
   :language: cmake
   :lines: 65-

For the compilation:

.. include:: ../../examples/cmake/add_subdirectory/README.rst
   :start-line: 3

A *full* example is available in the ``examples/cmake/add_subdirectory`` directory.


External Project
****************

If you don't want to use LIEF as a submodule or upgrade to CMake 3.11, we can use `CMake External Project <https://cmake.org/cmake/help/v3.0/module/ExternalProject.html>`_ to set up a project as a `*superbuild* <https://www.kitware.com/cmake-superbuilds-git-submodules>`_:

.. literalinclude:: ../../examples/cmake/external_project/CMakeLists.txt
   :language: cmake
   :lines: 1-41

And now, to be integrated with our main ``HelloLIEF`` project that is located in a subdirectory and looks exactly like the ``find_package()`` example shown earlier:

.. literalinclude:: ../../examples/cmake/external_project/CMakeLists.txt
   :language: cmake
   :lines: 44-

For the compilation:

.. include:: ../../examples/cmake/external_project/README.rst
   :start-line: 3

A *full* example is available in the ``examples/cmake/external_project`` directory.

Visual Studio Integration
-------------------------

Given a pre-compiled version of LIEF SDK (e.g. ``LIEF-0.14.1-win64.zip``):

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

One should add the ``include/`` directory in the compiler search path:
``Configuration Properties > C/C++ > General > Additional Include Directories``
and add either ``LIEF.lib`` or ``LIEF.dll`` in the link step:

``Configuration Properties > Linker > Input > Additional Dependencies``

.. warning::

   ``LIEF.dll`` is compiled with the ``/MD`` flag (``MultiThreadedDLL``) while
   ``LIEF.lib`` is compiled with the ``/MT`` flag (``MultiThreaded``).

   If this configuration is not suitable for your project, you can compile LIEF
   with your required runtime.

XCode Integration
-----------------

Similarly to Visual Studio, one should configure the XCode project to include
the ``include/`` directory of LIEF and the `lib/` directory:

- ``include/``:  ``Build Settings > Search Paths > Header Search Paths``
- ``lib/``:  ``Build Settings > Search Paths > Library Search Paths``

Then, we can add ``libLIEF.lib`` or ``libLIEF.dylib`` in the list of the libraries
to link with:

``Build Phases > Link Binary With Libraries``
