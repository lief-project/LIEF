Installation and Integration
============================

SDK
---

For each platform there is a SDK which contains

  * Static library
  * Shared library
  * Headers

To install the static or shared library one have to copy them in the right folder. For instance, on Linux it would be in ``/usr/lib`` and ``/usr/include``.


Python
------

To install the Python API (example with ``Python 3.5``):

.. code-block:: console

  $ pip install lief-XX.YY.ZZ_py35.tar.gz


Visual Studio Integration
-------------------------

The pre-built SDK is compiled in release configuration with the *Multi-threaded* runtime library.

As example we compile the following snippet with Visual Studio 2015

.. code-block:: cpp

  #include "stdafx.h"

  #include <LIEF/LIEF.hpp>

  int main()
  {
    LIEF::PE::Binary* pe_binary = LIEF::PE::Parser::parse("C:\\Windows\\explorer.exe");
    std::cout << *pe_binary << std::endl;
    delete pe_binary;
    return 0;
  }

First the build type must be set to ``Release``:

.. figure:: _static/windows_sdk/s1.png
  :align: center

  Build type set to ``Release``


Then we need to specify the location of the LIEF include directory:

.. figure:: _static/windows_sdk/s2.png
  :align: center

  LIEF include directory

and the location of the ``LIEF.lib`` library:


.. figure:: _static/windows_sdk/s5.png
  :align: center

  LIEF library

As ``LIEF.lib`` was compiled with the ``\MT`` flag we have to set it:

.. figure:: _static/windows_sdk/s3.png
  :align: center

  *Multi-threaded* as runtime library

LIEF makes use of ``and, or, not`` C++ keywords. As **MSVC** doesn't support these keywords by default, we need to add the special file ``iso646.h``:

.. figure:: _static/windows_sdk/s4.png
  :align: center

  Add ``iso646.h`` file

XCode Integration
-----------------

To integrate LIEF within a XCode project, one needs to follow these steps:

First we create a new project:

.. figure:: _static/xcode_integration/step1.png
  :align: center

  New Project

For this example we select a *Command Line Tool*:

.. figure:: _static/xcode_integration/step2.png
  :align: center

  Command Line Tool


.. figure:: _static/xcode_integration/step3.png
  :align: center

  Project options

Then we need to add the static library ``libLIEF.a`` or the shared one (``libLIEF.dylib``)

.. figure:: _static/xcode_integration/step4.png
  :align: center

  Project configuration - Build Phases


.. figure:: _static/xcode_integration/step5.png
  :align: center

  Project configuration - Build Phases


.. figure:: _static/xcode_integration/step6.png
  :align: center

  Project configuration - Build Phases

In the `Build Settings - Search Paths` one needs to specify the paths to the **include directory** and to location of the LIEF libraries (``libLIEF.a`` and/or ``libLIEF.dylib``)

.. figure:: _static/xcode_integration/step7.png
  :align: center

  Libraries and Include search paths

Once the new project configured we can use LIEF:


.. figure:: _static/xcode_integration/code.png
  :align: center

  Source code

and run it:

.. figure:: _static/xcode_integration/result.png
  :align: center

  Output


CMake Integration
-----------------

By using `CMake External Project <https://cmake.org/cmake/help/v3.0/module/ExternalProject.html>`_, integration of LIEF is quiet simple.

This script setup LIEF as an *external project*

.. code-block:: cmake

  set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
  set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
  set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

  # LIEF static library
  set(LIB_LIEF_STATIC
    "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}")

  # URL of the LIEF repo (Can be your fork)
  set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

  # LIEF's version to be used (can be 'master')
  set(LIEF_VERSION 0.7.0)

  # LIEF compilation config
  set(LIEF_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DLIEF_DOC=off
    -DLIEF_PYTHON_API=off
    -DLIEF_EXAMPLES=off
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
  )

  ExternalProject_Add(LIEF
    PREFIX           "${LIEF_PREFIX}"
    GIT_REPOSITORY   ${LIEF_GIT_URL}
    GIT_TAG          ${LIEF_VERSION}
    INSTALL_DIR      ${LIEF_INSTALL_DIR}
    CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
    BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
    UPDATE_COMMAND   ""
  )

And now, to be integrated within a project:

.. code-block:: cmake

  add_executable(HelloLIEF main.cpp)

  if (MSVC)
    # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
    target_compile_options(HelloLIEF PUBLIC /FIiso646.h)
    set_property(TARGET HelloLIEF PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
  endif()

  # Setup the LIEF include directory
  target_include_directories(HelloLIEF
    PUBLIC
    ${LIEF_INCLUDE_DIRS}
  )

  # Enable C++11
  set_property(TARGET HelloLIEF PROPERTY CXX_STANDARD           11)
  set_property(TARGET HelloLIEF PROPERTY CXX_STANDARD_REQUIRED  ON)

  # Link the executable with LIEF
  target_link_libraries(HelloLIEF PUBLIC ${LIB_LIEF_STATIC})

  add_dependencies(HelloLIEF LIEF)

For the compilation:

.. code-block:: console

  $ mkdir build
  $ cd build
  $ cmake ..
  $ make -j3 # and wait...

A *full* example is available in the ``examples/cmake`` directory.
