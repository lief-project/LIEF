Installation
============

SDK
---

For each platform there is a SDK which contains

  * Static library
  * Shared library
  * Headers

To install the static or shared library you have to copy them in the right folder. For instance, on Linux it would be in ``/usr/lib`` and ``/usr/include``.


Python
------

To install the Python API (example with ``Python 3.5``):

.. code-block:: console

  $ pip install lief-XX.YY.ZZ_py35.tar.gz


Windows SDK
-----------

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

  Add ``iso646.h`` file








