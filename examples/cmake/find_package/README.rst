LIEF CMake Integration Example - find_package()
===============================================


.. code-block:: console

  $ mkdir build
  $ cd build
  $ cmake -DLIEF_DIR=<PATH_TO_LIEF_INSTALL_DIR> .. # By default, LIEF_DIR=CMAKE_INSTALL_PREFIX
  $ make
  $ HelloLIEF /bin/ls # or explorer.exe or whatever

