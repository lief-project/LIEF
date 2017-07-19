LIEF CMake Integration Example - find_package()
===============================================


.. code-block:: console

  $ mkdir build
  $ cd build
  $ cmake -DLIEF_ROOT=<PATH_TO_LIEF_INSTALL_DIR> .. # By default, LIEF_ROOT=CMAKE_INSTALL_PREFIX
  $ make
  $ HelloLIEF /bin/ls # or explorer.exe or whatever

