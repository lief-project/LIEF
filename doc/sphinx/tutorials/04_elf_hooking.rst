04 - ELF Hooking
----------------

The objective of this tutorial is to hook a library function

Scripts and materials are available here: `materials <https://github.com/lief-project/tutorials/tree/master/03_ELF_hooking>`_

By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

------

In the previous tutorial we saw how to swap symbols names from a shared library, we will now see the mechanism to hook a function in a shared library.

The targeted library is the standard math library (``libm.so``) and we will insert a hook on the ``exp`` function so that :math:`exp(x) = x + 1`. The source code of the sample that uses this function is given in the following listing:

.. code-block:: cpp

  #include <stdio.h>
  #include <stdlib.h>
  #include <math.h>

  int main(int argc, char **argv) {
    if (argc != 2) {
      printf("Usage: %s <a> \n", argv[0]);
      exit(-1);
    }

    int a = atoi(argv[1]);
    printf("exp(%d) = %f\n", a, exp(a));
    return 0;
  }


The hooking function is as simple as:

.. code-block:: cpp

  double hook(double x) {
    return x + 1;
  }

Compiled with :code:`gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared hook.c -o hook`.

To inject this hook into the library, we use the :meth:`~lief.ELF.Binary.add` (segment) method

.. automethod:: lief.ELF.Binary.add
  :noindex:

Once the stub is injected we just have to change the address of the ``exp`` symbol:

.. code-block:: python

  exp_symbol  = libm.get_symbol("exp")
  hook_symbol = hook.get_symbol("hook")

  exp_symbol.value = segment_added.virtual_address + hook_symbol.value


To test the patched library:

.. code-block:: console

  $ ./do_math.bin 1
  exp(1) = 2.718282
  LD_LIBRARY_PATH=. ./do_math.bin 1
  exp(1) = 2.000000




