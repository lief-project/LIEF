04 - ELF Hooking
----------------

The objective of this tutorial is to hook a library function

Scripts and materials are available here: `materials <https://github.com/lief-project/tutorials/tree/master/04_ELF_hooking>`_

By Romain Thomas - `@rh0main <https://twitter.com/rh0main>`_

------

In the previous tutorial we saw how to swap symbols names from a shared library, we will now see the mechanism to hook a function in a shared library.

The targeted library is the standard math library (``libm.so``) and we will insert a hook on the ``exp`` function so that :math:`\exp(x) = x + 1`. The source code of the sample that uses this function is given in the following listing:

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

First, we find the code for our hook function, and add it to the library:

.. code-block:: python

  import lief

  libm = lief.parse("/usr/lib/libm.so.6")
  hook = lief.parse("hook")

  exp_symbol  = libm.get_symbol("exp")
  hook_symbol = hook.get_symbol("hook")

  code_segment = hook.segment_from_virtual_address(hook_symbol.value)
  segment_added = libm.add(code_segment)

Once the stub is injected we have to calculate the new address for the ``exp`` symbol, and update it:

.. code-block:: python

  new_address = segment_added.virtual_address + hook_symbol.value - code_segment.virtual_address
  exp_symbol.value = new_address
  exp_symbol.type  = lief.ELF.Symbol.TYPE.FUNC  # it might have been GNU_IFUNC

Note that we have to update symbol's type to be regular `FUNC` because on many
distributions `libm.so` is built with automatic hardware detection and exposes
symbols as `GNU_IFUNC`__ that has different dynamic binding protocol compared
to regular functions.

__ https://sourceware.org/glibc/wiki/GNU_IFUNC

Finally, we write out the patched library to a file in the current folder:

.. code-block:: python

  libm.write("libm.so.6")

To test the patched library:

.. code-block:: console

  $ ./do_math.bin 1
  exp(1) = 2.718282
  $ LD_LIBRARY_PATH=. ./do_math.bin 1
  exp(1) = 2.000000




