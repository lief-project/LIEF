# 04 - ELF Hooking

The objective of this tutorial is to hook a library function.

______________________________________________________________________

In the previous tutorial, we saw how to swap symbol names in a shared library.
We will now see the mechanism for hooking a function in a shared library.

The targeted library is the standard math library (`libm.so`), and we will
insert a hook on the `exp` function so that {math}`\exp(x) = x + 1`.
The source code of the sample that uses this function is provided in the
following listing:

```cpp
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
```

The hook function is as follows:

```cpp
double hook(double x) {
  return x + 1;
}
```

Compiled with {code}`gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared hook.c -o hook`.

To inject this hook into the library, we use the {meth}`~lief.ELF.Binary.add` (segment) method:

```{eval-rst}
.. automethod:: lief.ELF.Binary.add
  :noindex:
```

First, we find the code for our hook function and add it to the library:

{{ literalinclude("../../code/python/tuto_elf_hooking.py", "inject") }}

Once the stub is injected, we must calculate the new address for the `exp`
symbol and update it:

{{ literalinclude("../../code/python/tuto_elf_hooking.py", "update") }}

Note that we must update the symbol type to a regular {title-reference}`FUNC` because, on many
distributions, {title-reference}`libm.so` is built with automatic hardware detection and exposes
symbols as [GNU_IFUNC](https://sourceware.org/glibc/wiki/GNU_IFUNC), which uses a different dynamic binding protocol
compared to regular functions.

Finally, we write the patched library to a file in the current directory:

{{ literalinclude("../../code/python/tuto_elf_hooking.py", "write") }}

To test the patched library:

```console
$ ./do_math.bin 1
exp(1) = 2.718282
$ LD_LIBRARY_PATH=. ./do_math.bin 1
exp(1) = 2.000000
```
