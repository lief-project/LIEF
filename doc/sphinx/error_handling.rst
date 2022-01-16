.. _err_handling:

Error Handling
==============

Currently, LIEF manages the errors using two mechanisms:

1. The exceptions (widely used)
2. `Boost's LEAF <https://www.boost.org/doc/libs/1_75_0/libs/leaf/doc/html/index.html>`_

It turns out that using the C++ exceptions (and the RTTI) were not the better design choice as LIEF (as a
library) can be used in ``-fno-exceptions`` context. This is why we are slowly moving to the second mechanism
which is based on the ``ResultOrError`` idiom. We can find this kind idiom in LLVM with `llvm::ErrorOr <https://llvm.org/doxygen/classllvm_1_1ErrorOr.html>`_,
in Rust with `std::result <https://doc.rust-lang.org/std/result/>`_ and in `Boost LEAF <https://www.boost.org/doc/libs/1_75_0/libs/leaf/doc/html/index.html>`_.
We based our implementation from Boost LEAF as can be integrated smoothly in LIEF.

Basically, the LIEF functions that use this idiom return a :cpp:type:`LIEF::result` which wraps the effective
result or an error.

The user can process this result as follows:

.. code-block:: cpp

   result<PE_TYPE> pe_type = PE::get_type("/tmp/NotPE.elf")
   if (pe_type) {
     PE_TYPE effective_type = pe_type.value();
   } else {
     lief_errors err = as_lief_err(pe_type);
   }

In the case of Python, we leverage the *dynamic* features of the language to return either: the expected value
or an error if the function failed. For instance, if we take the :func:`lief.PE.get_type` function,
the former implementation of this function raised an exception to inform the user:

.. code-block:: python

  try:
    pe_type = lief.PE.get_type("/tmp/NotPE.elf")
    # If it does not fail, pe_type handles a lief.PE.PE_TYPE object
  except Exception as e:
    print(f"Error: {e}")

With the new implementation that relies on the ``ResultOrError`` idiom, the function returns the
:class:`lief.PE.PE_TYPE` value is everything is ok and in the case of a processing error, it returns a
:class:`lief.lief_errors`.

The user can handle this new interface by using the ``isinstance()`` function or by comparing the value with
a :class:`lief.lief_errors` attribute:

.. code-block:: python

  pe_type = lief.PE.get_type("/tmp/NotPE.elf")

  if pe_type == lief.lief_errors.file_error:
    print("File error")
  elif isinstance(pe_type, lief.lief_errors):
    print("Another kind of error")
  else:
    print("No error, type is: {}".format(pe_type))

