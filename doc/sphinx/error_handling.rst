.. _err_handling:

Error Handling
==============

LIEF manages the errors using

1. The exceptions (removed in LIEF 0.13.0)
2. `std::expected (tl::expected) <https://github.com/TartanLlama/expected>`_

It turns out that using the C++ exceptions (and the RTTI) were not the better design choice as LIEF (as a
library) can be used in ``-fno-exceptions`` context. This is why we are slowly moving to the second mechanism
which is based on the ``ResultOrError`` idiom. We can find this kind idiom in LLVM with `llvm::ErrorOr <https://llvm.org/doxygen/classllvm_1_1ErrorOr.html>`_,
in Rust with `std::result <https://doc.rust-lang.org/std/result/>`_.
LIEF is using a `std::expected`-like to handle errors. Since this interface is
only available in C++23, we rely on `TartanLlama/expected <https://github.com/TartanLlama/expected>`_ which
provides this interface for C++11/C++17.

Basically, LIEF functions that use this idiom return a :cpp:type:`LIEF::result` which wraps the effective
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

