.. _err_handling:

:fa:`solid fa-triangle-exclamation` Error Handling
--------------------------------------------------

Introduction
~~~~~~~~~~~~~

LIEF manages errors using:

1. Exceptions (deprecated and removed since LIEF 0.13.0)
2. `std::expected (tl::expected) <https://github.com/TartanLlama/expected>`_

It turns out that using C++ exceptions (and RTTI) was not the best design choice,
as LIEF, as a library, can be used in a ``-fno-exceptions`` context.
Consequently, we moved to a mechanism based on the ``ResultOrError``
idiom. This idiom is similar to those found in LLVM with
`llvm::ErrorOr <https://llvm.org/doxygen/classllvm_1_1ErrorOr.html>`_ and in Rust
with `std::result <https://doc.rust-lang.org/std/result/>`_.
LIEF uses a `std::expected`-like interface to handle errors. Since this
interface is only available in C++23, we rely on
`TartanLlama/expected <https://github.com/TartanLlama/expected>`_, which
provides this interface for C++11/C++17.

Functions using this idiom return a :cpp:type:`LIEF::result`, which wraps either
the successful result or an error.

The user can process this result as follows:

.. code-block:: cpp

   result<PE_TYPE> pe_type = PE::get_type("/tmp/NotPE.elf");
   if (pe_type) {
     PE_TYPE effective_type = pe_type.value();
   } else {
     lief_errors err = as_lief_err(pe_type);
   }

In the case of Python, we leverage the *dynamic* features of the language to
return either the expected value or an error if the function fails.
For instance, in previous versions of :func:`lief.PE.get_type`, the
implementation raised an exception to inform the user:

.. code-block:: python

  try:
    pe_type = lief.PE.get_type("/tmp/NotPE.elf")
    # If it does not fail, pe_type handles a lief.PE.PE_TYPE object
  except Exception as e:
    print(f"Error: {e}")

With the new implementation that relies on the ``ResultOrError`` idiom, the
function returns the :class:`lief.PE.PE_TYPE` value if everything is correct,
and returns a :class:`lief.lief_errors` in case of a processing error.

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

:fa:`solid fa-code` API
~~~~~~~~~~~~~~~~~~~~~~~

C++
++++++++


.. doxygenclass:: LIEF::result

.. doxygenfunction:: LIEF::as_lief_err

.. doxygenenum:: lief_errors

.. doxygenclass:: LIEF::ok_error_t

.. doxygenfunction:: LIEF::ok

.. doxygenstruct:: LIEF::ok_t

Python
++++++++

.. autoclass:: lief.lief_errors

.. autoclass:: lief.ok_t

.. autoclass:: lief.ok_error_t
