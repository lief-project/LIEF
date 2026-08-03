(err_handling)=

# {fa}`solid fa-triangle-exclamation` Error Handling

## Introduction

LIEF manages errors using:

1. Exceptions (deprecated and removed since LIEF 0.13.0)
2. [std::expected (tl::expected)](https://github.com/TartanLlama/expected)

It turns out that using C++ exceptions (and RTTI) was not the best design choice,
as LIEF, as a library, can be used in a `-fno-exceptions` context.
Consequently, we moved to a mechanism based on the `ResultOrError`
idiom. This idiom is similar to those found in LLVM with
[llvm::ErrorOr](https://llvm.org/doxygen/classllvm_1_1ErrorOr.html) and in Rust
with [std::result](https://doc.rust-lang.org/std/result/).
LIEF uses a {title-reference}`std::expected`-like interface to handle errors. Since this
interface is only available in C++23, we rely on
[TartanLlama/expected](https://github.com/TartanLlama/expected), which
provides this interface for C++11/C++17.

Functions using this idiom return a {cpp:type}`LIEF::result`, which wraps either
the successful result or an error.

The user can process this result as follows:

{{ literalinclude("../../../code/cpp/error_handling.cpp", "result-handling") }}

In the case of Python, we leverage the *dynamic* features of the language to
return either the expected value or an error if the function fails.
For instance, in previous versions of {func}`lief.PE.get_type`, the
implementation raised an exception to inform the user:

{{ literalinclude("../../../code/python/error_handling.py", "get-type-exception") }}

With the new implementation that relies on the `ResultOrError` idiom, the
function returns the {class}`lief.PE.PE_TYPE` value if everything is correct,
and returns a {class}`lief.lief_errors` in case of a processing error.

The user can handle this new interface by using the `isinstance()` function or by comparing the value with
a {class}`lief.lief_errors` attribute:

{{ literalinclude("../../../code/python/error_handling.py", "get-type-error") }}

## {fa}`solid fa-code` API

### C++

```{eval-rst}
.. doxygenclass:: LIEF::result
```

```{eval-rst}
.. doxygenfunction:: LIEF::as_lief_err
```

```{eval-rst}
.. doxygenenum:: lief_errors
```

```{eval-rst}
.. doxygenclass:: LIEF::ok_error_t
```

```{eval-rst}
.. doxygenfunction:: LIEF::ok
```

```{eval-rst}
.. doxygenstruct:: LIEF::ok_t
```

### Python

```{eval-rst}
.. autoclass:: lief.lief_errors
```

```{eval-rst}
.. autoclass:: lief.ok_t
```

```{eval-rst}
.. autoclass:: lief.ok_error_t
```
