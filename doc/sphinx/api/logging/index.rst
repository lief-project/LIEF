:fa:`regular fa-rectangle-list` Logging
---------------------------------------

This section details the API for interacting with LIEF's logging engine.

LIEF uses `spdlog <https://github.com/gabime/spdlog>`_ for its logging
mechanism, and this API provides an abstraction over that implementation.


:fa:`solid fa-code` API
~~~~~~~~~~~~~~~~~~~~~~~

C++
++++++++

.. doxygenfunction:: LIEF::logging::disable

.. doxygenfunction:: LIEF::logging::enable

.. doxygenfunction:: LIEF::logging::set_level

.. doxygenfunction:: LIEF::logging::set_path

.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &fmt, const Args&... args)

.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &fmt, const std::vector<std::string> &args)

.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &msg)

.. doxygenfunction:: LIEF::logging::reset

.. doxygenenum:: LIEF::logging::Level

.. doxygenclass:: LIEF::logging::Scoped

Example
~~~~~~~

.. literalinclude:: ../../../code/cpp/logging.cpp
  :language: cpp
  :start-after: lief-doc: example-start
  :end-before: lief-doc: example-end
  :dedent:

Python
++++++

.. autofunction:: lief.logging.set_level

.. autofunction:: lief.logging.enable

.. autofunction:: lief.logging.disable

.. autofunction:: lief.logging.set_path

.. autofunction:: lief.logging.log

.. autofunction:: lief.logging.level_scope

.. autoclass:: lief.logging.Scoped
  :members:

.. autoclass:: lief.logging.Level

Example
~~~~~~~

.. literalinclude:: ../../../code/python/logging.py
  :language: python
  :start-after: lief-doc: example-start
  :end-before: lief-doc: example-end
  :dedent:


Rust
++++

- :rust:func:`lief::logging::disable`
- :rust:func:`lief::logging::enable`
- :rust:func:`lief::logging::set_level`
- :rust:func:`lief::logging::set_path`
- :rust:func:`lief::logging::log`
- :rust:func:`lief::logging::reset`
- :rust:enum:`lief::logging::Level`
- :rust:struct:`lief::logging::Scoped`

Example
~~~~~~~

.. literalinclude:: ../../../code/rust/src/logging.rs
  :language: rust
  :start-after: lief-doc: example-start
  :end-before: lief-doc: example-end
  :dedent:
