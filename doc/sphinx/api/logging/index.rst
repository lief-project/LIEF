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

.. doxygenfunction:: LIEF::logging::log(LEVEL level, const std::string &fmt, const Args&... args)

.. doxygenfunction:: LIEF::logging::log(LEVEL level, const std::string &fmt, const std::vector<std::string> &args)

.. doxygenfunction:: LIEF::logging::log(LEVEL level, const std::string &msg)

.. doxygenfunction:: LIEF::logging::reset

.. doxygenenum:: LIEF::logging::LEVEL

.. doxygenclass:: LIEF::logging::Scoped

Example
~~~~~~~

.. code-block:: cpp

  #include <LIEF/logging.hpp>

  // Set global level to ERROR
  LIEF::logging::set_level(LIEF::logging::LEVEL::ERROR);

  {
    // Temporarily set global level to DEBUG (RAII)
    LIEF::logging::Scoped _(LIEF::logging::LEVEL::DEBUG);
    LIEF::logging::log(LIEF::logging::LEVEL::DEBUG, "This is a debug message");
  }

Python
++++++++

.. autofunction:: lief.logging.set_level

.. autofunction:: lief.logging.enable

.. autofunction:: lief.logging.disable

.. autofunction:: lief.logging.set_path

.. autofunction:: lief.logging.log

.. autofunction:: lief.logging.level_scope

.. autoclass:: lief.logging.Scoped
  :members:

.. autoclass:: lief.logging.LEVEL

Example
~~~~~~~

.. code-block:: python

  import lief

  # Set global level to ERROR
  lief.logging.set_level(lief.logging.LEVEL.ERROR)

  # Temporarily set global level to DEBUG
  with lief.logging.level_scope(lief.logging.LEVEL.DEBUG):
      lief.logging.log(lief.logging.LEVEL.DEBUG, "This is a debug message")
