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

Python
++++++++

.. autofunction:: lief.logging.set_level

.. autofunction:: lief.logging.enable

.. autofunction:: lief.logging.disable

.. autofunction:: lief.logging.set_path

.. autofunction:: lief.logging.log

.. autoclass:: lief.logging.LEVEL
