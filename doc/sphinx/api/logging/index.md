# {fa}`regular fa-rectangle-list` Logging

This section details the API for interacting with LIEF's logging engine.

LIEF uses [spdlog](https://github.com/gabime/spdlog) for its logging
mechanism, and this API provides an abstraction over that implementation.

## {fa}`solid fa-code` API

### C++

```{eval-rst}
.. doxygenfunction:: LIEF::logging::disable
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::enable
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::set_level
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::set_path
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &fmt, const Args&... args)
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &fmt, const std::vector<std::string> &args)
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::log(Level level, const std::string &msg)
```

```{eval-rst}
.. doxygenfunction:: LIEF::logging::reset
```

```{eval-rst}
.. doxygenenum:: LIEF::logging::Level
```

```{eval-rst}
.. doxygenclass:: LIEF::logging::Scoped
```

## Example

{{ literalinclude("../../../code/cpp/logging.cpp", "example") }}

### Python

```{eval-rst}
.. autofunction:: lief.logging.set_level
```

```{eval-rst}
.. autofunction:: lief.logging.enable
```

```{eval-rst}
.. autofunction:: lief.logging.disable
```

```{eval-rst}
.. autofunction:: lief.logging.set_path
```

```{eval-rst}
.. autofunction:: lief.logging.log
```

```{eval-rst}
.. autofunction:: lief.logging.level_scope
```

```{eval-rst}
.. autoclass:: lief.logging.Scoped
  :members:
```

```{eval-rst}
.. autoclass:: lief.logging.Level
```

## Example

{{ literalinclude("../../../code/python/logging.py", "example") }}

### Rust

- {rust:func}`lief::logging::disable`
- {rust:func}`lief::logging::enable`
- {rust:func}`lief::logging::set_level`
- {rust:func}`lief::logging::set_path`
- {rust:func}`lief::logging::log`
- {rust:func}`lief::logging::reset`
- {rust:enum}`lief::logging::Level`
- {rust:struct}`lief::logging::Scoped`

## Example

{{ literalinclude("../../../code/rust/src/logging.rs", "example") }}
