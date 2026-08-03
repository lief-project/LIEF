# {fa}`regular fa-file-code` C++

:::{note}
You can also find the Doxygen documentation here: [here](../../doxygen/)
:::

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::load(const std::string &path, const std::string &arch = "")
```

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::load(const std::vector<std::string> &files)
```

## Cache Processing

:::{warning}
If you aim at extracting several libraries from a dyld shared cache, it is
**highly** recommended to enable caching. Otherwise, performances can be
impacted.
:::

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::enable_cache()
```

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::enable_cache(const std::string &dir)

```

## DyldSharedCache

```{eval-rst}
.. doxygenclass:: LIEF::dsc::DyldSharedCache

```

## Dylib

```{eval-rst}
.. doxygenclass:: LIEF::dsc::Dylib

```

## MappingInfo

```{eval-rst}
.. doxygenclass:: LIEF::dsc::MappingInfo

```

## SubCache

```{eval-rst}
.. doxygenclass:: LIEF::dsc::SubCache

```

## Utilities

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::is_shared_cache(BinaryStream&)
```

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::is_shared_cache(const std::vector< uint8_t > &)
```

```{eval-rst}
.. doxygenfunction:: LIEF::dsc::is_shared_cache(const uint8_t *, size_t)
```
