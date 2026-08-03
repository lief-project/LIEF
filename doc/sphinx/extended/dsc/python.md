# {fa}`brands fa-python` Python

```{eval-rst}
.. autofunction:: lief.dsc.load
```

## Cache Processing

:::{warning}
If you aim at extracting several libraries from a dyld shared cache, it is
**highly** recommended to enable caching. Otherwise, performances can be
impacted.
:::

```{eval-rst}
.. autofunction:: lief.dsc.enable_cache
```

## DyldSharedCache

```{eval-rst}
.. autoclass:: lief.dsc.DyldSharedCache

```

## Dylib

```{eval-rst}
.. autoclass:: lief.dsc.Dylib
```

## MappingInfo

```{eval-rst}
.. autoclass:: lief.dsc.MappingInfo
```

## SubCache

```{eval-rst}
.. autoclass:: lief.dsc.SubCache
```

## Utilities

```{eval-rst}
.. autofunction:: lief.is_shared_cache
```
