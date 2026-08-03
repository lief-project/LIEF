# {fa}`brands fa-python` Python

:::{admonition} Python `void*`
:class: warning

The Python bindings manage opaque `void*` pointers as
[Capsules](https://docs.python.org/3/c-api/capsule.html#capsules).
Given a Capsule, there is no easy way to convert it into a raw address and vice
versa.
To address this limitation, LIEF exposes {py:func}`lief.to_int` and {py:func}`lief.to_ptr`
to convert back and forth between raw addresses and pointers.
:::

## {fa}`solid fa-screwdriver-wrench` Utilities

```{eval-rst}
.. autofunction:: lief.to_int
```

```{eval-rst}
.. autofunction:: lief.to_ptr
```

```{eval-rst}
.. autoattribute:: lief.runtime.enabled
```

```{eval-rst}
.. autoattribute:: lief.runtime.platform
```

```{eval-rst}
.. autoattribute:: lief.runtime.arch
```

```{eval-rst}
.. autofunction:: lief.runtime.modules
```

```{eval-rst}
.. autofunction:: lief.runtime.assemble
```

```{eval-rst}
.. autofunction:: lief.runtime.disassemble
```

______________________________________________________________________

## {fa}`solid fa-server` Host

```{eval-rst}
.. autoclass:: lief.runtime.Host
```

______________________________________________________________________

## {fa}`solid fa-gears` Process

```{eval-rst}
.. autoclass:: lief.runtime.Process
```

______________________________________________________________________

## {fa}`solid fa-cubes` Module

```{eval-rst}
.. autoclass:: lief.runtime.Module
```

```{eval-rst}
.. autofunction:: lief.runtime.module_from_name
```

```{eval-rst}
.. autofunction:: lief.runtime.module_from_path
```

```{eval-rst}
.. autofunction:: lief.runtime.module_from_addr
```

______________________________________________________________________

## {fa}`solid fa-memory` Memory

```{eval-rst}
.. autoclass:: lief.runtime.Memory
```

______________________________________________________________________

## {fa}`brands fa-linux` Linux

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. autoclass:: lief.runtime.linux.Module
```

```{eval-rst}
.. autofunction:: lief.runtime.linux.dlopen
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. autoclass:: lief.runtime.linux.Host
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. autoclass:: lief.runtime.linux.Process

```

______________________________________________________________________

## {fa}`brands fa-android` Android

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. autoclass:: lief.runtime.android.Module
```

```{eval-rst}
.. autofunction:: lief.runtime.android.dlopen
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. autoclass:: lief.runtime.android.Host
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. autoclass:: lief.runtime.android.Process
```

### {fa}`solid fa-tag` Property

```{eval-rst}
.. autoclass:: lief.runtime.android.Property
```

______________________________________________________________________

## {fa}`brands fa-apple` OSX

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. autoclass:: lief.runtime.osx.Module
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. autoclass:: lief.runtime.osx.Host
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. autoclass:: lief.runtime.osx.Process
```

______________________________________________________________________

## {fa}`brands fa-windows` Windows

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. autoclass:: lief.runtime.windows.Module
```

```{eval-rst}
.. autofunction:: lief.runtime.windows.dlopen
```

```{eval-rst}
.. autofunction:: lief.runtime.windows.find_module
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. autoclass:: lief.runtime.windows.Host
```

### {fa}`solid fa-syringe` Injector

```{eval-rst}
.. autoclass:: lief.runtime.windows.injection_context_t
```

```{eval-rst}
.. autofunction:: lief.runtime.windows.inject_spawn
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. autoclass:: lief.runtime.windows.Process
```

### {fa}`solid fa-box` PEB

```{eval-rst}
.. autoclass:: lief.runtime.windows.PEB
```

### {fa}`solid fa-table-list` LdrDataTableEntry

```{eval-rst}
.. autoclass:: lief.runtime.windows.LdrDataTableEntry
```

______________________________________________________________________

## {fa}`solid fa-microchip` ARCH

```{eval-rst}
.. autoclass:: lief.runtime.ARCH
```

## {fa}`solid fa-desktop` PLATFORMS

```{eval-rst}
.. autoclass:: lief.runtime.PLATFORMS
```
