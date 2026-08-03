# {fa}`regular fa-file-code` C++

## {fa}`solid fa-screwdriver-wrench` Utilities

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::is_enabled()
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::platform()
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::arch()
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::modules()
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::assemble(uint64_t, const std::string&, assembly::AssemblerConfig&)
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::disassemble(uintptr_t)
```

______________________________________________________________________

## {fa}`solid fa-gears` Process

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Process
```

______________________________________________________________________

## {fa}`solid fa-server` Host

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Host
```

______________________________________________________________________

## {fa}`solid fa-cubes` Module

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Module
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::module_from_name(const std::string &)
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::module_from_path(const std::string &)
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::module_from_addr(uintptr_t)
```

______________________________________________________________________

## {fa}`solid fa-memory` Memory

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Memory
```

______________________________________________________________________

## {fa}`brands fa-linux` Linux

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Linux::Module
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::Linux::dlopen(const std::string &)

```

______________________________________________________________________

### {fa}`solid fa-server` Host

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Linux::Host

```

______________________________________________________________________

### {fa}`solid fa-gears` Process

```{eval-rst}
.. doxygenclass:: LIEF::runtime::Linux::Process

```

______________________________________________________________________

## {fa}`brands fa-android` Android

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. doxygenclass:: LIEF::runtime::android::Module
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::android::dlopen(const std::string &)

```

______________________________________________________________________

### {fa}`solid fa-server` Host

```{eval-rst}
.. doxygenclass:: LIEF::runtime::android::Host

```

______________________________________________________________________

### {fa}`solid fa-gears` Process

```{eval-rst}
.. doxygenclass:: LIEF::runtime::android::Process

```

### {fa}`solid fa-tag` Property

```{eval-rst}
.. doxygenclass:: LIEF::runtime::android::Property

```

______________________________________________________________________

## {fa}`brands fa-apple` OSX

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. doxygenclass:: LIEF::runtime::osx::Module
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::osx::dlopen(const std::string &)
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. doxygenclass:: LIEF::runtime::osx::Host
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. doxygenclass:: LIEF::runtime::osx::Process

```

______________________________________________________________________

## {fa}`brands fa-windows` Windows

### {fa}`solid fa-cubes` Module

```{eval-rst}
.. doxygenclass:: LIEF::runtime::windows::Module
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::windows::dlopen(const std::string &)
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::windows::find_module(const std::string &)
```

### {fa}`solid fa-server` Host

```{eval-rst}
.. doxygenclass:: LIEF::runtime::windows::Host
```

### {fa}`solid fa-syringe` Injector

```{eval-rst}
.. doxygenstruct:: LIEF::runtime::windows::injection_context_t
```

```{eval-rst}
.. doxygenfunction:: LIEF::runtime::windows::inject_spawn(const injection_context_t &)
```

### {fa}`solid fa-gears` Process

```{eval-rst}
.. doxygenclass:: LIEF::runtime::windows::Process
```

### {fa}`solid fa-box` PEB

```{eval-rst}
.. doxygenclass:: LIEF::runtime::windows::PEB
```

### {fa}`solid fa-table-list` LdrDataTableEntry

```{eval-rst}
.. doxygenclass:: LIEF::runtime::windows::LdrDataTableEntry
```

______________________________________________________________________

## {fa}`solid fa-microchip` ARCH

```{eval-rst}
.. doxygenenum:: LIEF::runtime::ARCH
```

## {fa}`solid fa-desktop` PLATFORMS

```{eval-rst}
.. doxygenenum:: LIEF::runtime::PLATFORMS
```
