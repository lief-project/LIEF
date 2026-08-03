(debug-info)=

# {fa}`solid fa-magnifying-glass` Debug Info

{ref}`PDB <extended-pdb>` and {ref}`DWARF <extended-dwarf>` share similar
traits which are abstracted by the following classes:

## {fa}`regular fa-file-code` C++

### DebugInfo

```{eval-rst}
.. doxygenclass:: LIEF::DebugInfo
```

### debug_location_t

```{eval-rst}
.. doxygenstruct:: LIEF::debug_location_t
```

### DeclOpt

```{eval-rst}
.. doxygenclass:: LIEF::DeclOpt
```

______________________________________________________________________

## {fa}`brands fa-python` Python

### DebugInfo

```{eval-rst}
.. autoclass:: lief.DebugInfo

```

### debug_location_t

```{eval-rst}
.. autoclass:: lief.debug_location_t
```

### DeclOpt

```{eval-rst}
.. autoclass:: lief.DeclOpt
```

______________________________________________________________________

## {fa}`brands fa-rust` Rust

- {rust:trait}`lief::generic::DebugInfo`
- {rust:struct}`lief::DebugLocation`
- {rust:struct}`lief::DeclOpt`
