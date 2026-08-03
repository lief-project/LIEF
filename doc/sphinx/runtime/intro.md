(runtime-intro)=

# {fa}`solid fa-wand-magic-sparkles` Runtime

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-gears">&nbsp;</i>Components
  :maxdepth: 1

  components/host
  components/process
  components/memory
  components/modules
```

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust
```

## Introduction

LIEF's runtime module provides facilities to inspect and interact with the
current process in which the API is used. You can, for instance, list
modules loaded in memory or read the content at a specific memory address.

These runtime features are **not** enabled by default and must be explicitly
turned on when compiling LIEF.

When using CMake, you must enable the `LIEF_RUNTIME` option (`-DLIEF_RUNTIME=ON`)
followed by the target platform and the architecture for which you want to use
the runtime API:

```console
$ cmake [...]                     \
  -DLIEF_RUNTIME=ON               \
  -DLIEF_RUNTIME_PLATFORM=windows \
  -DLIEF_RUNTIME_ARCH=arm64
```

:::{note}
Only `arm64`, `x86_64` and `riscv64` are currently supported for
`LIEF_RUNTIME_ARCH`. The supported values for `LIEF_RUNTIME_PLATFORM`
are `linux`, `windows`, `android` and `osx`.
:::

To compile the Python bindings with the runtime features,
you must enable the `lief.features.runtime` option and specify the
target platform and architecture within the `[lief.runtime]` block:

```{code-block} toml
:emphasize-lines: 20,22-24

[lief.build]
type          = "Release"
cache         = true
ninja         = true
parallel-jobs = 0

[lief.formats]
elf     = true
pe      = true
macho   = true
android = true
art     = true
vdex    = true
oat     = true
dex     = true

[lief.features]
json    = true
frozen  = true
runtime = true

[lief.runtime]
platform = 'linux'
architecture = 'x86_64'
```

The runtime features are split in the following components:

```{eval-rst}
.. toctree::
  :caption: <i class="fa-solid fa-gears">&nbsp;</i>Components
  :maxdepth: 1

  components/host
  components/process
  components/memory
  components/modules
```
