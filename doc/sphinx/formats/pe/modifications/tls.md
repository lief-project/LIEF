# {fa}`solid fa-gears` TLS Modification

:::{figure} ../../../_static/pe_tls/tls.webp
:alt: PE TLS Overview
:scale: 50%
:::

LIEF can be used to **modify**, **create**, or **remove** Thread Local Storage (TLS)
information.

## TLS Modifications

All attributes of the {sub-ref}`lief-pe-tls` interface can be modified as long as the
changes are consistent with the layout of the PE binary. For instance, you
can adjust the TLS callbacks by removing, reordering, or adding addresses:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_tls.py", "modify-callbacks") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_tls.cpp", "modify-callbacks") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_tls.rs", "modify-callbacks") }}
:::
::::

:::{admonition} Relocations
:class: tip

Note that LIEF **automatically** manages the relocations that must be
created or removed when modifying the TLS callbacks.
:::

## TLS Creation

If a PE binary does not contain TLS metadata, LIEF can be used to create this
structure.

First, we can create and initialize a TLS instance:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_tls.py", "create-tls") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_tls.cpp", "create-tls") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_tls.rs", "create-tls") }}
:::
::::

And then, we can add this instance to a {sub-ref}`lief-pe-binary`:

::::{tabs}
:::{tab} {fa}`brands fa-python` Python
{{ literalinclude("../../../../code/python/pe_tls.py", "add-tls") }}
:::
:::{tab} {fa}`regular fa-file-code` C++
{{ literalinclude("../../../../code/cpp/pe_tls.cpp", "add-tls") }}
:::
:::{tab} {fa}`brands fa-rust` Rust
{{ literalinclude("../../../../code/rust/src/pe_tls.rs", "add-tls") }}
:::
::::

:::{admonition} Relocations
:class: tip

Similar to TLS callback modifications, LIEF **automatically** manages
relocations. In addition, it automatically initializes (if not set by the
user) `AddressOfIndex`, which is required when setting up TLS metadata.
:::

{{ cross_api }}
