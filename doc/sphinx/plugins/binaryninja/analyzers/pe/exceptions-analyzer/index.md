(plugins-binaryninja-analyzers-exceptions)=

# {fa}`solid fa-object-ungroup` Exceptions

This analyzer improves the representation and underlying data of PE exceptions
metadata, primarily for ARM64 and ARM64EC binaries.

```{eval-rst}
.. img-comparison::
  :left: img/pdata_before.svg
  :right: img/pdata_after.svg
```

```{raw} html
<br />
```

```{eval-rst}
.. img-comparison::
  :left: img/rdata_before.svg
  :right: img/rdata_after.svg
```

Additionally, it defines functions automatically based on the metadata of exceptions.
This results in a more accurate representation of the binary, as illustrated in this feature map:

```{eval-rst}
.. img-comparison::
  :left: img/featmap_before.svg
  :right: img/featmap_after.svg
```

```{eval-rst}
.. seealso::

  See also this blog post: https://lief.re/blog/2025-02-16-arm64ec-pe-support/#binaryninja-arm64ec-support

```

{{ cross_api }}
