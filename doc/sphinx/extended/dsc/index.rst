.. _extended-dsc:

:fa:`solid fa-diagram-predecessor` Dyld Shared Cache
-----------------------------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

LIEF's dyld shared cache support allows the inspection and extraction of libraries
from Apple dyld shared cache.

One can load a shared cache using the |lief-dsc-load| function:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        dyld_cache: lief.dsc.DylibSharedCache = lief.dsc.load("macos-15.0.1/")

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/DyldSharedCache.hpp>

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache = LIEF::dsc::load("macos-15.0.1/")

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dyld_cache = lief::dsc::load_from_path("macos-15.0.1/", "");

.. warning::

  |lief-dsc-load| takes as input either a directory for loading the **whole**
  shared cache or a set of files to load a subset of the cache.

From this |lief-dsc-dyldsharedcache| object, we can inspect the embedded
|lief-dsc-dylib| as follows:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        dyld_cache: lief.dsc.DylibSharedCache = ...

        for dylib in dyld_cache.libraries:
            print("0x{:016x}: {}".format(dylib.address, dylib.path))

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;
        for (std::unique_ptr<LIEF::dsc::Dylib> dylib : dyld_cache->libraries()) {
          std::cout << dylib->address() << ' ' << dylib->path() << '\n';
        }

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dyld_cache: lief::dsc::DyldSharedCache;

        for dylib in dyld_cache.libraries() {
            println!("0x{:016x}: {}", dylib.address(), dylib.path());
        }

It is worth mentioning that |lief-dsc-dylib| exposes the |lief-dsc-dylib-get|
method which can be used to **extract** a |lief-macho-binary| instance from a
dyld shared cache libraries:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        dyld_cache: lief.dsc.DylibSharedCache = ...

        liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib")

        macho: lief.MachO.Binary = liblockdown.get()

        for segment in macho.segments:
            print(segment.name)

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;
        std::unique_ptr<Dylib> liblockdown = dyld_cache->find_lib_from_name("liblockdown.dylib");

        std::unique_ptr<LIEF::MachO::Binary> macho = liblockdown.get();
        for (const LIEF::MachO::SegmentCommand& segment : macho->segments()) {
          std::cout << segment.name() << '\n';
        }

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let dyld_cache: lief::dsc::DyldSharedCache;

        let liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib").unwrap();

        let macho = liblockdown.get().unwrap();

        for segment in macho.segments() {
            println!("{}", segment.name());
        }

Finally, we can leverage the |lief-macho-binary-write| function to write back
the |lief-macho-binary| object:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib")

        macho: lief.MachO.Binary = liblockdown.get()
        macho.write("on-disk-liblockdown.dylib")

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;
        std::unique_ptr<Dylib> liblockdown = dyld_cache->find_lib_from_name("liblockdown.dylib");

        std::unique_ptr<LIEF::MachO::Binary> macho = liblockdown.get();
        macho->write("on-disk-liblockdown.dylib");

    .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib").unwrap();
        let macho = liblockdown.get().unwrap();

        macho.write("on-disk-liblockdown.dylib");

.. warning::

  By default, LIEF **does not** remove dyld shared cache optimizations.
  To remove some of these optimizations, you can check the |lief-dsc-dylib-eopt|
  structure.

:fa:`solid fa-stopwatch` Performance Considerations
****************************************************

Dyld shared cache files are pretty large which means that they can't be
processed in the same way as other regular |lief-macho-binary| or
|lief-elf-binary| binaries.

The dyld shared cache support in LIEF follows the principle:
*don't pay overhead for what you don't access*. This is the opposite of the
implementation of |lief-pe-parse|, |lief-macho-parse| and |lief-elf-parse|.

.. note::

  These functions parse all the format structures (with decent performances)
  because:

  1. Most of the binary's sizes are less than gigabytes.
  2. A complete representation is required for modifying binaries.

From a technical perspective, LIEF is using a :cpp:class:`LIEF::FileStream` to
access (on-demand) dyld shared cache structures. Thus, the in-memory consumption
is limited to the size of the structures being accessed. The drawback of this
:cpp:class:`~LIEF::FileStream` is that since this is a file-based access, it takes
more time compared to a :cpp:class:`LIEF::VectorStream`.

Additionally, LIEF's dyld shared cache implementation **heavily** relies on
the iterator pattern to follow the principle: *don't pay overhead for what you don't access*.

For instance, |lief-dsc-dyldsharedcache-libraries| is returning an **iterator**
over the |lief-dsc-dylib|. Therefore, if you don't iterate, you don't pay for the
access and the parsing of the |lief-dsc-dylib| objects.

When it is possible, LIEF implements the trait of a **random access** iterator [1]_
so that we can programmatically do:

.. tabs::

    .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        dyld_cache: lief.dsc.DyldSharedCache = ...

        # No cost
        libraries = cache.libraries

        # O(1) cost
        first_lib = libraries[0]

        # O(len(libraries)) cost
        for lib in libraries:
            print(lib.path)

    .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache;

        // No cost
        auto libraries = dyld_cache.libraries();

        // O(1) cost
        std::unique_ptr<Dylib> first_lib = libraries[0];

        // O(libraries.size()) cost
        for (const auto& dylib : libraries) {
          std::cout << dylib.path() << '\n';
        }

When extracting a |lief-macho-binary| from a |lief-dsc-dylib| object with
|lief-dsc-dylib-get|, **the extraction can a substantial amount of time**,
especially if some deoptimizations are turned on (c.f. |lief-dsc-dylib-eopt|).

For instance, |lief-dsc-dylib-eopt-fix_branches| could require to iterate
over the dyld shared cache's stub islands several times. To improve overall
performances, LIEF provides a cache-based optimization that can be enabled
and configured with:

- |lief-dsc-enable_cache|
- |lief-dsc-dyldsharedcache-enable_caching|

.. admonition:: When you should turn caching on?
  :class: warning

  You can **skip** LIEF's caching if:

  - You don't plan to extract libraries from the shared cache.
  - You plan to extract only one library from the shared cache and **only once**
  - You don't want to have LIEF cache artifacts on your system.

  For all other situations, you should turn on |lief-dsc-enable_cache|.

  **By default, the cache mechanism is not enabled.**

.. [1] https://en.cppreference.com/w/cpp/iterator/random_access_iterator


:fa:`solid fa-book-open-reader` References
*******************************************

- :github-ref:`arandomdev/DyldExtractor`
- :github-ref:`blacktop/ipsw`
- :github-ref:`apple-oss-distributions/dyld`
- https://www.romainthomas.fr/post/24-09-apple-lockdown-dbi-lifting/

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: :rust:module:`lief::dsc`

.. include:: ../../_cross_api.rst

