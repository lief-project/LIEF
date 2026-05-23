.. _lief_rust_bindings:

:fa:`brands fa-rust` Rust
======================================

.. note::

  The API is documented here |lief-rust-doc| and the nightly doc is
  here: |lief-rust-doc-nightly|.

.. code-block:: toml

  [package]
  name    = "my-awesome-project"
  version = "0.0.1"
  edition = "2024"

  [dependencies]
  lief = { git = "https://github.com/lief-project/LIEF", branch = "main" }


.. warning::

   LIEF rust bindings are not on ``docs.rs`` because of network restrictions:
   https://github.com/rust-lang/docs.rs/issues/2563


Precompiled FFI Bindings
~~~~~~~~~~~~~~~~~~~~~~~~

LIEF's Rust bindings are split into two parts:

1. ``lief``: the high-level, idiomatic Rust API.
2. ``lief-ffi``: the low-level FFI API based on `cxx <https://cxx.rs/>`_.

Two additional crates support the build process:

* ``lief-build``: build-script helper used by ``lief-ffi`` to fetch the
  pre-compiled artifacts and emit the ``cargo`` link directives.
* ``lief-ffigen``: standalone CLI that generates the C++ side of the
  ``cxx`` bridge from the ``#[cxx::bridge]`` modules declared in
  ``lief-ffi``.

Building ``lief-ffi`` requires generating the C++ bridge files with
``lief-ffigen`` and then compiling them alongside ``libLIEF``. Both steps
can take several minutes.

To save time, LIEF provides pre-compiled versions of these artifacts, which
are downloaded from GitHub (for releases) or an S3 bucket (for nightly
builds).

.. _lief-rust-precompiled:

``LIEF_RUST_PRECOMPILED``
--------------------------

If you need to avoid downloading these pre-compiled files, set
``LIEF_RUST_PRECOMPILED`` to point to the directory that contains these files:

.. code-block:: text

  /home/romain/out
  └── lib
      ├── libLIEF.a
      └── liblief-sys.a

  1 directory, 2 files

  LIEF_RUST_PRECOMPILED=/home/romain/out cargo build [...]

This variable can also be used when building in **offline** mode
(e.g., ``cargo --offline``).

As of now, the following targets are supported with pre-compilation:

+---------------------------------+--------------------------------------------------------+
| Target                          | Description                                            |
+=================================+========================================================+
| ``x86_64-unknown-linux-gnu``    | Regular Linux x86-64 (Ubuntu 19.10, Debian 10, ...)    |
+---------------------------------+--------------------------------------------------------+
| ``i686-unknown-linux-gnu``      | Regular Linux i686 (Ubuntu 19.10, Debian 10, ...)      |
+---------------------------------+--------------------------------------------------------+
| ``x86_64-unknown-linux-musl``   | Musl target that allows full static build              |
+---------------------------------+--------------------------------------------------------+
| ``i686-unknown-linux-musl``     | Linux i686 with Musl                                   |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-unknown-linux-gnu``   | Linux aarch64 (Debian 12+)                             |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-unknown-linux-musl``  | Linux aarch64 with Musl                                |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-linux-android``       | Android aarch64 (API 30+)                              |
+---------------------------------+--------------------------------------------------------+
| ``x86_64-linux-android``        | Android x86_64 (API 30+)                               |
+---------------------------------+--------------------------------------------------------+
| ``x86_64-apple-darwin``         | macOS 11+ x86-64                                       |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-apple-darwin``        | macOS 11+ arm64 (Apple Silicon)                        |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-apple-ios``           | iOS 12+                                                |
+---------------------------------+--------------------------------------------------------+
| ``x86_64-pc-windows-msvc[MT]``  | Regular Windows x86-64 (static UCRT runtime)           |
+---------------------------------+--------------------------------------------------------+
| ``x86_64-pc-windows-msvc[MD]``  | Regular Windows x86-64 (dynamic UCRT runtime ``.dll``) |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-pc-windows-msvc[MT]`` | Regular Windows arm64 (static UCRT runtime)            |
+---------------------------------+--------------------------------------------------------+
| ``aarch64-pc-windows-msvc[MD]`` | Regular Windows arm64 (dynamic UCRT runtime ``.dll``)  |
+---------------------------------+--------------------------------------------------------+

Precompilation
--------------

The assets of the pre-compiled output are:

1. LIEF static library: ``LIEF.{a,lib}``
2. ``liefsys.{a,lib}``: bridge between C++ and Rust

The LIEF static library must be compiled as described in the
:ref:`compilation_ref` section using the CMake option: ``-DLIEF_RUST_API=ON``.

``liefsys.{a,lib}`` is built in two steps. First, generate the C++ bridge
files with ``lief-ffigen``:

.. code-block:: console

  $ cargo build [--profile release] -p lief-ffigen
  $ target/{release,debug}/lief-ffigen \
      --output-dir cxx-bridge/         \
      --source-dir lief-ffi/

Then compile them as a regular CMake-based library:

.. code-block:: console

  $ cmake -GNinja                            \
      -S api/rust/cmake-ffi/                 \
      -B cxx-bridge-build/                   \
      -DLIEF_DIR=$INSTALL_DIR/lib/cmake/LIEF \
      -DLIEF_RUST_FFI_SRC=cxx-bridge/        \
      -DCMAKE_INSTALL_PREFIX=cxx-bridge-out/

  $ ninja -C cxx-bridge-build/
