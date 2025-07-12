.. _tools-lief-patchelf:

:fa:`solid fa-screwdriver-wrench` lief-patchelf
-----------------------------------------------

``lief-patchelf`` is an implementation of the original patchelf created by NixOS
(`NixOS/patchelf <https://github.com/NixOS/patchelf>`_), based on the LIEF

This LIEF-based version is written in Rust, offering a more robust, modern, and
maintainable implementation compared to the original project.

.. admonition:: CLI
  :class: tip

  It is worth mentioning that ``lief-patchelf`` maintains the same command-line
  interface as the original NixOS implementation, allowing for a seamless transition
  between the two versions.

Compilation
~~~~~~~~~~~

You can build ``lief-patchelf`` using ``cargo`` from the
``src/tools/lief-patchelf`` directory with the following commands:

.. code-block:: bash

   $ cargo build [--release]
   $ ./target/{release,debug}/lief-patchelf --version

Since LIEF is a cross-platform library that supports various platforms and
architectures, you can compile (or cross-compile) this tool for other platforms.
For example, you can generate a Windows ARM64 executable as follows:

.. code-block:: powershell

  rustup.exe target add $RUST_TARGET (optional)
  $env:RUSTFLAGS="-Ctarget-feature=+crt-static"
  cargo build --target=aarch64-pc-windows-msvc
  ./target/{release,debug}/lief-patchelf.exe --version

For more information about the supported platforms, please refer to the
:ref:`Rust Bindings <lief_rust_bindings>` section

Man Page
~~~~~~~~

Given the ``lief-patchelf`` binary, you can generate a man page with the
following command:

.. code-block:: bash

   $ lief-patchelf --generate-manpage ./lief-patchelf.1


This support is provided by the crate `clap_mangen <https://crates.io/crates/clap_mangen>`_

Shell Completion
~~~~~~~~~~~~~~~~

Thanks to `clap <https://github.com/clap-rs/clap>`_ and its ``clap_complete`` extension to
generate auto-completion in various shells, you can generate completion stubs for
``lief-patchelf`` with:

.. code-block:: bash

   $ ./lief-patchelf --generate {bash, elvish, fish, powershell, zsh}

