.. _format-coff:

:fa:`brands fa-windows`  COFF
-----------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

COFF object files can be parsed with using |lief-coff-parse| or the generic
|lief-parse| functions:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        # Using a filepath as a string
        coff: lief.COFF.Binary = lief.COFF.parse("hello.obj")

        # Using a Path from pathlib
        coff: lief.COFF.Binary = lief.COFF.parse(pathlib.Path(r"C:\Users\romain\test.obj"))

        # Using a io object
        with open("/tmp/test.ob", 'rb') as f:
            coff: lief.COFF.Binary = lief.COFF.parse(f)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/COFF.hpp>

        // Using a file path as a std::string
        std::unique_ptr<LIEF::COFF::Binary> coff = LIEF::COFF::Parser::parse("test.obj");


  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let coff: lief::coff::Binary = lief::coff::Binary::parse("test.obj");

These functions return a |lief-coff-Binary| instance that exposes the main API
to process and access COFF information:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        coff: lief.COFF.Binary = ...

        for section in coff.sections:
            print(section.name)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/COFF.hpp>

        std::unique_ptr<LIEF::COFF::Binary> coff;
        for (const LIEF::COFF::Section& section : coff->sections()) {
            std::cout << section.name() << '\n';
        }

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let coff: lief::coff::Binary;

        for section in coff.sections() {
            println!("{section:?} {section}");
        }


.. include:: ../../_cross_api.rst
