.. _format-elf:

:fa:`brands fa-linux` ELF
---------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

ELF binaries can be parsed with LIEF using the |lief-elf-parse| function:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        # Using filepath
        elf: lief.ELF.Binary = lief.ELF.parse("/bin/ls")

        # Using a Path from pathlib
        elf: lief.ELF.Binary = lief.ELF.parse(pathlib.Path(r"C:\Users\test.elf"))

        # Using a io object
        with open("/bin/ssh", 'rb') as f:
          elf: lief.ELF.Binary = lief.ELF.parse(f)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/ELF.hpp>

        // Using a file path as a std::string
        std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse("/bin/ls");

        // Using a vector
        std::vector<uint8_t> my_raw_elf;
        std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(my_raw_elf);

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let elf: lief::elf::Binary = lief::elf::Binary::parse("/bin/ls");

.. note::

  In Python, you can also use :py:func:`lief.parse` which returns a
  :class:`lief.ELF.Binary` object.

From this parsed ELF binary you can use all the API exposed by the |lief-elf-binary|
object to inspect or modify the binary itself.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        print(elf.header.entrypoint)

        for section in elf.sections:
            print(section.name, len(section.content))


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;

        std::cout << elf->header().entrypoint();

        for (const LIEF::ELF::Section& section : elf->sections()) {
          std::cout << section.name() << section.content().size() << '\n'
        }

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let elf: lief::elf::Binary;

        println!("{}", elf.header().entrypoint());

        for section in elf.sections() {
            println!("{} {}", section.name(), section.content().len());
        }

Upon a |lief-elf-binary| modification, one can use the method
|lief-elf-binary-write| to write back the ELF binary object into a raw ELF
file.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        elf.add_library("libdemo.so")
        elf.write("new.elf")


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;
        elf->add_library("libdemo.so");
        elf->write("new.elf");

.. seealso::

  :ref:`binary-abstraction`

Advance Parsing/Writing
***********************

|lief-elf-parse| can take an extra |lief-elf-parser-config| parameter to specify
some parts of the ELF format to skip during parsing.

.. warning::

   Generally speaking, |lief-elf-binary-write| requires a **complete** initial
   parsing of the ELF file.

Similarly, |lief-elf-binary-write| can also take an extra |lief-elf-builder-config|
to specify which parts of the ELF should be re-built or not.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        parser_config = lief.ELF.ParserConfig()
        parser_config.parse_overlay = False

        elf: lief.ELF.Binary = lief.ELF.parse("my.elf", parser_config)

        builder_config = lief.ELF.Builder.config_t()
        builder_config.gnu_hash = False

        elf.write("new.elf", builder_config)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        LIEF::ELF::ParserConfig parser_config;
        parser_config.parse_overlay = false;

        auto elf = LIEF::ELF::Parser::parse("my.elf", parser_config);
        LIEF::ELF::Builder::config_t builder_config;

        builder_config.gnu_hash = false;
        elf->write("new.elf", builder_config);

DWARF Support
*************

If the binary embeds DWARF debug info, one can use |lief-dwarf-binary-debug-info|
to access the underlying |lief-dwarf-debug-info| object.

Note that this support is only available in the :ref:`extended <extended-intro>`
version of LIEF.

.. include:: ../../_cross_api.rst
