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

.. _format-elf-section-segment:

Adding a Section/Segment
************************

The ELF format uses two tables to represent the different slices of the binary:

1. The sections table
2. The segments table

While the sections table offers a detailed view of the binary,
it is primarily needed by the **compiler** and the **linker**. In particular,
this table is not required for **loading** and **executing** an ELF file.
The Android loader enforces the existence of a sections table and requires
certain specific sections but from a loading perspective, this table is not used.

If you intend to modify an ELF file to load additional content into memory
(such as code or data), it is recommended to add a |lief-elf-segment| instead of
a section:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        segment = lief.ELF.Segment()
        segment.type = lief.ELF.Segment.TYPES.LOAD
        segment.content = list(b'Hello World')

        new_segment: lief.ELF.Segment = elf.add(segment)

        elf.write("new.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;

        LIEF::ELF::Segment segment;
        segment.type(LIEF::ELF::Segment::TYPES::LOAD);
        segment.content({1, 2, 3});

        LIEF::ELF::Segment* new_segment = elf.add(segment);
        elf.write("new.elf");

You can also achieve this modification by creating a |lief-elf-section| that will
**implicitly** create an associated ``PT_LOAD`` segment:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        section = lief.ELF.Section(".lief_demo")
        section.content = list(b'Hello World')

        new_section: lief.ELF.Section = elf.add(section, loaded=True)

        elf.write("new.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;

        LIEF::ELF::Section section(".lief_demo");
        section.content({1, 2, 3});

        LIEF::ELF::Section* new_section = elf.add(section, /*loaded=*/true);
        elf.write("new.elf");

As mentioned above, the segments table matters from a loading perspective over
the sections table. Therefore, it makes more sense to explicitly add a new
segment rather than adding a section that implicitly adds a segment.

On the other hand, for debugging purposes or specific
tools, one might want to add a **non-loaded** section. In this case, the data
of the section is inserted at the end of the binary right after all the data wrapped
by the segments:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        section = lief.ELF.Section(".metadata")
        section.content = list(b'version: 1.2.3')

        # /!\ Note that loaded is set to False here
        # ------------------------------------------
        new_section: lief.ELF.Section = elf.add(section, loaded=False)

        elf.write("new.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;

        LIEF::ELF::Section section(".metadata");
        section.content({1, 2, 3});

        LIEF::ELF::Section* new_section = elf.add(section, /*loaded=*/false);
        elf.write("new.elf");

See: |lief-elf-binary-add| for the details about the API

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
