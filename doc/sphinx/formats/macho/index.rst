.. _format-macho:

:fa:`brands fa-apple`  Mach-O
------------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

Mach-O binaries can be parsed with LIEF using the |lief-macho-parse| function.

.. note::

  The Mach-O format defines the notion of FAT binaries which can embed different
  architectures into a single file. |lief-macho-parse| always returns a
  |lief-macho-fatbinary| with the assumption that a non-fat Mach-O can be
  represented as a |lief-macho-fatbinary| with **one** architecture.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        # Using filepath
        macho: lief.MachO.FatBinary = lief.MachO.parse("/bin/ls")

        # Using a Path from pathlib
        macho: lief.MachO.FatBinary = lief.MachO.parse(pathlib.Path(r"C:\Users\test.macho"))

        # Using a io object
        with open("/bin/ssh", 'rb') as f:
          macho: lief.MachO.FatBinary = lief.MachO.parse(f)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/MachO.hpp>

        // Using a file path as a std::string
        std::unique_ptr<LIEF::MachO::FatBinary> macho = LIEF::MachO::Parser::parse("/bin/ls");

        // Using a vector
        std::vector<uint8_t> my_raw_macho;
        std::unique_ptr<LIEF::MachO::FatBinary> macho = LIEF::MachO::Parser::parse(my_raw_macho);

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let macho: lief::macho::FatBinary = lief::macho::FatBinary::parse("/bin/ls");


This |lief-macho-fatbinary| object exposes facilities to either iterate over the
different |lief-macho-binary| or pick/take a specific one:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        fat: lief.MachO.FatBinary

        # Iterate
        for macho in fat:
            print(macho.entrypoint)
            print(len(macho.commands))

        # Pick one at the specified index
        macho: lief.MachO.Binary = fat.at(0)

        # Pick one based on the architecture
        macho: lief.MachO.Binary = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::FatBinary> fat;

        // Iterate
        for (const LIEF::MachO::Binary& macho : *fat) {
          std::cout << macho.entrypoint() << '\n';
          std::cout << macho.commands().size() << '\n';
        }

        // Pick one at the specified index (without take the ownership)
        const LIEF::MachO::Binary* macho = fat->at(0);

        // Pick one at the specified index and take the ownership
        const LIEF::MachO::Binary* macho = fat->take(0);

        // Pick one with the given arch and take the ownership
        const LIEF::MachO::Binary* macho = fat->take(LIEF::MachO::Header::CPU_TYPE::ARM64);

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let fat: lief::macho::FatBinary;

        // Iterate
        for macho in fat {
            println!("{}", macho.entrypoint());
        }

Upon a |lief-macho-binary| or |lief-macho-fatbinary| modification, one can use
either |lief-macho-binary-write| or |lief-macho-fatbinary-write| to write back
the (FAT) MachO binary object into a raw MachO file.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho: lief.MachO.FatBinary = ...

        macho.at(0).write("fit.macho")
        macho.write("fat.macho") # write-back the whole FAT binary

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::FatBinary> macho;

        macho->at(LIEF::MachO::Header::CPU_TYPE::ARM64)->write("fit.macho");
        macho->write("fat.macho");

You can also use |lief-macho-binary-write_to_bytes| to get the new MachO binary
as a buffer of bytes:

.. note::

   This API can also take an extra |lief-macho-builder-config| parameter

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho: lief.MachO.Binary = ...
        new_macho: bytes = macho.write_to_bytes()

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::Binary> macho;

        std::ostringstream os;
        macho->write(os);
        std::string buffer = os.str();

        const auto* start = reinterpret_cast<const uint8_t>(buffer.data());
        size_t size = buffer.size();


Advance Parsing/Writing
***********************

|lief-macho-parse| can take an extra |lief-macho-parser-config| parameter to specify
some parts of the MachO format to skip during parsing.

.. warning::

   Generally speaking, |lief-macho-binary-write| and |lief-macho-fatbinary-write|
   require a **complete** initial parsing of the MachO file.

Similarly, |lief-macho-binary-write| can also take an extra |lief-macho-builder-config|
to specify which parts of the MachO should be re-built or not.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        parser_config = lief.MachO.ParserConfig()
        parser_config.parse_dyld_bindings = False

        macho: lief.MachO.FatBinary = lief.MachO.parse("my.macho", parser_config)

        builder_config = lief.MachO.Builder.config_t()
        builder_config.linkedit = False

        macho.write("new.macho", builder_config)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        LIEF::MachO::ParserConfig parser_config;
        parser_config.parse_dyld_bindings = false;

        auto macho = LIEF::MachO::Parser::parse("my.macho", parser_config);
        LIEF::MachO::Builder::config_t builder_config;

        builder_config.linkedit = false;
        macho->write("new.macho", builder_config);

.. seealso::

  :ref:`binary-abstraction`

.. _format-macho-rpath:

RPath and Library Path Modification
***********************************

Sometimes, we need to modify the Mach-O rpath commands or the (absolute) path of
a linked library in an executable. When recompiling or linking the executable
is not possible, LIEF can be used for these modifications.

For instance, let's consider a binary with the following dependencies:

.. code-block:: bash

  $ otool -L hello.bin
  hello:
        /Users/romain/dev/libmylib.dylib (compatibility version 0.0.0, current version 0.0.0)
        /usr/lib/libc++.1.dylib (compatibility version 1.0.0, current version 1700.255.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.100.2)

One can change the directory of ``libmylib.dylib`` with the following code:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho = lief.MachO.parse("hello.bin")
        lib: lief.MachO.DylibCommand = macho.find_library("libmylib.dylib")
        lib.name = "/opt/hombrew/my_package/libmylib.dylib"

        macho.write("hello_fixed.bin")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::Binary> macho = LIEF::MachO::Parser::parse("hello.bin").take(0);
        LIEF::MachO::DylibCommand* lib = macho->find_library("libmylib.dylib");
        lib->name("/opt/hombrew/my_package/libmylib.dylib");

        macho->write("hello_fixed.bin");

.. note::

   It is worth mentioning that LIEF does not have restrictions on the length of
   the modified library path. LIEF manages all the internal modifications to
   support both longer and shorter library paths.


This kind of modification can be used in pair with the ``@rpath`` feature of
Mach-O binaries:

1. We can add an extra ``LC_RPATH`` (|lief-macho-rpath|) command to ``hello.bin``:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho = lief.MachO.parse("hello.bin")
        rpath = lief.MachO.RPathCommand.create("/opt/hombrew/my_package")
        macho.add(rpath)

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::Binary> macho = LIEF::MachO::Parser::parse("hello.bin").take(0);
        auto rpath = LIEF::MachO::RPathCommand::create("/opt/hombrew/my_package");
        macho->add(*rpath);

2. Then, we can change the library path of ``libmylib.dylib`` to include the rpath prefix:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        lib: lief.MachO.DylibCommand = macho.find_library("libmylib.dylib")
        lib.name = "@rpath/libmylib.dylib"

        macho.write("hello_fixed.bin")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        LIEF::MachO::DylibCommand* lib = macho->find_library("libmylib.dylib");
        lib->name("@rpath/libmylib.dylib");

        macho->write("hello_fixed.bin");

Objective-C Support
********************

If a Mach-O binary is compiled from Objetive-C sources, it could contain
metadata which are represented by the |lief-objc-metadata| object.

This metadata can help understand the underlying structures of the binary and
:ref:`LIEF extended <extended-intro>` provides the support for accessing this
information through: |lief-macho-binary-objc-metadata|.

For more details, you can check the :ref:`Obj-C section <extended-objc>`.

.. include:: ../../_cross_api.rst
