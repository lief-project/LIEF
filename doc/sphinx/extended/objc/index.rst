.. _extended-objc:

:fa:`brands fa-apple` Objective-C
---------------------------------

This module allows to inspect Objective-C metadata from a Mach-O binary.

If a Mach-O binary embeds Objective-C metadata, they can be accessed through
:attr:`lief.MachO.Binary.objc_metadata` / :cpp:func:`LIEF::MachO::Binary::objc_metadata`:

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho: lief.MachO.Binary = ...
        metadata: lief.objc.Metadata = macho.objc_metadata
        if metadata is not None:
            print("Objective-C metadata found")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::Binary> macho;
        std::unique_ptr<LIEF::objc::Metadata> metadata = macho->objc_metadata();

        if (metadata != nullptr) {
          std::cout << "Objective metadata found\n";
        }

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let macho: lief::macho::Binary;

        if let Some(metadata) = macho.objc_metadata() {
            println!("Objective-C metadata found");
        }

Then at this point, one can use the API exposed by the class :class:`lief.objc.Metadata`
/ :cpp:class:`LIEF::objc::Metadata` to inspect the Objective-C Metadata.

In particular, the function: :meth:`lief.objc.Metadata.to_decl`/
:cpp:func:`LIEF::objc::Metadata::to_decl` can be used to generate a header-like
output of all the Objective-C metadata found in the binary.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        macho: lief.MachO.Binary = lief.parse("some_macho")
        metadata: lief.objc.Metadata = macho.objc_metadata
        for clazz in metadata.classes:
            print(f"name={clazz.name}")
            for meth in clazz.methods:
                print(f"  method.name={meth.name}")
        print(metadata.to_decl())

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(argv[1]);
        LIEF::MachO::Binary* bin = fat->at(0);

        std::unique_ptr<LIEF::objc::Metadata> metadata = bin->objc_metadata();

        for (const std::unique_ptr<LIEF::objc::Class>& clazz : metadata->classes()) {
          log(LOG_LVL, "name={}", clazz->name());
          for (const std::unique_ptr<LIEF::objc::Method>& meth : clazz->methods()) {
            log(LOG_LVL, "  method.name={}", meth->name());
          }
        }

        log(LOG_LVL, metadata->to_decl());

  .. tab:: :fa:`brands fa-rust` Rust

    .. code-block:: rust

        let Some(lief::Binary::MachO(fat)) = lief::Binary::parse(&path) else { process::exit(1); };
        let Some(bin) = fat.iter().next() else { process::exit(1); };
        let Some(metadata) = bin.objc_metadata() else { process::exit(1); };

        for class in metadata.classes() {
            println!("name={}", class.name());
            for method in class.methods() {
                println!("  method.name={}", method.name());
            }
        }
        println!("{}", metadata.to_decl());


This Objective-C support is based on iCDump which is detailed here:

- https://www.romainthomas.fr/post/23-01-icdump/
- https://github.com/romainthomas/iCDump

----

You can find the documentation of the API for the different languages here:

:fa:`brands fa-python` :doc:`Python API <python>`

:fa:`regular fa-file-code` :doc:`C++ API <cpp>`

:fa:`brands fa-rust` Rust API: |lief-rust-doc-nightly|
