.. _format-pe:

:fa:`brands fa-windows`  PE
----------------------------

.. toctree::
  :caption: <i class="fa-solid fa-code">&nbsp;</i>API
  :maxdepth: 1

  cpp
  python
  rust

----

Introduction
************

PE binaries can be parsed with LIEF using the |lief-pe-parse| function.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import lief

        # Using filepath
        pe: lief.PE.Binary = lief.PE.parse(r"C:\Users\test.exe")

        # Using a Path from pathlib
        pe: lief.PE.Binary = lief.PE.parse(pathlib.Path(r"C:\Users\test.exe"))

        # Using an io object
        with open(r"C:\Users\test.exe", 'rb') as f:
          pe: lief.PE.Binary = lief.PE.parse(f)


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        #include <LIEF/PE.hpp>

        // Using a file path as a std::string
        std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse("some.exe");

        // Using a vector
        std::vector<uint8_t> my_raw_pe;
        std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(my_raw_pe);

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let pe: lief::pe::Binary = lief::pe::Binary::parse("/bin/ls");

.. note::

  In Python, you can also use :py:func:`lief.parse` which returns a
  :class:`lief.PE.Binary` object.

From this parsed PE binary you can use all the API exposed by the |lief-pe-binary|
object to inspect or modify the binary itself.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        pe: lief.PE.Binary = ...

        print(pe.rich_header)
        print(pe.authentihash_md5.hex(':'))

        for section in pe.sections:
            print(section.name, len(section.content))


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::PE::Binary> pe;

        if (const LIEF::PE::RichHeader* rich = pe->rich_header()) {
          std::cout << *rich << '\n';
        }

        for (const LIEF::PE::Section& section : pe->sections()) {
          std::cout << section.name() << section.content().size() << '\n'
        }

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let pe: lief::pe::Binary;

        println!("{:?}", pe.rich_header().expect("Missing Rich header"));

        for section in pe.sections() {
            println!("{} {}", section.name(), section.content().len());
        }

Upon a |lief-pe-binary| modification, one can use the method
|lief-pe-binary-write| to write back the PE binary object into a raw PE
file.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        pe: lief.PE.Binary = ...

        section = lief.PE.Section(".hello")
        section.content = [0xCC] * 0x100
        pe.add_section(section)

        pe.write("new.exe")


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::PE::Binary> pe;

        LIEF::PE::Section section(".hello");
        section.content = std::vector<uint8_t>(0x100, 0xCC);
        pe->add_section(section);

        pe->write("new.exe");

.. seealso::

  :ref:`binary-abstraction`

Advance Parsing/Writing
***********************

|lief-pe-parse| can take an extra |lief-pe-parser-config| parameter to specify
some parts of the ELF format to skip during parsing.

.. warning::

   Generally speaking, |lief-pe-binary-write| requires a **complete** initial
   parsing of the PE file.

Similarly, |lief-pe-builder| can be configured to avoid reconstructing
some parts of the PE binary

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        parser_config = lief.PE.ParserConfig()
        parser_config.parse_signature = False

        pe: lief.PE.Binary = lief.PE.parse("some.exe", parser_config)

        builder = lief.PE.Builder(pe)
        builder.build_imports(False)
        builder.patch_imports(False)

        builder.build()
        builder.write("new.exe")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        LIEF::PE::ParserConfig parser_config;
        parser_config.parse_signature = false;

        auto pe = LIEF::PE::Parser::parse("some.exe", parser_config);
        LIEF::PE::Builder builder(*pe);

        builder.build_imports(false);
        builder.patch_imports(false);

        builder.build();
        builder.write("new.exe");

Accessing PDB
*************

Using :ref:`LIEF Extended <extended-intro>`, one can access PDB debug info
(|lief-pdb-debug-info|) using the function: |lief-pdb-binary-debug-info|.

For more the details about the PDB support, please check the :ref:`PDB section <extended-pdb>`.

Authenticode
************

LIEF supports PE authenticode by providing API to inspect and **verify** the
signature of PE executables.

One can access PE authenticode signature(s) by iterating over the |lief-pe-binary-signatures|.
The |lief-pe-binary-verify_signature| function can be used to verify that
a PE binary is correctly signed.

.. note::

   Usually, a signed PE executable embeds only one signature but the format does
   not limit the number of signature. Thus, |lief-pe-binary-signatures| returns
   an iterator and not only one signature object.

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        import

        pe = lief.PE.parse("signed.exe")
        for signature in pe.signatures:
            for crt in signature.certificates:
              print(crt)

        assert pe.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        auto pe = LIEF::PE::Parser::parse("signed.exe");

        for (const LIEF::PE::Signature& sig : pe->signatures()) {
          for (const LIEF::PE::X509& crt : sig.certificates()) {
            std::cout << crt << '\n';
          }
        }

        std::cout << pe->verify_signature() == LIEF::PE::Signature::VERIFICATION_FLAGS::OK;

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        if let Some(lief::Binary::PE(pe)) = lief::Binary::parse("signed.exe") {
            for sig in pe.signatures() {
                for crt in sig.certificates() {
                    println("{:?}", crt);
                }
            }

            assert!(
              pe.verify_signature(pe::signature::VerificationChecks::DEFAULT) ==
              lief::pe::signature::VerificationFlags::OK
            );
        }

You can find additional details about the authenticode support in this tutorial:
:ref:`PE Authenticode <pe-authenticode>`

.. include:: ../../_cross_api.rst
