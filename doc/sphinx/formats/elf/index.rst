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

You can also use |lief-elf-binary-write_to_bytes| to get the new ELF binary
as a buffer of bytes:

.. note::

   This API can also take an extra |lief-elf-builder-config| parameter

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...
        new_elf: bytes = elf.write_to_bytes()

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf;

        std::ostringstream os;
        elf->write(os);
        std::string buffer = os.str();

        const auto* start = reinterpret_cast<const uint8_t>(buffer.data());
        size_t size = buffer.size();

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

.. _format-elf-rpath-modification:

R[UN]PATH Modification
**********************

LIEF provides all the facilities to manipulate binary's RPATH/RUNPATH.

.. admonition:: DT_RPATH vs DT_RUNPATH
  :class: tip

  ``DT_RPATH`` and ``DT_RUNPATH`` are both dynamic tags that are used to
  specify runtime library search paths.

  The ``DT_RPATH`` is now considered as legacy since it does not respect the
  precedence of the ``LD_LIBRARY_PATH`` environment variable. This means that
  if the ``LD_LIBRARY_PATH`` is set to a valid directory where the library can
  be found, it will be ignored in favor of the ``DT_RPATH`` value.
  Therefore, the ``DT_RUNPATH`` tag should be prefered ``DT_RPATH``.

  Please note that if both tags are present, the loader will use the ``DT_RUNPATH``
  entry over the legacy ``DT_RPATH``.


The ``DT_RPATH`` tag is represented by the |lief-elf-DynamicEntryRpath|
interface and the ``DT_RUNPATH`` tag by |lief-elf-DynamicEntryRunPath|

The RPATH/RUNPATH modifications supported by LIEF include:

**Adding a new entry**

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        runpath = lief.ELF.DynamicEntryRunPath("$ORIGIN:/opt/lib64")

        elf.add(runpath)

        other_runpath = lief.ELF.DynamicEntryRunPath([
          '$ORIGIN', '/opt/lib64'
        ])

        elf.add(other_runpath)

        elf.write("updated.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf = ...;

        LIEF::ELF::DynamicEntryRunPath runpath("$ORIGIN:/opt/lib64");

        elf->add(runpath);

        LIEF::ELF::DynamicEntryRunPath other_runpath(
          std::vector<std::string> {
            "$ORIGIN", "/opt/lib64"
          }
        );

        elf->add(other_runpath);

        elf->write("updated.elf");

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf: lief::elf::Binary = ...

        let runpath = lief::elf::dynamic::RunPath::new("$ORIGIN:/opt/lib64");

        elf.add_dynamic_entry(&runpath);

        let other_runpath = lief::elf::dynamic::RunPath::with_paths(
          &vec!["$ORIGIN", "/opt/lib64"]
        );

        elf.add_dynamic_entry(&other_runpath);

        let output = PathBuf::from("updated.elf");

        elf.write(output.as_path());

**Changing an entry**

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        runpath = elf.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
        assert runpath is not None

        runpath.runpath = "$ORIGIN:/opt/lib64"
        runpath.append("lib-x86_64-gnu")

        elf.write(output.as_path());

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf = ...;

        LIEF::ELF::DynamicEntryRunPath* runpath =
          elf->get(LIEF::ELF::DynamicEntry::TAG::RUNPATH);

        assert(runpath != nullptr);

        runpath->runpath("$ORIGIN:/opt/lib64");
        runpath->append("lib-x86_64-gnu");

        elf->write("updated.elf");

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf: lief::elf::Binary = ...

        if let Some(dynamic::Entries::RunPath(mut runpath)) =
            elf.dynamic_entry_by_tag(dynamic::Tag::RUNPATH)
        {
          runpath.set_runpath("$ORIGIN:/opt/lib64");
          runpath.append("lib-x86_64-gnu");
        }

        let output = PathBuf::from("updated.elf");

        elf.write(output.as_path());

**Removing entries**

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        # Remove **all** DT_RUNPATH entries
        elf.remove(lief.ELF.DynamicEntry.TAG.RUNPATH)

        # Remove all entries that contain '$ORIGIN'
        to_remove: list[lief.ELF.DynamicEntryRunPath] = []
        for dt_entry in elf.dynamic_entries:
            if not isinstance(dt_entry, lief.ELF.DynamicEntryRunPath):
                continue

            if "$ORIGIN" in dt_entry.runpath:
                to_remove.append(dt_entry)

        for entry in to_remove:
            elf.remove(dt_entry)

        elf.write("updated.elf")


  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf = ...;

        // Remove **all** DT_RUNPATH entries
        elf->remove(LIEF::ELF::DynamicEntry::TAG::RUNPATH);

        // Remove all entries that contain '$ORIGIN'
        std::vector<LIEF::ELF::DynamicEntryRunPath*> to_remove;
        for (DynamicEntry& entry : elf->dynamic_entries()) {
          if (auto* dt_entry = entry.cast<LIEF::ELF::DynamicEntryRunPath>()) {
            if (dt_entry->runpath().find("$ORIGIN") != std::string::npos) {
              to_remove.push_back(dt_entry);
            }
          }
        }

        for (LIEF::ELF::DynamicEntryRunPath* entry : to_remove) {
          elf->remove(*entry);
        }

        elf->write("updated.elf");

  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf: lief::elf::Binary = ...

        // Remove **all** DT_RUNPATH entries
        elf.remove_dynamic_entries_by_tag(elf::dynamic::Tag::RUNPATH);

        // Remove all entries that contain '$ORIGIN'
        elf.remove_dynamic_entry_if(|e| {
            if let elf::dynamic::Entries::RunPath(runpath) = e {
                return runpath.runpath().contains("$ORIGIN");
            }
            false
        });

        let output = PathBuf::from("updated.elf");
        elf.write(output.as_path());

You can also check the :ref:`lief-patchelf <tools-lief-patchelf>` section for a
command-line interface.

.. _format-elf-symbols-version:

Symbol Versions
***************

The ELF format supports symbol versioning, allowing multiple versions of
the same function or variable to coexist within a single shared object.

During compilation, the linker selects the appropriate symbols and versions based
on the libraries provided as input. For example, if the program uses
the function ``printf`` and is linked with a version of ``libc.so`` that exposes
``printf@@GLIBC_2.40``, the compiled executable will require at least that
version of the ``libc`` to run.

This requirement regarding versioning can be problematic if we want to create
an executable or library compatible with a wide range of Linux distributions.

The **best way** to ensure maximum compatibility is to provide the minimum supported version of
the Glibc. For instance, if we aim to support Linux
distributions with at least Glibc version ``2.28`` (released in 2018),
we should specifically provide that version of ``libc.so``:

.. code-block:: console

   $ ld --sysroot=/sysroot/glibc-2.28/ my_program.o -o my_program.elf
   $ ld -L /sysroot/glibc-2.28/lib64/ my_program.o -o my_program.elf -lc


There are situations where we don't have that control over the link step, and
for which we want to change the versioning **post-compilation**. LIEF can be
used in these situations to perform the following modifications on the symbol
versions.

**Remove the version for a specific symbol**

In this example, we remove the version attached to the ``printf`` symbol
by setting the versioning as global (the default setting for imported functions).

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        sym = elf.get_dynamic_symbol("printf")

        sym.symbol_version.as_global()

        elf.write("updated.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf = ...;

        LIEF::ELF::Symbol* sym = elf->get_dynamic_symbol("printf");

        assert(sym != nullptr);

        sym->symbol_version()->as_global();

        elf->write("updated.elf")


  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf: lief::elf::Binary = ...

        if let Some(sym) = elf.dynamic_symbol_by_name("printf") {
            if let Some(mut symver) = dynsym.symbol_version() {
                symver.as_global();
            }
        }

        let output = PathBuf::from("updated.elf");
        elf.write(output.as_path());

**Remove all the versions for a specific library**

In this example, we remove all the symbol versions associated with an imported
library (``libm.so.6``):

.. tabs::

  .. tab:: :fa:`brands fa-python` Python

      .. code-block:: python

        elf: lief.ELF.Binary = ...

        elf.remove_version_requirement("libm.so.6")

        elf.write("updated.elf")

  .. tab:: :fa:`regular fa-file-code` C++

      .. code-block:: cpp

        std::unique_ptr<LIEF::ELF::Binary> elf = ...;

        elf->remove_version_requirement("libm.so.6");

        elf->write("updated.elf")


  .. tab:: :fa:`brands fa-rust` Rust

      .. code-block:: rust

        let mut elf: lief::elf::Binary = ...

        elf.remove_version_requirement("libm.so.6");

        let output = PathBuf::from("updated.elf");
        elf.write(output.as_path());

.. tabs::

  .. tab:: :fa:`solid fa-terminal` Before

      .. code-block:: console

        $ readelf -V input.elf

        Version symbols section '.gnu.version' contains 48 entries:
         Addr: 00000000000009bc  Offset: 0x0009bc  Link: 6 (.dynsym)
          000:   0 (*local*)       2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
          004:   2 (GLIBC_2.2.5)   0 (*local*)       4 (GLIBC_2.17)    3 (GLIBC_2.2.5)
          008:   2 (GLIBC_2.2.5)   5 (GLIBC_2.27)    2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
          00c:   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   6 (GLIBC_2.4)     2 (GLIBC_2.2.5)
          010:   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
          014:   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   0 (*local*)
          018:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
          01c:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
          020:   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
          024:   3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
          028:   3 (GLIBC_2.2.5)   0 (*local*)       3 (GLIBC_2.2.5)   3 (GLIBC_2.2.5)
          02c:   3 (GLIBC_2.2.5)   7 (GLIBC_2.29)    2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)

        Version needs section '.gnu.version_r' contains 2 entries:
         Addr: 0000000000000a20  Offset: 0x000a20  Link: 7 (.dynstr)
          0x0000: Version: 1  File: libm.so.6  Cnt: 3
          0x0010:   Name: GLIBC_2.29  Flags: none  Version: 7
          0x0020:   Name: GLIBC_2.27  Flags: none  Version: 5
          0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 3
          0x0040: Version: 1  File: libc.so.6  Cnt: 3
          0x0050:   Name: GLIBC_2.4  Flags: none  Version: 6
          0x0060:   Name: GLIBC_2.17  Flags: none  Version: 4
          0x0070:   Name: GLIBC_2.2.5  Flags: none  Version: 2


  .. tab:: :fa:`solid fa-terminal` After

      .. code-block:: console

        $ readelf -V updated.elf

        Version symbols section '.gnu.version' contains 48 entries:
         Addr: 00000000000009bc  Offset: 0x0009bc  Link: 6 (.dynsym)
          000:   0 (*local*)       1 (*global*)      1 (*global*)      1 (*global*)
          004:   1 (*global*)      0 (*local*)       4 (GLIBC_2.17)    1 (*global*)
          008:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          00c:   1 (*global*)      1 (*global*)      6 (GLIBC_2.4)     1 (*global*)
          010:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          014:   1 (*global*)      1 (*global*)      1 (*global*)      0 (*local*)
          018:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          01c:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          020:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          024:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)
          028:   1 (*global*)      0 (*local*)       1 (*global*)      1 (*global*)
          02c:   1 (*global*)      1 (*global*)      1 (*global*)      1 (*global*)

        Version needs section '.gnu.version_r' contains 1 entries:
         Addr: 0000000000000a20  Offset: 0x000a20  Link: 7 (.dynstr)
          0x0000: Version: 1  File: libc.so.6  Cnt: 3
          0x0010:   Name: GLIBC_2.4  Flags: none  Version: 6
          0x0020:   Name: GLIBC_2.17  Flags: none  Version: 4
          0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 2

.. include:: ../../_cross_api.rst
