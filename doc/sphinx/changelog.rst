Changelog
=========


0.15.1 - July 23th, 2024
------------------------

:MachO:

  * Fix missing commit for ``.hwx`` support


0.15.0 - July 21th, 2024
------------------------

:Extended:

  .. note::

    See: https://extended.lief.re and :ref:`extended-intro`

  * Add support for DWARF: :ref:`extended-dwarf`
  * Add support for PDB: :ref:`extended-pdb`
  * Add support for Objective-C: :ref:`extended-objc`


:Repo:
  * ``master`` branch has been renamed ``main``

:Rust:
  * First (beta) release of the bindings (c.f. :ref:`lief_rust_bindings`)

:ELF:
  * Add support to create custom notes (:issue:`1026`):

    .. code-block:: python

      elf: lief.ELF.Binary = ...

      elf += lief.ELF.Note.create(
          name="my-custom-note",
          original_type=lief.ELF.Note.TYPE.UNKNOWN,
          description=list(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed"),
          section_name=".lief.note.custom"
      )

      config = lief.ELF.Builder.config_t()
      config.notes = True
      elf.write("/tmp/new-binary.elf", config)

  * Add :meth:`lief.ELF.Binary.get_relocated_dynamic_array` which allows
    to get a **relocated** view of the of init/fini entries. This function can
    handy ELF init array/fini array functions are defined through relocations.
    See: :issue:`1058`, :issue:`626`
  * Add support for QNX Stack note (:issue:`1065`)
  * The ``static_symbols`` API functions has been renamed in ``symtab_symbols``.

    LIEF was naming symbols located in the ``.symtab`` sections as **static
    symbols** in opposition to the ``.dynsym`` symbols. This naming can be
    confusing since the concept of **static symbol** in a program is well
    defined (i.e. ``static bool my_var``) and not applicable in this case.

    **Therefore, the ``xxx_static_symbols`` API is has been renamed
    ``xxx_symtab_symbol``.**

  * Re-scope ``DYNAMIC_TAGS`` into :class:`lief.ELF.DynamicEntry.TAG`
  * Re-scope ``E_TYPE`` into :class:`lief.ELF.Header.FILE_TYPE`
  * Re-scope ``VERSION`` into :class:`lief.ELF.Header.VERSION`
  * Re-scope ``ELF_CLASS`` into :class:`lief.ELF.Header.CLASS`
  * Re-scope ``ELF_DATA`` into :class:`lief.ELF.Header.ELF_DATA`
  * Re-scope ``OS_ABI`` into :class:`lief.ELF.Header.OS_ABI`
  * Re-scope ``ELF_SECTION_TYPES`` into :class:`lief.ELF.Section.TYPE`
  * Re-scope ``ELF_SECTION_FLAGS`` into :class:`lief.ELF.Section.FLAGS`
  * Re-scope ``SYMBOL_BINDINGS`` into :class:`lief.ELF.Symbol.BINDING`
  * Re-scope ``ELF_SYMBOL_TYPES`` into :class:`lief.ELF.Symbol.TYPE`
  * Re-scope ``ELF_SYMBOL_VISIBILITY`` into :class:`lief.ELF.Symbol.VISIBILITY`
  * Re-scope ``SEGMENT_TYPES`` into :class:`lief.ELF.Segment.TYPE`
  * Re-scope ``ELF_SEGMENT_FLAGS`` into :class:`lief.ELF.Segment.FLAG`
  * Re-scope ``DYNAMIC_FLAGS_1`` into :class:`lief.ELF.DynamicEntryFlags.FLAG`
  * Re-scope ``DYNAMIC_FLAGS`` into :class:`lief.ELF.DynamicEntryFlags.FLAG`
  * Re-scope ``DYNSYM_COUNT_METHODS`` into :class:`lief.ELF.ParserConfig.DYNSYM_COUNT`
  * Re-scope ``RELOCATION_PURPOSES`` into :class:`lief.ELF.Relocation.PURPOSE`
  * ``RELOC_x86_64``, ``RELOC_i386``, ... have been re-scoped **and merged**
    into :class:`lief.ELF.Relocation.TYPE`

  * Add support for Android packed relocation format (``DT_ANDROID_REL{A}``)
  * Add support for relative relocation format (``DT_RELR``)

:PE:
  * Authenticode:
    Add partial support for the following PKCS #7 attributes:

      - ``1.3.6.1.4.1.311.3.3.1 - Ms-CounterSign`` (:class:`lief.PE.MsCounterSign`)
      - ``1.3.6.1.4.1.311.10.3.28 - Ms-ManifestBinaryID`` (:class:`lief.PE.MsManifestBinaryID`)
      - ``1.3.6.1.4.1.311.2.6.1 - SPC_RELAXED_PE_MARKER_CHECK_OBJID`` (:class:`lief.PE.SpcRelaxedPeMarkerCheck`)
      - ``1.2.840.113549.1.9.16.2.47 - SIGNING_CERTIFICATE_V2`` (:class:`lief.PE.SigningCertificateV2`)

    - ``1.2.840.113549.1.9.16.1.4 - PKCS#9 TSTInfo`` (:class:`lief.PE.PKCS9TSTInfo`)

  * Add :attr:`lief.PE.CodeViewPDB.guid` attribute (:issue:`480`)
  * Move ``lief.PE.OptionalHeader.computed_checksum`` to :meth:`lief.PE.Binary.compute_checksum`

    In previous versions of LIEF, :attr:`lief.PE.OptionalHeader.checksum` was
    re-computed (on purpose) in the parsing phase. On large
    binaries, this re-computation can have a **strong impact** on the performances.
    Thus, this computation has been deferred to a dedicated method :meth:`lief.PE.Binary.compute_checksum`

    .. code-block:: python

      pe = lief.PE.parse("...")
      # Before:
      computed = pe.optional_header.computed_checksum
      # Now:
      computed = pe.compute_checksum()

:MachO:

  * Add support to modify Mach-O rpath (see: :issue:`1074`)
  * Add helper :attr:`lief.MachO.Binary.support_arm64_ptr_auth` to check if a
    Mach-O binary is supporting ARM64 pointer authentication (arm64e)
  * Fix **major performance issue when processing Mach-O binaries on Windows & macOS**
  * Add generic :class:`lief.MachO.UnknownCommand` to support Apple private Load
    commands not officially supported by LIEF.
  * Re-scope ``LOAD_COMMAND_TYPES`` into :class:`lief.MachO.LoadCommand.TYPE`
  * Re-scope ``FILE_TYPES`` into :class:`lief.MachO.Header.FILE_TYPE`
  * Re-scope ``HEADER_FLAGS`` into :class:`lief.MachO.Header.FLAGS`
  * Re-scope ``MACHO_SEGMENTS_FLAGS`` into :class:`lief.MachO.SegmentCommand.FLAGS`
  * Re-scope ``MACHO_SECTION_TYPES`` into :class:`lief.MachO.Section.TYPE`
  * Re-scope ``MACHO_SECTION_FLAGS`` into :class:`lief.MachO.Section.FLAGS`
  * Re-scope ``REBASE_TYPES`` into :class:`lief.MachO.DyldInfo.REBASE_TYPE`
  * Re-scope ``REBASE_OPCODES`` into :class:`lief.MachO.DyldInfo.REBASE_OPCODES`
  * Re-scope ``BIND_OPCODES`` into :class:`lief.MachO.DyldInfo.BIND_OPCODES`
  * Re-scope ``BINDING_CLASS`` into :class:`lief.MachO.DyldBindingInfo.CLASS`
  * Re-scope ``BIND_TYPES`` into :class:`lief.MachO.DyldBindingInfo.TYPE`
  * Re-scope ``EXPORT_SYMBOL_FLAGS`` into :class:`lief.MachO.ExportInfo.FLAGS`
  * Re-scope ``EXPORT_SYMBOL_KINDS`` into :class:`lief.MachO.ExportInfo.KIND`
  * Re-scope ``RELOCATION_ORIGINS`` into :class:`lief.MachO.Relocation.ORIGIN`
  * Re-scope ``SYMBOL_ORIGINS`` into :class:`lief.MachO.Symbol.ORIGIN`
  * Re-scope ``VM_PROTECTIONS`` into :class:`lief.MachO.SegmentCommand.VM_PROTECTIONS`
  * Re-scope ``CPU_TYPES`` into :class:`lief.MachO.Header.CPU_TYPE`

:CMake:

  * ``LIEFConfig.cmake`` is now installed in ``<prefix>/lib/cmake/LIEF/``
    instead of ``<prefix>/share/LIEF/cmake/``


:Python Bindings:

  * Add :func:`lief.disable_leak_warning` to disable Nanobind warning about "leaks".

  .. warning::

    These warnings does not necessarily mean that LIEF leak objects. These
    warnings might happen in `Cyclic garbage collection <https://nanobind.readthedocs.io/en/latest/typeslots.html#cyclic-garbage-collection>`_.

:Documentation:

  * Add icons
  * Include inheritance diagram for Python API (e.g. :class:`lief.ELF.Note`)


0.14.1 - February 11th, 2024
----------------------------

:ELF:
  * Fix regression in Symbol Version Definition processing (:issue:`1014`)

:PE:
  * Address :issue:`1016` by creating aliases:

    - :attr:`lief.PE.ContentInfo.digest` to :attr:`lief.PE.SpcIndirectData.digest`
    - :attr:`lief.PE.ContentInfo.digest_algorithm` to :attr:`lief.PE.SpcIndirectData.digest_algorithm`

:Python:

  * Fix regression in iterator's performances

0.14.0 - January 20, 2024
-------------------------

:ELF:
  * Add support for the GNU note properies (:issue:`975`).

    :Example:

      .. code-block:: python

        elf = lief.ELF.parse("...")
        note = elf.get(lief.ELF.Note.TYPE.GNU_PROPERTY_TYPE_0)
        aarch64_feat: lief.ELF.AArch64Feature = note.find(lief.ELF.NoteGnuProperty.Property.TYPE.AARCH64_FEATURES)
        if lief.ELF.AArch64Feature.FEATURE.BTI in aarch64_feat.features:
            print("BTI supported")

    See:

    - :class:`lief.ELF.NoteGnuProperty`
    - :class:`lief.ELF.AArch64Feature`
    - :class:`lief.ELF.NoteNoCopyOnProtected`
    - :class:`lief.ELF.StackSize`
    - :class:`lief.ELF.X86Features`
    - :class:`lief.ELF.X86ISA`


  * Refactoring of the ELF note processing
  * Fix relocation issue when using ``-Wl,--emit-relocs`` (c.f. :issue:`897` / :pr:`898` by :github_user:`adamjseitz`)
  * Improve the computation of the dynamic symbols thanks to :github_user:`adamjseitz` (c.f. :issue:`922`)
  * Add support for the LoongArch architecture thanks to :github_user:`loongson-zn` (c.f. :pr:`921`)

  * Add a :class:`lief.ELF.ParserConfig` interface that can be used to tweak
    which parts of the ELF format should be parsed.

    :Example:

      .. code-block:: python

        config = lief.ELF.ParserConfig()

        # Skip parsing static and dynamic symbols
        config.parse_static_symbols = False
        config.parse_dyn_symbols = False

        elf = lief.ELF.parse("target.elf", config)

:MachO:

  * The *fileset name* is now stored in :attr:`lief.MachO.Binary.fileset_name`
    (instead of `lief.MachO.Binary.name`)

:PE:
  * ``RESOURCE_SUBLANGS`` has been removed
  * ``RESOURCE_LANGS`` is now defined in a dedicated header: ``LIEF/PE/resources/langs.hpp``
  * ``RESOURCE_TYPES`` is now scoped in ``ResourcesManager::TYPE``
  * ``GUARD_CF_FLAGS`` is now scoped as :class:`~lief.PE.LoadConfigurationV1.IMAGE_GUARD` in
    :class:`lief.PE.LoadConfigurationV1`
  * ``SECTION_CHARACTERISTICS`` is now scoped within the
    :class:`~lief.PE.Section` class instead of being globally defined:

    .. code-block:: python

      # Before
      lief.PE.SECTION_CHARACTERISTICS.CNT_CODE
      # Now:
      lief.PE.Section.CHARACTERISTICS.CNT_CODE
  * ``DATA_DIRECTORY`` is now scoped within the
    :class:`~lief.PE.DataDirectory` class instead of being globally defined:

    .. code-block:: python

      # Before
      lief.PE.DATA_DIRECTORY.IAT
      # Now:
      lief.PE.DataDirectory.TYPES.IAT

  * ``MACHINE_TYPES`` and ``HEADER_CHARACTERISTICS`` are now scoped within the
    :class:`~lief.PE.Header` class instead of being globally defined:

    .. code-block:: python

      # Before
      lief.PE.MACHINE_TYPES.AMD64
      # Now:
      lief.PE.Header.MACHINE_TYPES.AMD64

  * :attr:`lief.PE.Header.characteristics` now returns a
    `list`/`std::vector` instead of a ``set``.
  * :attr:`lief.PE.OptionalHeader.dll_characteristics_lists` now returns a
    ``list``/``std::vector`` instead of a ``set``.
  * ``SUBSYSTEM`` and ``DLL_CHARACTERISTICS`` are now scoped within the
    :class:`~lief.PE.OptionalHeader` class instead of being globally defined:

    .. code-block:: python

      # Before
      lief.PE.SUBSYSTEM.NATIVE
      # Now:
      lief.PE.OptionalHeader.SUBSYSTEM.NATIVE
  * :attr:`lief.PE.DosHeader.used_bytes_in_the_last_page` has been renamed in
    :attr:`lief.PE.DosHeader.used_bytes_in_last_page`
  * Refactoring of the Debug directory processing:
    :class:`lief.PE.Debug` is now the root class of:
    :class:`lief.PE.CodeView` / :class:`lief.PE.CodeView`, :class:`lief.PE.Pogo`,
    :class:`lief.PE.Repro`.

    The parsing logic has been cleaned and the tests updated.
  * Add a :class:`lief.PE.ParserConfig` interface that can be used to tweak
    which parts of the PE format should be parsed (:issue:`839`).

    :Example:

      .. code-block:: python

        config = lief.PE.ParserConfig()

        # Skip parsing PE authenticode
        config.parse_signature = False

        pe = lief.PE.parse("pe.exe", config)

:Abstraction:

    * ``LIEF::EXE_FORMATS`` is now scoped in ``LIEF::Binary::FORMATS``
    * All the `Binary` classes now implement `classof`:

      .. code-block:: cpp

        std::unique_ptr<LIEF::Binary> bin = LIEF::Parser::parse("...");
        if (LIEF::PE::Binary::classof(bin.get())) {
          auto& pe_file = static_cast<LIEF::PE::Binary&>(*bin);
        }

:General Design:

  * Python parser functions (like: :func:`lief.PE.parse`) now accept `os.PathLike`
    arguments like `pathlib.Path` (:issue:`974`).
  * Remove the `lief.Binary.name` attribute
  * LIEF is now compiled with C++17 (the API remains C++11 compliant)
  * Switch to `nanobind <https://nanobind.readthedocs.io/en/latest/>`_ for the
    Python bindings.
  * CI are now more efficient.
  * The Python documentation for properties now contains the type of the
    property.

0.13.2 - June 17, 2023
----------------------

:PE:

  Fix authenticode inconsitency (:issue:`932`)

:ELF:

     Fix missing undef (:issue:`929`)

0.13.1 - May 28, 2023
----------------------

:PE:

  * Fix PE authenticode verification issue in the case of special characters (:issue:`912`)

:Misc:

  * Fix mypy stubs (:issue:`909`)
  * Fix missing include (:issue:`918`)
  * Fix C99 comments (:issue:`916`)
  * Fix AArch64 docker image (:issue:`904`)



0.13.0 - April 9, 2023
----------------------

:ELF:

  * Fix overflow issue in segments (c.f. :issue:`845` found by :github_user:`liyansong2018`)
  * Fix missing relationship between symbols and sections (c.f. :issue:`841`)
  * Fix coredump parsing issue (c.f. :issue:`830` found by :github_user:`Lan1keA`)
  * Fix and (re)enable removing dynamic symbols (c.f. :issue:`828`)
  * Add support for `NT_GNU_BUILD_ATTRIBUTE_OPEN` and `NT_GNU_BUILD_ATTRIBUTE_FUNC` (c.f. :issue:`816`)
  * [CVE-2022-38497] Fix ELF core parsing issue (:issue:`766` found by :github_user:`CCWANG19`)
  * [CVE-2022-38306] Fix a heap overflow found by :github_user:`CCWANG19` (:issue:`763`)
  * :github_user:`aeflores` fixed an issue when there are multiple versions associated with a symbol
    (see: :issue:`749` for the details).
  * Handle binaries compiled with the `-static-pie` flag correctly (see: :issue:`747`)
  * Add support for modifying section-less binaries. The ELF :class:`~lief.ELF.Section` objects gain
    the :meth:`lief.ELF.Section.as_frame` method which defines the section as a *framed* section.

    A framed section is a section that concretely does not wraps data and can be corrupted.

    :Example:

      .. code-block:: python

        elf = lief.parse("/bin/ssh")
        text = elf.get_section(".text").as_frame()

        # We can now corrupt all the fields of the section
        text.offset  = 0xdeadc0de
        text.size    = 0xffffff
        text.address = 0x123

        elf.write("/tmp/out")

  * Add API to precisely define how the segments table should be relocated.
    One might want to enforce a certain ELF layout while adding sections/ segments.
    It is now possible to call the method: :meth:`~lief.ELF.Binary.relocate_phdr_table`
    to define how the segments table should be relocated for welcoming the
    new sections/segments:

    .. code-block:: python

      elf = lief.parse("...")
      # Enforce a specific relocation type:
      # The new segments table will be shift at the end
      # of the file
      elf.relocate_phdr_table(Binary.PHDR_RELOC.FILE_END)

      # Add sections/segments
      # [...]
      elf.write("out.elf")

    See:

      - :meth:`lief.ELF.Binary.relocate_phdr_table`
      - :class:`lief.ELF.Binary.PHDR_RELOC`

:MachO:

  * Add :attr:`~lief.MachO.Binary.rpaths` iterator (:issue:`291`)
  * Add support for parsing Mach-O in memory
  * Fix a memory issue (found by :github_user:`bladchan` via :issue:`806`)
  * [CVE-2022-40923] Fix parsing issue (:issue:`784` found by :github_user:`bladchan`)
  * [CVE-2022-40922] Fix parsing issue (:issue:`781` found by :github_user:`bladchan`)
  * [CVE-2022-38307] Fix a segfault when the Mach-O binary does not have segments (found by :github_user:`CCWANG19` via :issue:`764`)
  * Enable to create exports
  * Fix the layout of the binaries modified by LIEF such as they can be (re)signed.
  * Add support for `LC_DYLD_CHAINED_FIXUPS` and `LC_DYLD_EXPORTS_TRIE`
  * Global enhancement when modifying the `__LINKEDIT` content
  * Add API to get a :class:`~lief.MachO.Section` from a specified segment's name and section's name.

  :Example:

    .. code-block:: python

      sec = bin.get_section("__DATA", "__objc_metadata")

  * Add API to remove a :class:`~lief.MachO.Section` from a specified segment's name and section's name.

  :Example:

    .. code-block:: python

      sec = bin.remove_section("__DATA", "__objc_metadata")

  * Add :attr:`lief.MachO.Binary.page_size`

:PE:

  * The Python API now returns `bytes` objects instead of `List[int]`
  * Remove :meth:`lief.PE.ResourceNode.sort_by_id`
  * Fix the ordering of children of :class:`~lief.PE.ResourceNode`
  * Remove deprecated functions related to PE hooking.
  * Add support for new PE LoadConfiguration structures.

:DEX:

  * Fix multiple parsing issues raised by :github_user:`bladchan`

:Other:

  * [CVE-2022-38497]: :issue:`765` found by :github_user:`CCWANG19`
  * [CVE-2022-38495]: :issue:`767` found by :github_user:`CCWANG19`

:General Design:

  * :github_user:`ZehMatt` added the support to write LIEF binaries object through a `std::ostream` interface
    (:commit:`9d55f538602989c69454639565910884c5c5ac7c`)
  * Remove the exceptions
  * The library contains less static initializers which should improve the loading time.

:Python Bindings:

  * Move to a build system compliant with ``pyproject.toml``
  * Provide typing stubs: :issue:`650`
  * PyPI releases no longer provide source distribution (`sdist`)

:Dependencies:

  * Move to spdlog 1.11.0
  * Move to `Pybind11 - 2.10.1 <https://pybind11.readthedocs.io/en/stable/changelog.html#version-2-10-1-oct-31-2022>`_
  * Move to nlohmann/json 3.11.2
  * Move to MbedTLS 3.2.1
  * Move to utfcpp 3.2.1



0.12.3 - November 1, 2022
-------------------------

This release contains several security fixes:

  * [CVE-2022-38497] Fix ELF core parsing issue (:issue:`766` found by :github_user:`CCWANG19`)
  * [CVE-2022-38306] Fix a heap overflow found by :github_user:`CCWANG19` (:issue:`763`)
  * Fix a memory issue (found by :github_user:`bladchan` via :issue:`806`)
  * [CVE-2022-40923] Fix parsing issue (:issue:`784` found by :github_user:`bladchan`)
  * [CVE-2022-40922] Fix parsing issue (:issue:`781` found by :github_user:`bladchan`)
  * [CVE-2022-38307] Fix a segfault when the Mach-O binary does not have segments (found by :github_user:`CCWANG19` via :issue:`764`)


0.12.1 - April 08, 2022
------------------------

:ELF:
  * Fix section inclusion calculations (:pr:`692`)

:PE:
  * Fix parsing regressions (:issue:`689`, :issue:`687`, :issue:`686`, :issue:`685`, :issue:`691`, :issue:`693`)

:Compilation:
  * Nightly builds are now upload to Saleway's S3 server:

    - https://lief.s3-website.fr-par.scw.cloud/latest/lief
    - https://lief.s3-website.fr-par.scw.cloud/latest/sdk

  * Fix `GLIBCXX_USE_CXX11_ABI=1` ABI issue (see: :issue:`683`)

0.12.0 - March 25, 2022
-----------------------

:ELF:
  * :github_user:`ahaensler` added the support to insert and assign a :class:`lief.ELF.SymbolVersionAuxRequirement` (see: :pr:`670`)
  * Enhance the ELF parser to support corner cases described by `netspooky <https://n0.lol/>`_ in :

    - https://tmpout.sh/2/14.html (*84 byte aarch64 ELF*)
    - https://tmpout.sh/2/3.html (*Some ELF Parser Bugs*)

  * New ELF Builder which is more efficient in terms of speed and
    in terms of number of segments added when modifying binaries (see: https://lief-project.github.io/blog/2022-01-23-new-elf-builder/)

  * :github_user:`Clcanny` improved (see :pr:`507` and :pr:`509`) the reconstruction of the dynamic symbol table
    by sorting local symbols and non-exported symbols. It fixes the following warning when parsing
    a modified binary with ``readelf``

    .. code-block:: text

      Warning: local symbol 29 found at index >= .dynsym's sh_info value of 1

:MachO:
  * Change the layout of the binaries generated by LIEF such as they are compliant with ``codesign`` checks
  * The API to configure the MachO parser has been redesigned to provide a better granularity

    .. code-block:: python

      config = lief.MachO.ParserConfig()
      config.parse_dyld_bindings = False
      config.parse_dyld_exports  = True
      config.parse_dyld_rebases  = False

      lief.MachO.parse("/tmp/big.macho", config)

  * :github_user:`LucaMoroSyn` added the support for the ``LC_FILESET_ENTRY``. This command is usually
    found in kernel cache files
  * ``LIEF::MachO::Binary::get_symbol`` now returns a pointer (instead of a reference). If the symbol
    can't be found, it returns a nullptr.
  * Add API to select a :class:`~lief.MachO.Binary` from a :class:`~lief.MachO.FatBinary` by its architecture. See:
    :meth:`lief.MachO.FatBinary.take`.

    .. code-block:: python

      fat = lief.MachO.parse("/bin/ls")
      fit = fat.take(lief.MachO.CPU_TYPES.x86_64)

  * Handle the `0x0D` binding opcode (see: :issue:`524`)
  * :github_user:`xhochy` fixed performances issues in the Mach-O parser (see :pr:`579`)

:PE:
  * Adding :attr:`lief.PE.OptionalHeader.computed_checksum` that re-computes the :attr:`lief.PE.OptionalHeader.checksum`
    (c.f. issue :issue:`660`)
  * Enable to recompute the :class:`~lief.PE.RichHeader` (issue: :issue:`587`)

    - :meth:`~lief.PE.RichHeader.raw`
    - :meth:`~lief.PE.RichHeader.hash`

  * Add support for PE's delayed imports. see:

    - :class:`~lief.PE.DelayImport` / :class:`~lief.PE.DelayImportEntry`
    - :attr:`~lief.PE.Binary.delay_imports`

  * :attr:`lief.PE.LoadConfiguration.reserved1` has been aliased to :attr:`lief.PE.LoadConfiguration.dependent_load_flags`
  * :attr:`lief.PE.LoadConfiguration.characteristics` has been aliased to :attr:`lief.PE.LoadConfiguration.size`
  * Thanks to :github_user:`gdesmar`, we updated the PE checks to support PE files that have a corrupted
    :attr:`lief.PE.OptionalHeader.magic` (cf. :issue:`644`)

:DEX:
  * :github_user:`DanielFi` added support for DEX's fields (see: :pr:`547`)

:Abstraction:
  * Abstract binary imagebase for PE, ELF and Mach-O (:attr:`lief.Binary.imagebase`)
  * Add :meth:`lief.Binary.offset_to_virtual_address`
  * Add PE imports/exports as *abstracted* symbols

:Compilation & Integration:
  * :github_user:`ekilmer` updated and modernized the CMake integration files through the PR: :pr:`674`
  * Enable to use a pre-compiled version of spdlog. This feature aims
    at improving compilation time when developing on LIEF.

    One can provide path to spdlog install through:

    .. code-block:: console

      $ python ./setup.py --spdlog-dir=path/to/lib/cmake/spdlog [...]
      # or
      $ cmake -DLIEF_EXTERNAL_SPDLOG=ON -Dspdlog_DIR=path/to/lib/cmake/spdlog ...

  * Enable to feed LIEF's dependencies externally (c.f. :ref:`lief_third_party`)
  * Replace the keywords ``and``, ``or``, ``not`` with ``&&``, ``||`` and ``!``.

:Dependencies:
  * Upgrade to MbedTLS 3.1.0
  * Upgrade Catch2 to 2.13.8
  * The different dependencies can be *linked* externally (cf. above and :ref:`lief_third_party`)

:Documentation:
  * New section about the errors handling (:ref:`err_handling`) and the upcoming
    deprecation of the exceptions.
  * New section about how to compile LIEF for debugging/developing. See: :ref:`lief_debug`

:General Design:

  :span:

    LIEF now exposes Section/Segment's data through a `span` interface.
    As `std::span` is available in the STL from C++20 and the LIEF public API aims at being
    C++11 compliant, we expose this `span` thanks to `tcbrindle/span <https://github.com/tcbrindle/span>`_.
    This new interface enables to avoid copies of ``std::vector<uint8_t>`` which can be costly.
    With this new interface, the original ``std::vector<uint8_t>`` can be retrieved as follows:

    .. code-block:: cpp

      auto bin = LIEF::ELF::Parser::parse("/bin/ls");

      if (const auto* section = bin->get_section(".text")) {
        LIEF::span<const uint8_t> text_ref =  section->content();
        std::vector<uint8_t> copy = {std::begin(text_ref), std::end(text_ref)};
      }

    In Python, span are wrapped by a **read-only** `memory view <https://docs.python.org/3/c-api/memoryview.html>`_.
    The original *list of bytes* can be retrieved as follows:

    .. code-block:: python

      bin = lief.parse("/bin/ls")
      section = bin.get_section(".text")

      if section is not None:
        memory_view = section.content
        list_of_bytes = list(memory_view)

  :Exceptions:

    .. warning::

      We started to refactor the API and the internal design to remove C++ exceptions.
      These changes are described a the dedicated blog (`LIEF RTTI & Exceptions <https://lief-project.github.io/blog/2022-02-13-lief-rtti-exceptions/>`_)

      To highlighting the content of the blog for the end users,
      functions that returned a **reference and which threw an exception** in the case
      of a failure are now returning a **pointer that is set to nullptr** in the case of a failure.

      If we consider this original code:

      .. code-block:: cpp

        LIEF::MachO::Binary& bin = ...;

        try {
          LIEF::MachO::UUIDCommand& cmd = bin.uuid();
          std::cout << cmd << "\n";
        } catch (const LIEF::not_found&) {
          // ... dedicated processing
        }

        // Other option with has_uuid()
        if (bin.has_uuid()) {
          LIEF::MachO::UUIDCommand& cmd = bin.uuid();
          std::cout << cmd << "\n";
        }

      It can now be written as:

      .. code-block:: cpp

        LIEF::MachO::Binary& bin = ...;

        if (LIEF::MachO::UUIDCommand* cmd = bin.uuid();) {
          std::cout << *cmd << "\n";
        } else {
          // ... dedicated processing as it is a nullptr
        }

        // Other option with has_uuid()
        if (bin.has_uuid()) { // It ensures that it is not a nullptr
          LIEF::MachO::UUIDCommand& cmd = *bin.uuid();
          std::cout << cmd << "\n";
        }

    .. seealso::

      - :ref:`C++ API for errors handling <cpp-api-error-handling>`
      - :ref:`Python API for errors handling <python-api-error-handling>`
      - `List of the functions that changed <https://gist.github.com/romainthomas/37da45b043c5f8b8db6be2767611f625>`_


0.11.X - Patch Releases
-----------------------

.. _release-0115:

0.11.5 - May 22, 2021
*********************

* Remove usage of ``not`` in public headers (:commit:`b8e825b464418de385146bb3f89ef6126f4de5d4`)

:ELF:
  * :github_user:`pdreiter` fixed the issue :issue:`418`

:PE:
  * Fix issue when computing :attr:`lief.PE.Binary.sizeof_headers` (:commit:`ab3f073ac0c60d8453070f83dd4dc04fe60aa0a5`)

:MachO:
  * Fix error on property :attr:`lief.MachO.BuildVersion.sdk` (see :issue:`533`)

.. _release-0114:

0.11.4 - March 09, 2021
***********************

:PE:
    * Fix missing bound check when computing the authentihash

.. _release-0113:

0.11.3 - March 03, 2021
***********************

:PE:
    * Add sanity check on the signature's length that could lead to a ``std::bad_alloc`` exception

.. _release-0112:


0.11.2 - February 24, 2021
**************************

:PE:
    * Fix regression in the behavior of the PE section's name. One can now access the full
      section's name (with trailing bytes) through :attr:`lief.PE.Section.fullname` (see: :issue:`551`)

.. _release-0111:

0.11.1 - February 22, 2021
**************************

:PE:
    * :meth:`lief.PE.x509.is_trusted_by` and :meth:`lief.PE.x509.verify` now return
      a better :attr:`lief.PE.x509.VERIFICATION_FLAGS` instead of just :attr:`lief.PE.x509.VERIFICATION_FLAGS.BADCERT_NOT_TRUSTED`
      (see: :issue:`532`)
    * Fix errors in the computation of the Authentihash

.. _release-0110:

0.11.0 - January 19, 2021
-------------------------

:ELF:
  * :github_user:`mkomet` updated enums related to Android (see: :commit:`9dd641d380a5defd0a71a9f42dde2fe9c9cb1dbd`)
  * :github_user:`aeflores` added MIPS relocations support in the ELF parser
  * Fix :meth:`~lief.ELF.Binary.extend` on a ELF section (cf. issue :issue:`477`)
  * Fix issue when exporting symbols on empty-gnu-hash ELF binary (:commit:`1381f9a115e6e312ac0ab3deb46a78e481b81796`)
  * Fix reconstruction issue when the binary is prelinked (cf. issue :issue:`466`)
  * Add ``DF_1_PIE`` flag
  * Fix parsing issue of the ``.eh_frame`` section when the base address is not 0.
  * :github_user:`JanuszL` enhanced the algorithm that computes the string table.
    It moves from a ``N^2`` algorithm to a ``Nlog(N)`` (:commit:`1e0c4e81d4a3fd7282713f111193e42f198f8967`).
  * Fix ``.eh_frame`` parsing issue (:commit:`b57f32333a85d0f172206bc5d20aabe2d7942738`)
  * :github_user:`aeflores` fixed parsing issue in ELF relocations (:commit:`6c53646bb790acf28f2999527eafad30db7d6b69`)
  * Add ``PT_GNU_PROPERTY`` enum
  * Bug fix in the symbols table reconstruction (ELF)

:PE:
  * Enhance PE Authenticode. See `PE Authenticode <https://lief.quarkslab.com/doc/latest/tutorials/13_pe_authenticode.html>`_
  * :func:`~lief.PE.get_imphash` can now generate the same value as pefile and Virus Total (:issue:`299`)

    .. code-block:: python

      pe = lief.parse("example.exe")
      vt_imphash = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)
      lief_imphash = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.DEFAULT)

    .. seealso::

      :class:`lief.PE.IMPHASH_MODE` and :func:`lief.PE.get_imphash`
  * Remove the padding entry (0) from the rich header
  * :attr:`~lief.PE.LangCodeItem.items` now returns a dictionary for which the values are **bytes** (instead of
    ``str`` object). This change is related to ``utf-16`` support.
  * :github_user:`kohnakagawa` fixed wrong enums values: :commit:`c03125045e32a9cd65c613585eb4d0385350c6d2`, :commit:`6ee808a1e4611d09c6cf0aea82a612be69584db9`, :commit:`cd05f34bae681fc8af4b5e7cc28eaef816802b6f`
  * :github_user:`kohnakagawa` fixed a bug in the PE resources parser (:commit:`a7254d1ba935783f16effbc7faddf993c57e82f7`)
  * Handle PE forwarded exports (issue :issue:`307`)

:Mach-O:
  * Add API to access either ``LC_CODE_SIGNATURE`` or ``DYLIB_CODE_SIGN_DRS`` (issue :issue:`476`)
  * Fix issue when parsing twice a Mach-O file (issue :issue:`479`)

:Dependencies:
  * Replace ``easyloggingpp`` with `spdlog 1.8.1 <https://github.com/gabime/spdlog>`_
  * Upgrade ``frozen`` to 1.0.0
  * Upgrade ``json`` to 3.7.3
  * Upgrade ``pybind11`` to 2.6.0
  * Upgrade ``mbedtls`` to 2.16.6

:Documentation:
  * :github_user:`aguinet` updated the `bin2lib tutorial <tutorials/08_elf_bin2lib.html>`_ with the support
    of the new glibc versions (:commit:`7884e57aa1d103f3bd37682e47f412bfe7a3aa34`)
  * Global update and enable to build the documentation out-of-tree
  * Changing the theme

:Misc:
  * Add Python 3.9 support
  * ``FindLIEF.cmake`` deprecates ``LIEF_ROOT``. You should use ``LIEF_DIR`` instead.


:Logging:

  We changed the logging interface. The following log levels have been removed:

  - LOG_GLOBAL
  - LOG_FATAL
  - LOG_VERBOSE
  - LOG_UNKNOWN

  We also moved from an class-interface based to functions.

  Example:

  .. code-block:: python

    lief.logging.disable()
    lief.logging.enable()
    lief.logging.set_level(lief.logging.LEVEL.INFO)

  See: :func:`lief.logging.set_level`

  .. note::

     The log functions now output on ``stderr`` instead of ``stdout``



0.10.1 - November 29, 2019
--------------------------

- Fix regression in parsing Python ``bytes``
- Add Python API to demangle strings: ``lief.demangle``


0.10.0 - November 24, 2019
--------------------------

:ELF:

   * Add build support for ELF notes
   * Add coredump support (:commit:`9fc3a8a43358f608cf18ddbe341e1d94b13cb9e0`)
   * Enable to bind a relocation with a symbol (:commit:`a9f3cb8f9b4a1f2cdaa95eee4568ff0b162f77cd`)

     :Example:

      .. code-block:: python

        relocation = "..."

        symbol = lief.ELF.Symbol()
        symbol.name = "printf123"
        relocation.symbol = symbol

   * Add constructors  (:commit:`67d924a2206c36cb9979d8b1b194b03b2d592e71`)
   * Expose ELF destructors (:commit:`957384cd361c4a485470f877658af2bf052dbe0a`)
   * Add ``remove_static_symbol`` (:commit:`c6779702b1fec3c67b0c19a36576830fe18bd9d9`)
   * Add support for static relocation writing (:commit:`d1b98d69ade662e2471ce2905bf3fb247dfc3143`)
   * Expose function to get strings located in the ``.rodata`` section (:commit:`02f4851c9f0c2bfa6fb4f51dab393a1db83b4851`)
   * Export ELF ABI version (:commit:`8d7ec26a93800b0729c2c05be8c55c8318ba3b20`)

:PE:

   * Improve PE Authenticode parsing (:commit:`535623de3aa4f8ddc34536331b802e2cbdc44faf`)
   * Fix alignment issue when removing a PE section (:commit:`04dddd371080d731fab965b127cb15a91c57d53c`)
   * Parse PE debug data directory as a list of debug entries (by :github_user:`1orenz0` - :commit:`fcc75dd87982e52d77a1c7ee7e674741a199e41b`)
   * Add support to parse POGO debug entries (by :github_user:`1orenz0` - :commit:`3537440b8d0da6c9c3d00c25f7da8a04f29154d2`)

:Mach-O:

   * Enhance Mach-O modifications by exposing an API to:

     - Add load commands
     - Add sections
     - Add segments

     See: :commit:`406115c8d097da0b61f00b2bb7b2442322ffc5d1`

   * Enable ``write()`` on FAT Mach-O (:commit:`16595316fd588619ea39b942817d6527e0601fbd`)
   * Introduce Mach-O Build Version command (:commit:`6f967238fcd369210839605ab08c30d647a09a65`)
   * Enable to remove Mach-O symbols (:commit:`616d739da513092e9ab7446654414b0929d5d5cf`)
   * Add support for adding ``LC_UNIXTHREAD`` commands in a MachO (by :github_user:`nezetic` - :commit:`64d2597284149441fc734b251648ca917cd816e3`)


:Abstract Layer:

   * Expose ``remove_section()`` in the abstract layer (:commit:`918438c6bee52c8421d809bc3b42974165e5fa0b`)
   * Expose ``write()`` in the abstract layer (:commit:`af4d48ed2e1f1b96687644f2fc4661fcbdb979a6`)
   * Expose API to list functions found in a binary (:commit:`b5a08463ad63811e9e9432812406aadd74ab8c09`)

:Android:

   * Add partial support for Android 9 (:commit:`bce9ebe17064b1ca16b00dc14eebb5d5dd440184`)


:Misc:

   * :github_user:`lkollar` added support for Python 3.8 in CI (Linux & OSX only)
   * Update Pybind11 dependency to ``v2.4.3``
   * Enhance Python install
   * Thanks to :github_user:`lkollar`, Linux CI now produces **manylinux1-compliant wheels**

Many thanks to the contributors: :github_user:`recvfrom`, :github_user:`pbrunet`,
:github_user:`mackncheesiest`, :github_user:`wisk`, :github_user:`nezetic`,
:github_user:`lkollar`, :github_user:`jbremer`, :github_user:`DaLynX`, :github_user:`1orenz0`,
:github_user:`breadchris`, :github_user:`0xbf00`, :github_user:`unratito`, :github_user:`strazzere`,
:github_user:`aguinetqb`, :github_user:`mingwandroid`, :github_user:`serge-sans-paille-qb`, :github_user:`yrp604`,
:github_user:`majin42`, :github_user:`KOLANICH`

0.9.0 - June 11, 2018
---------------------

LIEF 0.9 comes with new formats related to Android: OAT, DEX, VDEX and ART. It also fixes bugs and thanks to
:github_user:`yd0b0N`, ELF parser now supports big and little endian binaries. We also completed the JSON serialization of LIEF objects.


Features
********

:MachO:

  * Enable to configure the Mach-O parser for quick parsing: :commit:`880b99aeef825786dd65aed286d7c4d23b62f564`
  * Add :class:`lief.MachO.EncryptionInfo` command: :commit:`f4e2d81bfe84238d463bdb65297c296635e783b1`
  * Add :class:`lief.MachO.RPathCommand` command: :commit:`196994dc089885ff2f1268e51f5514f7fcbc5cff`
  * Add :class:`lief.MachO.DataInCode` command: :commit:`a16e1c4d13c7071fabe6a5a46b6d6c0fd9565b72`
  * Add :class:`lief.MachO.SubFramework` command: :commit:`9e3b5b45f78cc075f2192c245247af00b88b5e3c`
  * Add :class:`lief.MachO.SegmentSplitInfo` command: :commit:`9e3b5b45f78cc075f2192c245247af00b88b5e3c`
  * Add :class:`lief.MachO.DyldEnvironment` command: :commit:`9e3b5b45f78cc075f2192c245247af00b88b5e3c`
  * API to show export-trie, rebase and binding opcodes: :commit:`5d56141061bfc27e3c971e9e474dc86fdaf0c6a9`


:PE:

  * Add PE Code View: :commit:`eab4a7614fdf6e9a180b1c638903310da0b83118`


:ELF:

  * Add support for ``.note.android.ident`` section: :commit:`d13db18214006ce654b723a882f70c3d7eabd20d`
  * Enable to add unlimited number of dynamic entries: :commit:`a40da3e3b4b985b18a6e6026d594f524b7bae963`
  * Add support for PPC relocations: :commit:`08b514191f661eeabbdf8ecacd1d7dd35a67ca54`
  * Endianness support: :commit:`e794ac1502ee7636755bd441923368f88525a7d0`

API
***

  * :func:`lief.breakp` and :func:`lief.shell`
  * :func:`lief.parse` now support ``io`` streams as input
  * Parser now returns a ``std::unique_ptr`` instead of a raw pointer: :commit:`cd1cc457cf3d63cfc5faa945657887200cedb8b3`

Misc
****

* Use `frozen <https://github.com/serge-sans-paille/frozen>`_ for some internal ``std::map`` (If C++14 is supported by the compiler)

Acknowledgements
****************

* :github_user:`yd0b0N` for :pr:`162` and :pr:`166` (Endianness support and PPC relocations)
* :github_user:`0xbf00` for :pr:`128` (``LC_RPATH`` command)
* :github_user:`illera88` for :pr:`118`


0.8.3
-----

* [Mach-O] Fix typo on comparison operator - :commit:`abbc264833894973f601f700b3abcc109904f722`

0.8.2
-----

* [ELF] Increase the upper limit of relocation number - :commit:`077bc329bdcc249cb8ed0b8bcb9630e1c9eede94`

0.8.1 - October 18, 2017
------------------------

* Fix an alignment issue in the ELF builder. See :commit:`8db199c04e9e6bcdbda165ab5c42d88218a0beb6`
* Add assertion on the setuptools version: :commit:`62e5825e27bb637c2f42f4d05690a100213beb03`


0.8.0 - October 16, 2017
------------------------

LIEF 0.8.0 mainly improves the MachO parser and the ELF builder. It comes with `Dockerfiles <https://github.com/lief-project/Dockerlief>`_ for `CentOS <https://github.com/lief-project/Dockerlief/blob/v0.1.0/dockerlief/dockerfiles/centos.docker>`_ and `Android <https://github.com/lief-project/Dockerlief/blob/v0.1.0/dockerlief/dockerfiles/android.docker>`_.

`LibFuzzer <https://llvm.org/docs/LibFuzzer.html>`_ has also been integrated in the project to enhance the parsers


Features
********


:Abstract Layer:

  * :class:`~lief.Relocation` are now abstracted from the 3 formats - :commit:`9503f2fc7b6c14bebd4c220bda4a243d87f14bd1`
  * ``PIE`` and ``NX`` are abstracted through the :attr:`~lief.Binary.is_pie` and :attr:`~lief.Binary.has_nx` properties
  * Add the :meth:`lief.Section.search` and :meth:`lief.Section.search_all` methods to look for patterns in the section's content.

:ELF:

  * ``DT_FLAGS`` and ``DT_FLAGS_1`` are now parsed into :class:`~lief.ELF.DynamicEntryFlags` - :commit:`754b8afa2b41993e6c37d2d9003cebdccc641d23`
  * Handle relocations of object files (``.o``) - :commit:`483b8dc2eabee3da29ce5e5ff2e25c2a3c9ca297`

  * Global enhancement of the ELF builder:

    One can now add **multiple** :class:`~lief.ELF.Section` or :class:`~lief.ELF.Segment` into an ELF:

    .. code-block:: python

      elf = lief.parse("/bin/cat")

      for i in range(3):
        segment = Segment()
        segment.type = SEGMENT_TYPES.LOAD
        segment.content = [i & 0xFF] * 0x1000
        elf += segment


      for i in range(3):
        section = Section("lief_{:02d}".format(i))
        section.content = [i & 0xFF] * 0x1000
        elf += section

      elf.write("foo")

    .. code-block:: console

      $ readelf -l ./foo
      PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                     0x00000000000061f8 0x00000000000061f8  R E    0x8
      INTERP         0x0000000000006238 0x0000000000006238 0x0000000000006238
                     0x000000000000001c 0x000000000000001c  R      0x1
          [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
      LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                     0x000000000000d6d4 0x000000000000d6d4  R E    0x200000
      LOAD           0x000000000000da90 0x000000000020da90 0x000000000020da90
                     0x0000000000000630 0x00000000000007d0  RW     0x200000
      LOAD           0x000000000000f000 0x000000000040f000 0x000000000040f000
                     0x0000000000001000 0x0000000000001000         0x1000
      LOAD           0x0000000000010000 0x0000000000810000 0x0000000000810000
                     0x0000000000001000 0x0000000000001000         0x1000
      LOAD           0x0000000000011000 0x0000000001011000 0x0000000001011000
                     0x0000000000001000 0x0000000000001000         0x1000
      ....

      $ readelf -S ./foo
      ...
      [27] lief_00           PROGBITS         0000000002012000  00012000
           0000000000001000  0000000000000000           0     0     4096
      [28] lief_01           PROGBITS         0000000004013000  00013000
           0000000000001000  0000000000000000           0     0     4096
      [29] lief_02           PROGBITS         0000000008014000  00014000
           0000000000001000  0000000000000000           0     0     4096

    .. warning::

      There are issues with executables statically linked with libraries that use ``TLS``

      See: :issue:`98`




    One can now add **multiple** entries in the dynamic table:

    .. code-block:: python

      elf = lief.parse("/bin/cat")

      elf.add_library("libfoo.so")
      elf.add(DynamicEntryRunPath("$ORIGIN"))
      elf.add(DynamicEntry(DYNAMIC_TAGS.INIT, 123))
      elf.add(DynamicSharedObject("libbar.so"))

      elf.write("foo")

    .. code-block:: console

      $ readelf -d foo
        0x0000000000000001 (NEEDED)  Shared library: [libfoo.so]
        0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
        0x000000000000000c (INIT)    0x7b
        0x000000000000000c (INIT)    0x3600
        ...
        0x000000000000001d (RUNPATH) Bibliothèque runpath:[$ORIGIN]
        0x000000000000000e (SONAME)  Bibliothèque soname: [libbar.so]

    See :commit:`b94900ca7f500912bfe249cd534055942e28e34b`, :commit:`1e410e6c950c391f0d1a3f12cb6f8e4c9fb16539` for details.

  * :commit:`b2d36940f60eacfa602c115cb542e11c70b6841c` enables modification of the ELF interpreter without **length restriction**

    .. code-block:: python

      elf = lief.parse("/bin/cat")
      elf.interpreter = "/a/very/long/path/to/another/interpreter"
      elf.write("foo")

    .. code-block:: console

      $ readelf -l foo
      Program Headers:
      Type           Offset             VirtAddr           PhysAddr
                     FileSiz            MemSiz              Flags  Align
      PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                     0x00000000000011f8 0x00000000000011f8  R E    0x8
      INTERP         0x000000000000a000 0x000000000040a000 0x000000000040a000
                     0x0000000000001000 0x0000000000001000  R      0x1
          [Requesting program interpreter: /a/very/long/path/to/another/interpreter]
      ....

  * Enhancement of the dynamic symbols counting - :commit:`985d1249b72494a0e62f34042b3c9cbfa0706e90`
  * Enable editing ELF's notes:

    .. code-block:: python

      elf = lief.parse("/bin/ls")
      build_id = elf[NOTE_TYPES.BUILD_ID]
      build_id.description = [0xFF] * 20
      elf.write("foo")

    .. code-block:: console

      $ readelf -n foo
      Displaying notes found in: .note.gnu.build-id
      Owner                 Data size Description
      GNU                  0x00000014 NT_GNU_BUILD_ID (unique build ID bitstring)
        Build ID: ffffffffffffffffffffffffffffffffffffffff

    See commit :commit:`3be9dd0ff58ec68cb8813e01d6798c16b42dac22` for more details

:PE:

  * Add :func:`~lief.PE.get_imphash` and :func:`~lief.PE.resolve_ordinals` functions - :commit:`a89bc6df4f242d7641292acdb184927449d14fff`, :commit:`dfa8e985c0561427a20088750693a004de587b1c`
  * Parse the *Load Config Table* into :class:`~lief.PE.LoadConfiguration` (up to Windows 10 SDK 15002 with *hotpatch_table_offset*)

    .. code-block:: python

      from lief import to_json
      import json
      pe = lief.parse("some.exe")
      loadconfig = to_json(pe.load_configuration)) # Using the lief.to_json function
      pprint(json.loads(to_json(loadconfig)))

    .. code-block:: javascript

      {'characteristics': 248,
       'code_integrity': {'catalog': 0,
                          'catalog_offset': 0,
                          'flags': 0,
                          'reserved': 0},
       'critical_section_default_timeout': 0,
       'csd_version': 0,
       'editlist': 0,
       ...
       'guard_cf_check_function_pointer': 5368782848,
       'guard_cf_dispatch_function_pointer': 5368782864,
       'guard_cf_function_count': 15,
       'guard_cf_function_table': 5368778752,
       'guard_flags': 66816,
       'guard_long_jump_target_count': 0,
       'guard_long_jump_target_table': 0,
       'guard_rf_failure_routine': 5368713280,
       'guard_rf_failure_routine_function_pointer': 5368782880,
       ...

    For details, see commit: :commit:`0234e3b8bbb6f6f3490392f8c295fde284a99334`




:MachO:

  * The ``dyld`` structure is parsed (deeply) into :class:`~lief.MachO.DyldInfo`. It includes:

    * Binding opcodes
    * Rebases opcodes
    * Export trie

    See: :commit:`e2b81e0a8e187cae5f0f115241243a84ee7696b6`, :commit:`0e972d69ce35731867d82c047eef7eb9ea58e3ec`, :commit:`f7cc518dcfbb0557fd8d396144bf99a222d96705`, :commit:`782295bfb86d2a12584c5b16a37a26d56d1ee235`, :issue:`67`

  * Section relocations are now parsed into :attr:`lief.MachO.Section.relocations` - :commit:`29c8157ecc3b308bd521cb1daee3c2e3a2cffb28`
  * ``LC_FUNCTION_STARTS`` is parsed into :class:`~lief.MachO.FunctionStarts` (:commit:`18d89198a0cc63ff291ae9110f465354c3b8f1e6`)
  * ``LC_SOURCE_VERSION``, ``LC_VERSION_MIN_MACOSX`` and ``LC_VERSION_MIN_IPHONEOS`` are
    parsed into :class:`~lief.MachO.SourceVersion` and :class:`~lief.MachO.VersionMin` (:commit:`c359778194db874669884aaccb52a4b05546bc07`, :commit:`0b4bb7d56520cd0ea08bbcb9530e5e0c96ac14ae`, :commit:`5b993117ed391db18ba775cabefa5f3981b2f1cc`, :issue:`45`)
  * ``LC_THREAD`` and ``LC_UNIXTHREAD`` are now parsed into :class:`~lief.MachO.ThreadCommand` - :commit:`23257830b291c40a3aed92360040f2b0b11ffa72`


Fixes
*****

Fix enums conflicts(:issue:`32`) - :commit:`66b4cd4550ecf6cf3adb4900e6ad7ac33f1f7f32`

Fix most of the memory leaks: :commit:`88dafa8db6e752393f69d73f68d295e91963b8da`, :commit:`d9b1436730b5d33a753e7dfa4301697a0c676066`, :commit:`554fa153af943b97a16fc4a52ab8459a3d0a9bc7`, :commit:`3602643f5d02a1c78c4de609cc47f193f3a8840f`

:ELF:

  * Bug Fix when counting dynamic symbols from the GnuHash Table - :commit:`9036a2405dc44726f40cb77cab1bcbf371ab7a70`

:PE:

  * Fix nullptr dereference in resources - :commit:`e90fe1b6c6f6a605390bcd1026435ce7503e7e6a`
  * Handle encoding issues in the Python API - `8c7ceaf <https://github.com/lief-project/LIEF/commit/8c7ceafa823bda508259bf3c7cdc05b865f13d5c>`_
  * Sanitize DLL names

:MachO:

  * Fix :issue:`87`, :issue:`92`
  * Fix memory leaks and *some* performance issues: :issue:`94`




API
***

In the C++ API ``get_XXX()`` getters have been renamed into ``XXX()`` (e.g. ``get_header()`` becomes ``header()``) - :commit:`a4c69f7868da1de5d09aa26e977dedb720e36cbd`, :commit:`e805669865b130057413f456958a471d8f0ac0b1`

:Abstract:

  * :class:`lief.Binary` gains the :attr:`~lief.Binary.format` property - :commit:`9391238f114fe963890777c2d8b90f2caaa5510c`
  * :func:`lief.parse` can now takes a list of integers - :commit:`f330fa887d14d47f0683144430ac9695d3136561`
  * Add :meth:`~lief.Binary.has_symbol` and :meth:`~lief.Binary.get_symbol` to :class:`lief.Binary` - :commit:`f121af5ca61a22fd83acc5c7094b50ed1cda8226`
  * [Python API] Enhance the access to the abstract layer through the :attr:`~lief.Binary.abstract` attribute - :commit:`07138549a46db87c7b924fd072356030b1d5c6bc`

    One can now do:

    .. code-block:: python

      elf = lief.ELF.parse("/bin/ls") # Could be lief.MachO / lief.PE
      abstract = elf.abstract # Return the lief.Binary object


:ELF:

  * Relocation gains the :attr:`~lief.ELF.Relocation.purpose` property - :commit:`b7b0bde4d51c54d8d226e5320b1b0d2cc48137c4`
  * Add :attr:`lief.ELF.Binary.symbols` which return an iterator over **all** symbols (static and dynamic) - :commit:`af6ab65dc91169627f4fbb87cda92093eb699a1e`
  * ``Header.sizeof_section_header`` has been renamed into :attr:`~lief.ELF.Header.section_header_size` - :commit:`d96971b0c3f8ff50add349957f571b8daa00708a`
  * ``Segment.flag`` has been renamed into :attr:`~lief.ELF.Segment.flags` - :commit:`20a5f666deb89b06b79a1c4418ac938497fb658c`
  * Add:

    * :attr:`~lief.ELF.Header.arm_flags_list`,
    * :attr:`~lief.ELF.Header.mips_flags_list`
    * :attr:`~lief.ELF.Header.ppc64_flags_list`
    * :attr:`~lief.ELF.Header.hexagon_flags_list`

    to :class:`~lief.ELF.Header` - :commit:`730d045e05dca7ef3cd6a51d1175f280be356c70`

    To check if a given flag is set, one can do:

    .. code-block:: python

      >>> if lief.ELF.ARM_EFLAGS.EABI_VER5 in lief.ELF.Header "yes" else "no"
  * [Python] Segment flags: ``PF_X``, ``PF_W``, ``PF_X`` has been renamed into :attr:`~lief.ELF.SEGMENT_FLAGS.X`, :attr:`~lief.ELF.SEGMENT_FLAGS.W`, :attr:`~lief.ELF.SEGMENT_FLAGS.X` - :commit:`d70ef9ec2c42619434352dbd7b74a835ebad7569`
  * Add :attr:`lief.ELF.Section.flags_list` - :commit:`4937b7193a5760df85d0ac1567afc011a22cdb98`
  * Enhancement for :attr:`~lief.ELF.DynamicEntryRpath` and :attr:`~lief.ELF.DynamicEntryRunPath`: :commit:`c375a47da7c4c524e886f9238f8dd51a44501087`
  * Enhancement for :attr:`~lief.ELF.DynamicEntryArray`: :commit:`81440ce00cdfc793161a0dc394ada345307dc24b`
  * Add some *operators*  :commit:`3b200b30503847be4779447c76f5207d18daf77f`, :commit:`43bd06f8f32196454ee2305201f4e27b3a3c8a1e`



:PE:
  * Add some *operators* :commit:`5666351e07b7bf4a9624033f670d02b8806d2663`

:MachO:

  * :func:`lief.MachO.parse` can now takes a list of integers - :commit:`f330fa887d14d47f0683144430ac9695d3136561`
  * :func:`lief.MachO.parse` now returns a :class:`~lief.MachO.FatBinary` instead of a ``list`` of :class:`~lief.MachO.Binary`. :class:`~lief.MachO.FatBinary` has a similar API as a list - :commit:`3602643f5d02a1c78c4de609cc47f193f3a8840f`
  * Add some *operators*: :commit:`cbe835484751396daffe7f8d238cbb85d66470ab`

:Logging:

  Add an API to configure the logger - :commit:`4600c2ba8d7d17b5965c2b74faeb7e4d2128de17`

  Example:

  .. code-block:: python

    from lief import Logger
    Logger.disable()
    Logger.enable()
    Logger.set_level(lief.LEVEL.INFO)

  See: :class:`lief.Logger`

Build system
************

* Add `FindLIEF.cmake <https://github.com/lief-project/LIEF/blob/e8ac976c994f6612e8dcca994032403c2d6f580f/scripts/FindLIEF.cmake>`_ - :commit:`6dd8b10325e832a7520bf5ae3a588b9e022d0345`
* Add ASAN, TSAN, USAN, LSAN - :commit:`7f6aeb0d0d74eae886f4b312e12e8f71e1d5da6a`
* Add LibFuzzer - :commit:`7a0dc28ea29a30209e944ebcde27f7c0ab234651`


Documentation
*************

:References:

  * recomposer, bearparser, IAT_patcher, PEframe, Manalyze, MachOView, elf-dissector


Acknowledgements
****************

* :github_user:`alvarofe` for :pr:`47`
* :github_user:`aguinet` for :pr:`55`, :pr:`61`, :pr:`65`, :pr:`77`
* :github_user:`jevinskie` for :pr:`75`
* :github_user:`liumuqing` for :pr:`80`
* :github_user:`Manouchehri` for :pr:`106`


0.7.0 - July 3, 2017
---------------------

Features
********

:Abstract Layer:

  * Add bitness (32bits / 64bits)  - :commit:`78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1`
  * Add object type (Library, executable etc)  - :commit:`78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1`
  * Add *mode* Thumbs, 16bits etc - :commit:`78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1`
  * Add endianness - :commit:`7ea08f72c43212f2e3f401b5c2c2614bc9aab8de`, :issue:`29`

:ELF:

  * Enable dynamic symbols permutation - :commit:`2dea7cb6d631b69995567e056a97e526f588b8ff`
  * Fully handle section-less binaries - :commit:`de40c068316b3334e4c8d81ecb3efc177ab24c3b`
  * Parse ELF notes  - :commit:`241aac7bedaf18ab5e3f0c9775a8a51cb0b40a3e`
  * Parse SYSV hash table  - :commit:`afa74cee88f730acef84fe6d9c984455a28463e7`, :issue:`36`
  * Add relocation size - :commit:`f1766f2c297caed636c7f32730cd10b62bfcc757`

:PE:

  * Parse PE Overlay - :commit:`e0634c1cf6d12fbdc5bcc1745059005e46e5d805`
  * Enable PE Hooking - :commit:`24f6b7213647469e269ead9441d78204162d08ec`
  * Parse and rebuilt dos stub  - :commit:`3f0639712617007e2e0431cb5eeb9be204c5d74b`
  * Add a *resources manager* to provide an enhanced API over the resources - :commit:`8473c8e126f2a8f14728ad3f8ebb59c45ac55d2d`
  * Serialize PE objects into JSON - :commit:`673f5a36f0d339ad9390427292fa6e725b8fd907`, :issue:`18`
  * Parse Rich Header - :commit:`0893bd9b08f2248ae8f656ccd81b1be12e8ae57e`, :issue:`15`

Bug Fixes
*********

:ELF:

  * Bug fix when a GNU hash has empty buckets - `21a6c30 <https://github.com/lief-project/LIEF/commit/21a6c3064bceead897392999ad66f14e03e5d530>`_

:PE:

  * Bug fix in the signature parser: :issue:`30`, :commit:`4af0256ce7c5577e0b1010c6f9b566634f0a3993`
  * Bug fix in the resources parser: Infinite loop - :commit:`a569cc13d99354ff96932460f5b1fd859378f252`
  * Add more *out-of-bounds* checks on relocations and exports - :commit:`9364f644e937a6a5d69c64c2ef4eaa1fbdd2cfad`
  * Use ``min(SizeOfRawData, VirtualSize)`` for the section's size and truncate the size to the file size - :commit:`61bf14ba1182fe458453599ff014de5d71d25680`


:MachO:

  * Bug fix when a binary hasn't a ``LC_MAIN`` command - :commit:`957501fe76596e0396c66d08540884876cea049c`

API
***

:Abstract Layer:

  * :attr:`lief.Header.is_32` and :attr:`lief.Header.is_64`
  * :attr:`lief.Header.object_type`
  * :attr:`lief.Header.modes`
  * :attr:`lief.Header.endianness`


:ELF:

  * :meth:`lief.ELF.Binary.permute_dynamic_symbols`
  * ``lief.ELF.Segment.data`` has been renamed to :attr:`lief.ELF.Segment.content`
  * :func:`lief.ELF.parse` takes an optional parameters: symbol counting - :class:`lief.ELF.DYNSYM_COUNT_METHODS`
  * :attr:`lief.ELF.Relocation.size`

  :Notes:

    * :class:`lief.ELF.Note`
    * :attr:`lief.ELF.Binary.has_notes`
    * :attr:`lief.ELF.Binary.notes`

  :Hash Tables:

    * :class:`lief.ELF.SysvHash`
    * :attr:`lief.ELF.Binary.use_gnu_hash`
    * :attr:`lief.ELF.Binary.use_sysv_hash`
    * :attr:`lief.ELF.Binary.sysv_hash`

:PE:

  * :attr:`lief.PE.Symbol.has_section`
  * :meth:`lief.PE.Binary.hook_function`
  * :meth:`lief.PE.Binary.get_content_from_virtual_address` takes either an **Absolute** virtual address or a **Relative** virtual address
  * ``lief.PE.Binary.section_from_virtual_address`` has been renamed to :meth:`lief.PE.Binary.section_from_rva`.
  * ``lief.PE.parse_from_raw`` has been removed. One can use :func:`lief.PE.parse`.
  * ``lief.PE.Section.data`` has been **removed**. Please use :attr:`lief.PE.Section.content`


  :Dos Stub:

    * :attr:`lief.PE.Binary.dos_stub`
    * :attr:`lief.PE.Builder.build_dos_stub`

  :Rich Header:

    * :attr:`lief.PE.Binary.rich_header`
    * :attr:`lief.PE.Binary.has_rich_header`
    * :class:`lief.PE.RichHeader`
    * :class:`lief.PE.RichEntry`

  :Overlay:

    * :attr:`lief.PE.Binary.overlay`
    * :attr:`lief.PE.Builder.build_overlay`

  :Imports:

    * :attr:`lief.PE.Binary.has_import`
    * :meth:`lief.PE.Binary.get_import`

  :Resources:

    * :attr:`lief.PE.Binary.resources`
    * :class:`lief.PE.ResourceData`
    * :class:`lief.PE.ResourceDirectory`
    * :class:`lief.PE.ResourceNode`
    * :class:`lief.PE.LangCodeItem`
    * :class:`lief.PE.ResourceDialog`
    * :class:`lief.PE.ResourceDialogItem`
    * :class:`lief.PE.ResourceFixedFileInfo`
    * :class:`lief.PE.ResourceIcon`
    * :class:`lief.PE.ResourceStringFileInfo`
    * :class:`lief.PE.ResourceVarFileInfo`
    * :class:`lief.PE.ResourceVersion`

:MachO:

  * :attr:`lief.MachO.Binary.has_entrypoint`
  * :attr:`lief.MachO.Symbol.demangled_name`

  :UUID:

    * :attr:`lief.MachO.Binary.has_uuid`
    * :attr:`lief.MachO.Binary.uuid`
    * :class:`lief.MachO.UUIDCommand`

  :Main Command:

    * :attr:`lief.MachO.Binary.has_main_command`
    * :attr:`lief.MachO.Binary.main_command`
    * :class:`lief.MachO.MainCommand`


  :Dylinker:

    * :attr:`lief.MachO.Binary.has_dylinker`
    * :attr:`lief.MachO.Binary.dylinker`
    * :class:`lief.MachO.DylinkerCommand`


Documentation
*************

:References:

  * elfsteem, pelook, PortEx, elfsharp, metasm, amoco, Goblin

:Tutorials:

  * `PE Hooking <tutorials/06_pe_hooking.html>`_, `Resources Manipulation <tutorials/07_pe_resource.html>`_

:Integration:

  * `XCode <installation.html#xcode-integration>`_, `CMake <installation.html#cmake-integration>`_

Acknowledgements
****************

* `ek0 <https://github.com/ek0>`_: :pr:`24`
* `ACSC-CyberLab <https://github.com/ACSC-CyberLab>`_: :pr:`33`, :pr:`34`, :pr:`37`, :pr:`39`
* Hyrum Anderson who pointed bugs in the PE parser
* My collegues for the feedbacks and suggestions (Adrien, SebK, Pierrick)

0.6.1 - April 6, 2017
----------------------

Bug Fixes
*********

:ELF:

  * Don't rely on :attr:`lief.ELF.Section.entry_size` to count symbols - :commit:`004c6769bec37e303bbe7aaceb49f4b05c8eec84`

API
***

:PE:

  * :attr:`lief.PE.TLS.has_section`
  * :attr:`lief.PE.TLS.has_data_directory`



Documentation
*************

:Integration:

  * `Visual Studio <installation.html#visual-studio-integration>`_

Acknowledgements
****************

* `Philippe <https://github.com/doegox>`_ for the proofreading.


0.6.0 - March 30, 2017
----------------------

First public release
