Changelog
=========


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
      Owner                 Data size	Description
      GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
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
    Logger.set_level(lief.LOGGING_LEVEL.INFO)

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
