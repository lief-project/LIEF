Changelog
=========

0.8.0 - XXXX
------------

Features
********


:Abstract Layer:

  * :class:`~lief.Relocation` are now abstracted from the 3 formats.
  * ``PIE`` and ``NX`` are abstracted through the :attr:`~lief.Binary.is_pie` and :attr:`~lief.Binary.has_nx` properties

:ELF:

  * DT_FLAGS and DT_FLAGS_1

:PE:

  * import hash / resolve ordinals


:MachO:

  * The ``dyld`` structure is parsed into :class:`~lief.MachO.DyldInfo`. It includes:
    * Binding opcodes
    * Rebases opcodes
    * Export trie

  * Section's relocations are now parsed. See: :attr:`lief.MachO.Section.relocations`
  * ``LC_FUNCTION_STARTS`` is parsed into :class:`~lief.MachO.FunctionStarts`
  * ``LC_SOURCE_VERSION``, ``LC_VERSION_MIN_MACOSX`` and ``LC_VERSION_MIN_IPHONEOS`` are
    parsed into :class:`~lief.MachO.SourceVersion` and :class:`~lief.MachO.VersionMin`


Bug Fixes
*********

Fix enums conflicts 66b4cd4550ecf6cf3adb4900e6ad7ac33f1f7f32

:ELF:

:PE:

  * Fix nullptr deref - `ce66916 <https://github.com/lief-project/LIEF/commit/ce6691682e231dbc9ebe97695229ee0afdc185a5>`_
  * Handle encoding issues in the Python API - `8c7ceaf <https://github.com/lief-project/LIEF/commit/8c7ceafa823bda508259bf3c7cdc05b865f13d5c>`_

  * Sanitize DLL name
  * Relocations (117f8663e57ff81369630a575b4a4d0695db29b6)

:MachO:



API
***

Logger --> configuration

:Abstract:

  * parser can take a list of integer

:ELF:

  * Relocation gains the :attr:`~lief.ELF.Relocation.purpose` property - `b7b0bde <https://github.com/lief-project/LIEF/commit/b7b0bde4d51c54d8d226e5320b1b0d2cc48137c4>`_
()
  * C++ get_XXX -> XXX
  * Header.sizeof_section_header -> section_header_size
  * Segment.flags -> segment.flags
  * Header flags (730d045e05dca7ef3cd6a51d1175f280be356c70)
  * 3b200b30503847be4779447c76f5207d18daf77f
  * 43bd06f8f32196454ee2305201f4e27b3a3c8a1e

:PE:

  * 5666351e07b7bf4a9624033f670d02b8806d2663

:MachO:

  * cbe835484751396daffe7f8d238cbb85d66470ab

TODO: Findlief.cmake
Make JSON related API optional

Documentation
*************

:References:

  * recomposer, bearparser, IAT_patcher, PEframe, Manalyze, MachOView, elf-dissector


Acknowledgements
****************

alvaro, aguinet

0.7.0 - July 3, 2017
---------------------

Features
********

:Abstract Layer:

  * Add bitness (32bits / 64bits)  - `78d1adb <https://github.com/lief-project/LIEF/commit/78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1>`_
  * Add object type (Library, executable etc)  - `78d1adb <https://github.com/lief-project/LIEF/commit/78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1>`_
  * Add *mode* Thumbs, 16bits etc - `78d1adb <https://github.com/lief-project/LIEF/commit/78d1adb41e8b0d21a6f6fe94014753ce68e0ffa1>`_
  * Add endianness - `7ea08f7 <https://github.com/lief-project/LIEF/commit/7ea08f72c43212f2e3f401b5c2c2614bc9aab8de>`_, `#29 <https://github.com/lief-project/LIEF/issues/29>`_

:ELF:

  * Enable dynamic symbols permutation - `2dea7cb <https://github.com/lief-project/LIEF/commit/2dea7cb6d631b69995567e056a97e526f588b8ff>`_
  * Fully handle section-less binaries - `de40c06 <https://github.com/lief-project/LIEF/commit/de40c068316b3334e4c8d81ecb3efc177ab24c3b>`_
  * Parse ELF notes  - `241aac7 <https://github.com/lief-project/LIEF/commit/241aac7bedaf18ab5e3f0c9775a8a51cb0b40a3e>`_
  * Parse SYSV hash table  - `afa74ce <https://github.com/lief-project/LIEF/commit/afa74cee88f730acef84fe6d9c984455a28463e7>`_, `#36 <https://github.com/lief-project/LIEF/issues/36>`_
  * Add relocation size - `f1766f2 <https://github.com/lief-project/LIEF/commit/f1766f2c297caed636c7f32730cd10b62bfcc757>`_

:PE:

  * Parse PE Overlay - `e0634c1 <https://github.com/lief-project/LIEF/commit/e0634c1cf6d12fbdc5bcc1745059005e46e5d805>`_
  * Enable PE Hooking - `24f6b72 <https://github.com/lief-project/LIEF/commit/24f6b7213647469e269ead9441d78204162d08ec>`_
  * Parse and rebuilt dos stub  - `3f06397 <https://github.com/lief-project/LIEF/commit/3f0639712617007e2e0431cb5eeb9be204c5d74b>`_
  * Add a *resources manager* to provide an enhanced API over the resources - `8473c8e <https://github.com/lief-project/LIEF/commit/8473c8e126f2a8f14728ad3f8ebb59c45ac55d2d>`_
  * Serialize PE objects into JSON - `673f5a3 <https://github.com/lief-project/LIEF/commit/673f5a36f0d339ad9390427292fa6e725b8fd907>`_, `#18 <https://github.com/lief-project/LIEF/issues/18>`_
  * Parse Rich Header - `0893bd9 <https://github.com/lief-project/LIEF/commit/0893bd9b08f2248ae8f656ccd81b1be12e8ae57e>`_, `#15 <https://github.com/lief-project/LIEF/issues/15>`_

Bug Fixes
*********

:ELF:

  * Bug fix when a GNU hash has empty buckets - `21a6c30 <https://github.com/lief-project/LIEF/commit/21a6c3064bceead897392999ad66f14e03e5d530>`_

:PE:

  * Bug fix in the signature parser: `#30 <https://github.com/lief-project/LIEF/issues/30>`_, `4af0256 <https://github.com/lief-project/LIEF/commit/4af0256ce7c5577e0b1010c6f9b566634f0a3993>`_
  * Bug fix in the resources parser: Infinite loop - `a569cc1 <https://github.com/lief-project/LIEF/commit/a569cc13d99354ff96932460f5b1fd859378f252>`_
  * Add more *out-of-bounds* checks on relocations and exports - `9364f64 <https://github.com/lief-project/LIEF/commit/9364f644e937a6a5d69c64c2ef4eaa1fbdd2cfad>`_
  * Use ``min(SizeOfRawData, VirtualSize)`` for the section's size and truncate the size to the file size - `61bf14b <https://github.com/lief-project/LIEF/commit/61bf14ba1182fe458453599ff014de5d71d25680>`_


:MachO:

  * Bug fix when a binary hasn't a ``LC_MAIN`` command - `957501f <https://github.com/lief-project/LIEF/commit/957501fe76596e0396c66d08540884876cea049c>`_

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

  * `ek0 <https://github.com/ek0>`_: `#24 <https://github.com/lief-project/LIEF/pull/24>`_
  * `ACSC-CyberLab <https://github.com/ACSC-CyberLab>`_: `#33 <https://github.com/lief-project/LIEF/pull/33>`_, `#34 <https://github.com/lief-project/LIEF/pull/34>`_, `#37 <https://github.com/lief-project/LIEF/pull/37>`_, `#39 <https://github.com/lief-project/LIEF/pull/39>`_
  * Hyrum Anderson who pointed bugs in the PE parser
  * My collegues for the feedbacks and suggestions (Adrien, SebK, Pierrick)

0.6.1 - April 6, 2017
----------------------

Bug Fixes
*********

:ELF:

  * Don't rely on :attr:`lief.ELF.Section.entry_size` to count symbols - `004c676 <https://github.com/lief-project/LIEF/commit/004c6769bec37e303bbe7aaceb49f4b05c8eec84>`_

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
