.. |demangle| lief-api:: LIEF.demangle()

    :rust:func:`lief::demangle`
    :py:func:`lief.demangle`
    :cpp:func:`LIEF::demangle`

.. |get_int_from_virtual_address| lief-api:: LIEF.get_int_from_virtual_address()

    :rust:method:`lief::elf::Binary::get_int_from_virtual_address [struct]`
    :py:meth:`lief.Binary.get_int_from_virtual_address`
    :cpp:func:`LIEF::Binary::get_int_from_virtual_address`

.. ObjC ==========================================================================

.. |lief-objc-metadata| lief-api:: lief.ObjC.Metadata

    :rust:struct:`lief::objc::Metadata`
    :py:class:`lief.objc.Metadata`
    :cpp:class:`LIEF::objc::Metadata`

.. |lief-objc-metadata-to_decl| lief-api:: lief.ObjC.Metadata.to_decl()

    :rust:method:`lief::objc::Metadata::to_decl [struct]`
    :py:meth:`lief.objc.Metadata.to_decl`
    :cpp:func:`LIEF::objc::Metadata::to_decl`

.. |lief-objc-method-address| lief-api:: lief.ObjC.Method.address()

    :rust:method:`lief::objc::Method::address [struct]`
    :py:attr:`lief.objc.Method.address`
    :cpp:func:`LIEF::objc::Method::address`

.. |lief-objc-metadata-to_decl_opt| lief-api:: lief.ObjC.Metadata.to_decl()

    :rust:method:`lief::objc::Metadata::to_decl_with_opt [struct]`
    :py:meth:`lief.objc.Metadata.to_decl`
    :cpp:func:`LIEF::objc::Metadata::to_decl`

.. |lief-objc-class-to_decl_opt| lief-api:: lief.ObjC.Class.to_decl()

    :rust:method:`lief::objc::Class::to_decl_with_opt [struct]`
    :py:meth:`lief.objc.Class.to_decl`
    :cpp:func:`LIEF::objc::Class::to_decl`

.. |lief-objc-proto-to_decl_opt| lief-api:: lief.ObjC.Protocol.to_decl()

    :rust:method:`lief::objc::Protocol::to_decl_with_opt [struct]`
    :py:meth:`lief.objc.Protocol.to_decl`
    :cpp:func:`LIEF::objc::Protocol::to_decl`

.. |lief-objc-declopt| lief-api:: lief.ObjC.DeclOpt

    :rust:struct:`lief::objc::DeclOpt`
    :py:class:`lief.objc.DeclOpt`
    :cpp:struct:`LIEF::objc::DeclOpt`

.. DWARF =======================================================================

.. |lief-dwarf-binary-debug-info| lief-api:: lief.Binary.debug_info()

    :rust:method:`lief::elf::Binary::debug_info [struct]`
    :py:attr:`lief.Binary.debug_info`
    :cpp:func:`LIEF::Binary::debug_info`

.. |lief-dwarf-debug-info| lief-api:: lief.dwarf.DebugInfo

    :rust:struct:`lief::dwarf::DebugInfo`
    :py:class:`lief.dwarf.DebugInfo`
    :cpp:class:`LIEF::dwarf::DebugInfo`

.. |lief-dwarf-load| lief-api:: lief.dwarf.load()

    :rust:func:`lief::dwarf::load`
    :py:func:`lief.dwarf.load`
    :cpp:func:`LIEF::dwarf::load`

.. PDB =========================================================================

.. |lief-pdb-binary-debug-info| lief-api:: lief.Binary.debug_info()

    :rust:method:`lief::pe::Binary::debug_info [struct]`
    :py:attr:`lief.Binary.debug_info`
    :cpp:func:`LIEF::Binary::debug_info`

.. |lief-pdb-debug-info| lief-api:: lief.pdb.DebugInfo

    :rust:struct:`lief::pdb::DebugInfo`
    :py:class:`lief.pdb.DebugInfo`
    :cpp:class:`LIEF::pdb::DebugInfo`

.. |lief-pdb-load| lief-api:: lief.pdb.load()

    :rust:func:`lief::pdb::load`
    :py:func:`lief.pdb.load`
    :cpp:func:`LIEF::pdb::load`

.. PE ==========================================================================

.. |lief-pe-parser-config| lief-api:: lief.PE.ParserConfig

    :py:class:`lief.PE.ParserConfig`
    :cpp:class:`LIEF::PE::ParserConfig`

.. |lief-pe-builder| lief-api:: lief.PE.Builder

    :py:class:`lief.PE.Builder`
    :cpp:class:`LIEF::PE::Builder`

.. |lief-pe-parse| lief-api:: lief.PE.parse()

    :rust:method:`lief::pe::Binary::parse [struct]`
    :py:func:`lief.PE.parse`
    :cpp:func:`LIEF::PE::Parser::parse`

.. |lief-pe-binary| lief-api:: lief.PE.Binary

    :rust:struct:`lief::pe::Binary`
    :py:class:`lief.PE.Binary`
    :cpp:class:`LIEF::PE::Binary`

.. |lief-pe-codeviewpdb-filename| lief-api:: lief.PE.CodeViewPDB.filename()

    :rust:method:`lief::pe::debug::CodeViewPDB::filename [struct]`
    :py:attr:`lief.PE.CodeViewPDB.filename`
    :cpp:func:`LIEF::PE::CodeViewPDB::filename`

.. |lief-pe-delayimportentry-demangled_name| lief-api:: lief.PE.DelayImportEntry.demangled_name()

    :rust:method:`lief::pe::delay_import::DelayImportEntry::demangled_name [struct]`
    :py:attr:`lief.PE.DelayImportEntry.demangled_name`
    :cpp:func:`LIEF::PE::DelayImportEntry::demangled_name`

.. |lief-pe-importentry-demangled_name| lief-api:: lief.PE.ImportEntry.demangled_name()

    :rust:method:`lief::pe::import::ImportEntry::demangled_name [struct]`
    :py:attr:`lief.PE.ImportEntry.demangled_name`
    :cpp:func:`LIEF::PE::ImportEntry::demangled_name`

.. |lief-pe-exportentry-demangled_name| lief-api:: lief.PE.ExportEntry.demangled_name()

    :rust:method:`lief::pe::export::Entry::demangled_name [struct]`
    :py:attr:`lief.PE.ExportEntry.demangled_name`
    :cpp:func:`LIEF::PE::ExportEntry::demangled_name`

.. |lief-pe-binary-write| lief-api:: lief.PE.Binary.write()

    :py:meth:`lief.PE.Binary.write`
    :cpp:func:`LIEF::PE::Binary::write`

.. |lief-pe-binary-signatures| lief-api:: lief.PE.Binary.signatures()

    :rust:method:`lief::pe::Binary::signatures [struct]`
    :py:attr:`lief.PE.Binary.signatures`
    :cpp:func:`LIEF::PE::Binary::signatures`

.. |lief-pe-signature| lief-api:: lief.PE.Signature

    :rust:struct:`lief::pe::Signature`
    :py:class:`lief.PE.Signature`
    :cpp:class:`LIEF::PE::Signature`

.. |lief-pe-signature-check| lief-api:: lief.PE.Signature.check()

    :rust:method:`lief::pe::Signature::check [struct]`
    :py:meth:`lief.PE.Signature.check`
    :cpp:func:`LIEF::PE::Signature::check`

.. |lief-pe-binary-verify_signature| lief-api:: lief.PE.Binary.verify_signature()

    :rust:method:`lief::pe::Binary::verify_signature [struct]`
    :py:meth:`lief.PE.Binary.verify_signature`
    :cpp:func:`LIEF::PE::Binary::verify_signature`

.. Abstract ====================================================================

.. |lief-abstract-binary| lief-api:: lief.abstract.Binary

    :rust:trait:`lief::generic::Binary`
    :py:class:`lief.Binary`
    :cpp:class:`LIEF::Binary`

.. |lief-abstract-parse| lief-api:: lief.abstract.parse

    :py:func:`lief.parse`
    :cpp:func:`LIEF::Parser::parse`

.. |lief-header-architectures| lief-api:: lief.Header.ARCHITECTURES

    :py:class:`lief.Header.ARCHITECTURES`
    :cpp:enum:`LIEF::Header::ARCHITECTURES`

.. |lief-header-modes| lief-api:: lief.Header.MODES

    :py:class:`lief.Header.MODES`
    :cpp:enum:`LIEF::Header::MODES`

.. |lief-header-object-types| lief-api:: lief.Header.OBJECT_TYPES

    :py:class:`lief.Header.OBJECT_TYPES`
    :cpp:enum:`LIEF::Header::OBJECT_TYPES`

.. |lief-header-endianness| lief-api:: lief.Header.ENDIANNESS

    :py:class:`lief.Header.ENDIANNESS`
    :cpp:enum:`LIEF::Header::ENDIANNESS`


.. ELF =========================================================================

.. |lief-elf-symbol-demangled_name| lief-api:: lief.ELF.Symbol.demangled_name()

    :rust:method:`lief::elf::Symbol::demangled_name [struct]`
    :py:attr:`lief.ELF.Symbol.demangled_name`
    :cpp:func:`LIEF::ELF::Symbol::demangled_name`

.. |lief-elf-parse| lief-api:: lief.ELF.parse()

    :rust:method:`lief::elf::Binary::parse [struct]`
    :py:func:`lief.ELF.parse`
    :cpp:func:`LIEF::ELF::Parser::parse`

.. |lief-elf-parser-config| lief-api:: lief.ELF.ParserConfig

    :py:class:`lief.ELF.ParserConfig`
    :cpp:class:`LIEF::ELF::ParserConfig`

.. |lief-elf-builder-config| lief-api:: lief.ELF.Builder.config_t

    :py:class:`lief.ELF.Builder.config_t`
    :cpp:struct:`LIEF::ELF::Builder::config_t`

.. |lief-elf-binary| lief-api:: lief.ELF.Binary

    :rust:struct:`lief::elf::Binary`
    :py:class:`lief.ELF.Binary`
    :cpp:class:`LIEF::ELF::Binary`

.. |lief-elf-binary-target-android| lief-api:: lief.ELF.Binary.is_targeting_android

    :rust:method:`lief::elf::Binary::is_targeting_android [struct]`
    :py:attr:`lief.ELF.Binary.is_targeting_android`
    :cpp:func:`LIEF::ELF::Binary::is_targeting_android`

.. |lief-elf-binary-write| lief-api:: lief.ELF.Binary.write()

    :py:meth:`lief.ELF.Binary.write`
    :cpp:func:`LIEF::ELF::Binary::write`

.. |lief-elf-aarch64pauth| lief-api:: lief.ELF.AArch64PAuth

    :py:class:`lief.ELF.AArch64PAuth`
    :cpp:class:`LIEF::ELF::AArch64PAuth`

.. Mach-O ======================================================================

.. |lief-macho-binary| lief-api:: lief.MachO.Binary

    :rust:struct:`lief::macho::Binary`
    :py:class:`lief.MachO.Binary`
    :cpp:class:`LIEF::MachO::Binary`

.. |lief-macho-binary-objc-metadata| lief-api:: lief.MachO.Binary.objc_metadata

    :rust:method:`lief::macho::Binary::objc_metadata [struct]`
    :py:attr:`lief.MachO.Binary.objc_metadata`
    :cpp:func:`LIEF::MachO::Binary::objc_metadata`

.. |lief-macho-binary-is-ios| lief-api:: lief.MachO.Binary.is_ios()

    :rust:method:`lief::macho::Binary::is_ios [struct]`
    :py:attr:`lief.MachO.Binary.is_ios`
    :cpp:func:`LIEF::MachO::Binary::is_ios`

.. |lief-macho-binary-is-macos| lief-api:: lief.MachO.Binary.is_macos()

    :rust:method:`lief::macho::Binary::is_macos [struct]`
    :py:attr:`lief.MachO.Binary.is_macos`
    :cpp:func:`LIEF::MachO::Binary::is_macos`

.. |lief-macho-binary-platform| lief-api:: lief.MachO.Binary.platform()

    :rust:method:`lief::macho::Binary::platform [struct]`
    :py:attr:`lief.MachO.Binary.platform`
    :cpp:func:`LIEF::MachO::Binary::platform`

.. |lief-macho-binary-symbol_stubs| lief-api:: lief.MachO.Binary.symbol_stubs()

    :rust:method:`lief::macho::Binary::symbol_stubs [struct]`
    :py:attr:`lief.MachO.Binary.symbol_stubs`
    :cpp:func:`LIEF::MachO::Binary::symbol_stubs`

.. |lief-macho-stub| lief-api:: lief.MachO.Stub

    :rust:struct:`lief::macho::Stub`
    :py:class:`lief.MachO.Stub`
    :cpp:class:`LIEF::MachO::Stub`

.. |lief-macho-subclient| lief-api:: lief.MachO.SubClient

    :rust:struct:`lief::macho::commands::SubClient`
    :py:class:`lief.MachO.SubClient`
    :cpp:class:`LIEF::MachO::SubClient`

.. |lief-macho-routine| lief-api:: lief.MachO.Routine

    :rust:struct:`lief::macho::commands::Routine`
    :py:class:`lief.MachO.Routine`
    :cpp:class:`LIEF::MachO::Routine`

.. |lief-macho-dyldinfo| lief-api:: lief.MachO.DyldInfo

    :rust:struct:`lief::macho::commands::DyldInfo`
    :py:class:`lief.MachO.DyldInfo`
    :cpp:class:`LIEF::MachO::DyldInfo`

.. |lief-macho-chainedbindinginfo| lief-api:: lief.MachO.ChainedBindingInfo

    :rust:struct:`lief::macho::binding_info::Chained`
    :py:class:`lief.MachO.ChainedBindingInfo`
    :cpp:class:`LIEF::MachO::ChainedBindingInfo`

.. |lief-macho-indirectbindinginfo| lief-api:: lief.MachO.IndirectBindingInfo

    :rust:struct:`lief::macho::binding_info::Indirect`
    :py:class:`lief.MachO.IndirectBindingInfo`
    :cpp:class:`LIEF::MachO::IndirectBindingInfo`

.. |lief-macho-dynamicsymbolcommand| lief-api:: lief.MachO.DynamicSymbolCommand

    :rust:struct:`lief::macho::commands::DynamicSymbolCommand`
    :py:class:`lief.MachO.DynamicSymbolCommand`
    :cpp:class:`LIEF::MachO::DynamicSymbolCommand`

.. |lief-macho-binary-bindings| lief-api:: lief.MachO.Binary.bindings()

    :rust:method:`lief::macho::Binary::bindings [struct]`
    :py:attr:`lief.MachO.Binary.bindings`
    :cpp:func:`LIEF::MachO::Binary::bindings`

.. |lief-macho-symbol-demangled_name| lief-api:: lief.MachO.Symbol.demangled_name()

    :rust:method:`lief::macho::Symbol::demangled_name [struct]`
    :py:attr:`lief.MachO.Symbol.demangled_name`
    :cpp:func:`LIEF::MachO::Symbol::demangled_name`

.. |lief-macho-parse| lief-api:: lief.MachO.parse()

    :rust:method:`lief::macho::FatBinary::parse [struct]`
    :py:func:`lief.MachO.parse`
    :cpp:func:`LIEF::MachO::Parser::parse`

.. |lief-macho-fatbinary| lief-api:: lief.MachO.FatBinary

    :rust:struct:`lief::macho::FatBinary`
    :py:class:`lief.MachO.FatBinary`
    :cpp:class:`LIEF::MachO::FatBinary`

.. |lief-macho-binary-write| lief-api:: lief.MachO.Binary.write()

    :py:meth:`lief.MachO.Binary.write`
    :cpp:func:`LIEF::MachO::Binary::write`

.. |lief-macho-fatbinary-write| lief-api:: lief.MachO.FatBinary.write()

    :py:meth:`lief.FatBinary.Binary.write`
    :cpp:func:`LIEF::FatBinary::Binary::write`

.. |lief-macho-parser-config| lief-api:: lief.MachO.ParserConfig

    :py:class:`lief.MachO.ParserConfig`
    :cpp:class:`LIEF::MachO::ParserConfig`

.. |lief-macho-builder-config| lief-api:: lief.MachO.Builder.config_t

    :py:class:`lief.MachO.Builder.config_t`
    :cpp:class:`LIEF::MachO::Builder::config_t`

.. dyld shared cache ===========================================================

.. |lief-dsc-load| lief-api:: lief.dsc.load()

    :rust:func:`lief::dsc::load_from_path`
    :rust:func:`lief::dsc::load_from_files`
    :py:func:`lief.dsc.load`
    :cpp:func:`LIEF::dsc::load`

.. |lief-dsc-dyldsharedcache| lief-api:: lief.dsc.DyldSharedCache

    :rust:struct:`lief::dsc::DyldSharedCache`
    :py:class:`lief.dsc.DyldSharedCache`
    :cpp:class:`LIEF::dsc::DyldSharedCache`

.. |lief-dsc-dyldsharedcache-libraries| lief-api:: lief.dsc.DyldSharedCache.libraries()

    :rust:method:`lief::dsc::DyldSharedCache::libraries [struct]`
    :py:attr:`lief.dsc.DyldSharedCache.libraries`
    :cpp:func:`LIEF::dsc::DyldSharedCache::libraries`

.. |lief-dsc-dylib| lief-api:: lief.dsc.Dylib

    :rust:struct:`lief::dsc::Dylib`
    :py:class:`lief.dsc.Dylib`
    :cpp:class:`LIEF::dsc::Dylib`

.. |lief-dsc-dylib-eopt| lief-api:: lief.dsc.Dylib.extract_opt_t

    :rust:struct:`lief::dsc::dylib::ExtractOpt`
    :py:class:`lief.dsc.Dylib.extract_opt_t`
    :cpp:struct:`LIEF::dsc::Dylib::extract_opt_t`

.. |lief-dsc-dylib-eopt-fix_branches| lief-api:: lief.dsc.Dylib.extract_opt_t.fix_branches

    :rust:member:`lief::dsc::dylib::ExtractOpt::fix_branches [struct]`
    :py:attr:`lief.dsc.Dylib.extract_opt_t.fix_branches`
    :cpp:member:`LIEF::dsc::Dylib::extract_opt_t::fix_branches`

.. |lief-dsc-enable_cache| lief-api:: lief.dsc.enable_cache()

    :rust:func:`lief::dsc::enable_cache`
    :py:func:`lief.dsc.enable_cache`
    :cpp:func:`LIEF::dsc::enable_cache`

.. |lief-dsc-dylib-get| lief-api:: lief.dsc.Dylib.get()

    :rust:method:`lief::dsc::Dylib::get [struct]`
    :py:meth:`lief.dsc.Dylib.get`
    :cpp:func:`LIEF::dsc::Dylib::get`

.. |lief-dsc-dyldsharedcache-enable_caching| lief-api:: lief.dsc.DyldSharedCache.enable_caching

    :rust:method:`lief::dsc::DyldSharedCache::enable_caching [struct]`
    :py:meth:`lief.dsc.DyldSharedCache.enable_caching`
    :cpp:func:`LIEF::dsc::DyldSharedCache::enable_caching`

