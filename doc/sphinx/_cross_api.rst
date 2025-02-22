.. |demangle| lief-api:: LIEF.demangle()

    :rust:func:`lief::demangle`
    :py:func:`lief.demangle`
    :cpp:func:`LIEF::demangle`

.. |lief-dump| lief-api:: LIEF.dump()

    :rust:func:`lief::dump`
    :rust:func:`lief::dump_with_limit`
    :py:func:`lief.dump`
    :cpp:func:`LIEF::dump`

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

.. |lief-dwarf-function| lief-api:: lief.dwarf.Function

    :rust:struct:`lief::dwarf::Function`
    :py:class:`lief.dwarf.Function`
    :cpp:class:`LIEF::dwarf::Function`


.. |lief-dwarf-function-is-external| lief-api:: lief.dwarf.Function.is_external()

    :rust:method:`lief::dwarf::Function::is_external [struct]`
    :py:attr:`lief.dwarf.Function.is_external`
    :cpp:func:`LIEF::dwarf::Function::is_external`

.. |lief-dwarf-cu-imported-functions| lief-api:: lief.dwarf.CompilationUnit.imported_functions()

    :rust:method:`lief::dwarf::CompilationUnit::imported_functions [struct]`
    :py:attr:`lief.dwarf.CompilationUnit.imported_functions`
    :cpp:func:`LIEF::dwarf::CompilationUnit::imported_functions`

.. |lief-dwarf-debug-info| lief-api:: lief.dwarf.DebugInfo

    :rust:struct:`lief::dwarf::DebugInfo`
    :py:class:`lief.dwarf.DebugInfo`
    :cpp:class:`LIEF::dwarf::DebugInfo`

.. |lief-dwarf-load| lief-api:: lief.dwarf.load()

    :rust:func:`lief::dwarf::load`
    :py:func:`lief.dwarf.load`
    :cpp:func:`LIEF::dwarf::load`

.. |lief-dwarf-function-instructions| lief-api:: lief.dwarf.Function.instructions()

    :rust:method:`lief::dwarf::Function::instructions [struct]`
    :cpp:func:`LIEF::dwarf::Function::instructions`
    :py:attr:`lief.dwarf.Function.instructions`

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

.. |lief-pdb-buildmetadata| lief-api:: lief.pdb.BuildMetadata

    :rust:struct:`lief::pdb::BuildMetadata`
    :py:class:`lief.pdb.BuildMetadata`
    :cpp:class:`LIEF::pdb::BuildMetadata`

.. |lief-pdb-compilationunit-buildmetadata| lief-api:: lief.pdb.CompilationUnit.build_metadata()

    :rust:method:`lief::pdb::CompilationUnit::build_metadata [struct]`
    :py:attr:`lief.pdb.CompilationUnit.build_metadata`
    :cpp:func:`LIEF::pdb::CompilationUnit::build_metadata`


.. PE ==========================================================================

.. |lief-pe-parser-config| lief-api:: lief.PE.ParserConfig

    :rust:struct:`lief::pe::ParserConfig`
    :py:class:`lief.PE.ParserConfig`
    :cpp:class:`LIEF::PE::ParserConfig`

.. |lief-pe-parser-config-parse_exceptions| lief-api:: lief.PE.ParserConfig.parse_exceptions

    :rust:member:`lief::pe::ParserConfig::parse_exceptions [struct]`
    :py:attr:`lief.PE.ParserConfig.parse_exceptions`
    :cpp:member:`LIEF::PE::ParserConfig::parse_exceptions`

.. |lief-pe-parser-config-parse_arm64x_binary| lief-api:: lief.PE.ParserConfig.parse_arm64x_binary

    :rust:member:`lief::pe::ParserConfig::parse_arm64x_binary [struct]`
    :py:attr:`lief.PE.ParserConfig.parse_arm64x_binary`
    :cpp:member:`LIEF::PE::ParserConfig::parse_arm64x_binary`

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

.. |lief-pe-tls| lief-api:: lief.PE.TLS

    :rust:struct:`lief::pe::TLS`
    :py:class:`lief.PE.TLS`
    :cpp:class:`LIEF::PE::TLS`

.. |lief-pe-binary-exceptions| lief-api:: lief.PE.Binary

    :rust:method:`lief::pe::Binary::exceptions [struct]`
    :py:attr:`lief.PE.Binary.exceptions`
    :cpp:func:`LIEF::PE::Binary::exceptions`

.. |lief-pe-loadconfig| lief-api:: lief.PE.LoadConfiguration

    :rust:struct:`lief::pe::LoadConfiguration`
    :py:class:`lief.PE.LoadConfiguration`
    :cpp:class:`LIEF::PE::LoadConfiguration`

.. |lief-pe-chpe_metadata| lief-api:: lief.PE.CHPEMetadata

    :rust:enum:`lief::pe::CHPEMetadata`
    :py:class:`lief.PE.CHPEMetadata`
    :cpp:class:`LIEF::PE::CHPEMetadata`

.. |lief-pe-dynamic-relocation| lief-api:: lief.PE.DynamicRelocation

    :rust:enum:`lief::pe::DynamicRelocation`
    :py:class:`lief.PE.DynamicRelocation`
    :cpp:class:`LIEF::PE::DynamicRelocation`

.. |lief-pe-enclave-configuration| lief-api:: lief.PE.EnclaveConfiguration

    :rust:struct:`lief::pe::EnclaveConfiguration`
    :py:class:`lief.PE.EnclaveConfiguration`
    :cpp:class:`LIEF::PE::EnclaveConfiguration`

.. |lief-pe-volatile-metadata| lief-api:: lief.PE.VolatileMetadata

    :rust:struct:`lief::pe::VolatileMetadata`
    :py:class:`lief.PE.VolatileMetadata`
    :cpp:class:`LIEF::PE::VolatileMetadata`


.. |lief-pe-exceptioninfo| lief-api:: lief.PE.ExceptionInfo

    :rust:enum:`lief::pe::exception::RuntimeExceptionFunction`
    :py:class:`lief.PE.ExceptionInfo`
    :cpp:class:`LIEF::PE::ExceptionInfo`

.. |lief-pe-section-coff_string| lief-api:: lief.PE.Section.coff_string

    :rust:method:`lief::pe::Section::coff_string [struct]`
    :py:attr:`lief.PE.Section.coff_string`
    :cpp:func:`LIEF::PE::Section::coff_string`

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

.. |lief-pe-export-entry| lief-api:: lief.PE.ExportEntry

    :rust:struct:`lief::pe::export::Entry`
    :py:class:`lief.PE.ExportEntry`
    :cpp:class:`LIEF::PE::ExportEntry`

.. |lief-pe-binary-write| lief-api:: lief.PE.Binary.write()

    :rust:method:`lief::pe::Binary::write [struct]`
    :py:meth:`lief.PE.Binary.write`
    :cpp:func:`LIEF::PE::Binary::write`

.. |lief-pe-binary-signatures| lief-api:: lief.PE.Binary.signatures()

    :rust:method:`lief::pe::Binary::signatures [struct]`
    :py:attr:`lief.PE.Binary.signatures`
    :cpp:func:`LIEF::PE::Binary::signatures`

.. |lief-pe-binary-is_arm64ec| lief-api:: lief.PE.Binary.is_arm64ec()

    :rust:method:`lief::pe::Binary::is_arm64ec [struct]`
    :py:attr:`lief.PE.Binary.is_arm64ec`
    :cpp:func:`LIEF::PE::Binary::is_arm64ec`

.. |lief-pe-binary-is_arm64x| lief-api:: lief.PE.Binary.is_arm64x()

    :rust:method:`lief::pe::Binary::is_arm64x [struct]`
    :py:attr:`lief.PE.Binary.is_arm64x`
    :cpp:func:`LIEF::PE::Binary::is_arm64x`

.. |lief-pe-binary-nested_pe_binary| lief-api:: lief.PE.Binary.nested_pe_binary()

    :rust:method:`lief::pe::Binary::nested_pe_binary [struct]`
    :py:attr:`lief.PE.Binary.nested_pe_binary`
    :cpp:func:`LIEF::PE::Binary::nested_pe_binary`

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

.. |lief-pe-datadirectory| lief-api:: lief.PE.DataDirectory

    :rust:struct:`lief::pe::DataDirectory`
    :py:class:`lief.PE.DataDirectory`
    :cpp:class:`LIEF::PE::DataDirectory`

.. |lief-pe-datadirectory-content| lief-api:: lief.PE.DataDirectory.content()

    :rust:method:`lief::pe::DataDirectory::content [struct]`
    :py:attr:`lief.PE.DataDirectory.content`
    :cpp:func:`LIEF::PE::DataDirectory::content`

.. |lief-pe-resource-node-parse| lief-api:: lief.PE.ResourceNode.parse()

    :rust:method:`lief::pe::ResourceNode::from_slice [enum]`
    :py:func:`lief.PE.ResourceNode.parse`
    :cpp:func:`LIEF::PE::ResourceNode::parse`

.. |lief-pe-binary-remove-import| lief-api:: lief.PE.Binary.remove_import()

    :rust:method:`lief::pe::Binary::remove_import [struct]`
    :py:func:`lief.PE.Binary.remove_import`
    :cpp:func:`LIEF::PE::Binary::remove_import`

.. |lief-pe-binary-remove-all-import| lief-api:: lief.PE.Binary.remove_all_imports()

    :rust:method:`lief::pe::Binary::remove_all_imports [struct]`
    :py:func:`lief.PE.Binary.remove_all_imports`
    :cpp:func:`LIEF::PE::Binary::remove_all_imports`

.. |lief-pe-binary-add-import| lief-api:: lief.PE.Binary.add_import()

    :rust:method:`lief::pe::Binary::add_import [struct]`
    :py:func:`lief.PE.Binary.add_import`
    :cpp:func:`LIEF::PE::Binary::add_import`

.. |lief-pe-import-add-entry| lief-api:: lief.PE.Import.add_entry()

    :rust:method:`lief::pe::import::Import::add_entry_by_name [struct]`
    :py:func:`lief.PE.Import.add_entry`
    :cpp:func:`LIEF::PE::Import::add_entry`

.. |lief-pe-import| lief-api:: lief.PE.Import

    :rust:struct:`lief::pe::import::Import`
    :py:class:`lief.PE.Import`
    :cpp:class:`LIEF::PE::Import`

.. |lief-pe-importentry| lief-api:: lief.PE.ImportEntry

    :rust:struct:`lief::pe::import::ImportEntry`
    :py:class:`lief.PE.ImportEntry`
    :cpp:class:`LIEF::PE::ImportEntry`

.. |lief-pe-importentry-iat-address| lief-api:: lief.PE.ImportEntry.iat_address()

    :rust:method:`lief::pe::import::ImportEntry::iat_address [struct]`
    :py:attr:`lief.PE.ImportEntry.iat_address`
    :cpp:func:`LIEF::PE::ImportEntry::iat_address`

.. |lief-pe-builder-config-resolved_iat_cbk| lief-api:: lief.PE.Builder.config_t.resolved_iat_cbk

    :py:attr:`lief.PE.Builder.config_t.resolved_iat_cbk`
    :cpp:member:`LIEF::PE::Builder::config_t::resolved_iat_cbk`

.. |lief-pe-builder-config-imports| lief-api:: lief.PE.Builder.config_t.imports

    :rust:member:`lief::pe::builder::Config::imports [struct]`
    :py:attr:`lief.PE.Builder.config_t.imports`
    :cpp:member:`LIEF::PE::Builder::config_t::imports`

.. |lief-pe-builder-config-exports| lief-api:: lief.PE.Builder.config_t.exports

    :rust:member:`lief::pe::builder::Config::exports [struct]`
    :py:attr:`lief.PE.Builder.config_t.exports`
    :cpp:member:`LIEF::PE::Builder::config_t::exports`

.. |lief-pe-builder-config-export_section| lief-api:: lief.PE.Builder.config_t.export_section

    :rust:member:`lief::pe::builder::Config::export_section [struct]`
    :py:attr:`lief.PE.Builder.config_t.export_section`
    :cpp:member:`LIEF::PE::Builder::config_t::export_section`

.. |lief-pe-builder-config| lief-api:: lief.PE.Builder.config_t

    :rust:struct:`lief::pe::::builder::Config`
    :py:class:`lief.PE.Builder.config_t`
    :cpp:class:`LIEF::PE::Builder::config_t`

.. |lief-pe-import-remove-entry| lief-api:: lief.PE.Import.remove_entry

    :rust:method:`lief::pe::import::Import::remove_entry_by_name [struct]`
    :rust:method:`lief::pe::import::Import::remove_entry_by_ordinal [struct]`
    :py:func:`lief.PE.Import.remove_entry`
    :cpp:func:`LIEF::PE::Import::remove_entry`

.. |lief-pe-resource-manager| lief-api:: lief.PE.ResourcesManager

    :rust:struct:`lief::pe::resources::Manager`
    :py:class:`lief.PE.ResourcesManager`
    :cpp:class:`LIEF::PE::ResourcesManager`

.. |lief-pe-resourcestringtable| lief-api:: lief.PE.ResourceStringTable

    :py:class:`lief.PE.ResourceStringTable`
    :cpp:class:`LIEF::PE::ResourceStringTable`


.. |lief-pe-resource-node| lief-api:: lief.PE.ResourceNode

    :rust:enum:`lief::pe::resources::Node`
    :py:class:`lief.PE.ResourceNode`
    :cpp:class:`LIEF::PE::ResourceNode`

.. |lief-pe-resource-node-add-child| lief-api:: lief.PE.ResourceNode.add_child()

    :rust:method:`lief::pe::resources::NodeBase::add_child [trait]`
    :py:meth:`lief.PE.ResourceNode.add_child`
    :cpp:func:`LIEF::PE::ResourceNode::add_child`

.. |lief-pe-resource-node-remove-child| lief-api:: lief.PE.ResourceNode.delete_child()

    :rust:method:`lief::pe::resources::NodeBase::delete_child [trait]`
    :py:meth:`lief.PE.ResourceNode.delete_child`
    :cpp:func:`LIEF::PE::ResourceNode::delete_child`

.. |lief-pe-binary-resources| lief-api:: lief.PE.Binary.resources()

    :rust:method:`lief::pe::Binary::resources [struct]`
    :py:attr:`lief.PE.Binary.resources`
    :cpp:func:`LIEF::PE::Binary::resources`

.. |lief-pe-binary-set_resources| lief-api:: lief.PE.Binary.set_resources()

    :rust:method:`lief::pe::Binary::set_resources [struct]`
    :py:func:`lief.PE.Binary.set_resources`
    :cpp:func:`LIEF::PE::Binary::set_resources`

.. |lief-pe-debug| lief-api:: lief.PE.Debug

    :rust:enum:`lief::pe::debug::Entries`
    :py:class:`lief.PE.Debug`
    :cpp:class:`LIEF::PE::Debug`

.. |lief-pe-codeviewpdb| lief-api:: lief.PE.CodeViewPDB

    :rust:struct:`lief::pe::debug::CodeViewPDB`
    :py:class:`lief.PE.CodeViewPDB`
    :cpp:class:`LIEF::PE::CodeViewPDB`

.. |lief-pe-binary-clear-debug| lief-api:: lief.PE.Binary.clear_debug

    :rust:method:`lief::pe::Binary::clear_debug [struct]`
    :py:func:`lief.PE.Binary.clear_debug`
    :cpp:func:`LIEF::PE::Binary::clear_debug`

.. |lief-pe-binary-remove-debug| lief-api:: lief.PE.Binary.remove_debug

    :rust:method:`lief::pe::Binary::remove_debug [struct]`
    :py:func:`lief.PE.Binary.remove_debug`
    :cpp:func:`LIEF::PE::Binary::remove_debug`


.. |lief-pe-binary-add-debug-info| lief-api:: lief.PE.Binary.add_debug_info

    :rust:method:`lief::pe::Binary::add_debug_info [struct]`
    :py:func:`lief.PE.Binary.add_debug_info`
    :cpp:func:`LIEF::PE::Binary::add_debug_info`

.. |lief-pe-vcfeature| lief-api:: lief.PE.VCFeature

    :rust:struct:`lief::pe::debug::VCFeature`
    :py:class:`lief.PE.VCFeature`
    :cpp:class:`LIEF::PE::VCFeature`

.. |lief-pe-fpo| lief-api:: lief.PE.FPO

    :rust:struct:`lief::pe::debug::FPO`
    :py:class:`lief.PE.FPO`
    :cpp:class:`LIEF::PE::FPO`

.. |lief-pe-exdllcharacteristics| lief-api:: lief.PE.ExDllCharacteristics

    :rust:struct:`lief::pe::debug::ExDllCharacteristics`
    :py:class:`lief.PE.ExDllCharacteristics`
    :cpp:class:`LIEF::PE::ExDllCharacteristics`

.. |lief-pe-pdbchecksum| lief-api:: lief.PE.PDBChecksum

    :rust:struct:`lief::pe::debug::PDBChecksum`
    :py:class:`lief.PE.PDBChecksum`
    :cpp:class:`LIEF::PE::PDBChecksum`

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

    :rust:method:`lief::elf::Binary::write [struct]`
    :rust:method:`lief::elf::Binary::write_with_config [struct]`
    :py:meth:`lief.ELF.Binary.write`
    :cpp:func:`LIEF::ELF::Binary::write`

.. |lief-elf-aarch64pauth| lief-api:: lief.ELF.AArch64PAuth

    :py:class:`lief.ELF.AArch64PAuth`
    :cpp:class:`LIEF::ELF::AArch64PAuth`

.. |lief-elf-relocation-resolve| lief-api:: lief.ELF.Relocation.resolve()

    :rust:method:`lief::elf::Relocation::resolve [struct]`
    :rust:method:`lief::elf::Relocation::resolve_with_base_address [struct]`
    :py:func:`lief.ELF.Relocation.resolve`
    :cpp:func:`LIEF::ELF::Relocation::resolve`


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

    :rust:method:`lief::macho::Binary::write [struct]`
    :rust:method:`lief::macho::Binary::write_with_config [struct]`
    :py:meth:`lief.MachO.Binary.write`
    :cpp:func:`LIEF::MachO::Binary::write`

.. |lief-macho-fatbinary-write| lief-api:: lief.MachO.FatBinary.write()

    :py:meth:`lief.FatBinary.Binary.write`
    :cpp:func:`LIEF::FatBinary::Binary::write`

.. |lief-macho-parser-config| lief-api:: lief.MachO.ParserConfig

    :py:class:`lief.MachO.ParserConfig`
    :cpp:class:`LIEF::MachO::ParserConfig`

.. |lief-macho-builder-config| lief-api:: lief.MachO.Builder.config_t

    :rust:struct:`lief::pe::builder::Config`
    :py:class:`lief.MachO.Builder.config_t`
    :cpp:class:`LIEF::MachO::Builder::config_t`

.. |lief-macho-atom-info| lief-api:: lief.MachO.AtomInfo

    :rust:struct:`lief::macho::commands::AtomInfo`
    :py:class:`lief.MachO.AtomInfo`
    :cpp:class:`LIEF::MachO::AtomInfo`

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

.. |lief-dsc-dyldsharedcache-disassemble| lief-api:: lief.dsc.DyldSharedCache.disassemble()

    :rust:method:`lief::dsc::DyldSharedCache::disassemble [struct]`
    :py:meth:`lief.dsc.DyldSharedCache.disassemble`
    :cpp:func:`LIEF::dsc::DyldSharedCache::disassemble`

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

.. extended utils =============================================================

.. |lief-extended-version-info| lief-api:: lief.extended_version_info()

    :rust:func:`lief::extended_version_info`
    :cpp:func:`LIEF::extended_version_info`

.. assembly ====================================================================

.. |lief-disassemble| lief-api:: lief.Binary.disassemble()

    :rust:method:`lief::generic::Binary::disassemble [trait]`
    :rust:method:`lief::generic::Binary::disassemble_symbol [trait]`
    :rust:method:`lief::generic::Binary::disassemble_address [trait]`
    :rust:method:`lief::generic::Binary::disassemble_slice [trait]`
    :cpp:func:`LIEF::Binary::disassemble`
    :py:meth:`lief.Binary.disassemble`
    :py:meth:`lief.Binary.disassemble_from_bytes`

.. |lief-assemble| lief-api:: lief.Binary.assemble()

    :rust:method:`lief::generic::Binary::assemble [trait]`
    :cpp:func:`LIEF::Binary::assemble`
    :py:meth:`lief.Binary.assemble`

.. |lief-asm-instruction| lief-api:: lief.assembly.Instruction

    :rust:enum:`lief::assembly::Instructions`
    :cpp:class:`LIEF::assembly::Instruction`
    :py:class:`lief.assembly.Instruction`

.. |lief-asm-x86-instruction| lief-api:: lief.assembly.x86.Instruction

    :rust:struct:`lief::assembly::x86::Instruction`
    :cpp:class:`LIEF::assembly::x86::Instruction`
    :py:class:`lief.assembly.x86.Instruction`

.. |lief-asm-arm-instruction| lief-api:: lief.assembly.arm.Instruction

    :rust:struct:`lief::assembly::arm::Instruction`
    :cpp:class:`LIEF::assembly::arm::Instruction`
    :py:class:`lief.assembly.arm.Instruction`

.. |lief-asm-aarch64-instruction| lief-api:: lief.assembly.aarch64.Instruction

    :rust:struct:`lief::assembly::aarch64::Instruction`
    :cpp:class:`LIEF::assembly::aarch64::Instruction`
    :py:class:`lief.assembly.aarch64.Instruction`

.. |lief-asm-powerpc-instruction| lief-api:: lief.assembly.powerpc.Instruction

    :rust:struct:`lief::assembly::powerpc::Instruction`
    :cpp:class:`LIEF::assembly::powerpc::Instruction`
    :py:class:`lief.assembly.powerpc.Instruction`

.. |lief-asm-mips-instruction| lief-api:: lief.assembly.mips.Instruction

    :rust:struct:`lief::assembly::mips::Instruction`
    :cpp:class:`LIEF::assembly::mips::Instruction`
    :py:class:`lief.assembly.mips.Instruction`

.. |lief-asm-riscv-instruction| lief-api:: lief.assembly.riscv.Instruction

    :rust:struct:`lief::assembly::riscv::Instruction`
    :cpp:class:`LIEF::assembly::riscv::Instruction`
    :py:class:`lief.assembly.riscv.Instruction`

.. |lief-asm-ebpf-instruction| lief-api:: lief.assembly.ebpf.Instruction

    :rust:struct:`lief::assembly::ebpf::Instruction`
    :cpp:class:`LIEF::assembly::ebpf::Instruction`
    :py:class:`lief.assembly.ebpf.Instruction`
