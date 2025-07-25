use autocxx::prelude::*;

include_cpp! {
    #include "LIEF/rust/LIEF.hpp"
    #include "LIEF/rust/Stream.hpp"
    #include "LIEF/rust/range.hpp"
    name!(autocxx_ffi)

    generate!("is_extended")
    generate!("extended_version_info")
    generate!("extended_version")
    generate!("version")
    generate!("demangle")
    generate!("dump")
    generate!("dump_with_limit")

    generate_pod!("Span")
    block_constructors!("Span")

    generate_pod!("LIEFVersion")
    block_constructors!("LIEFVersion")

    generate_pod!("Range")
    block_constructors!("Range")

    generate_pod!("DWARF_editor_Function_Range")
    block_constructors!("DWARF_editor_Function_Range")

    generate!("RustStream")
    block_constructors!("RustStream")

    generate!("DebugLocation")
    block_constructors!("DebugLocation")

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------
    generate!("LIEF_Logging")
    block_constructors!("LIEF_Logging")

    // -------------------------------------------------------------------------
    // Abstract
    // -------------------------------------------------------------------------
    generate!("AbstractBinary")
    block_constructors!("AbstractBinary")

    generate!("AbstractSymbol")
    block_constructors!("AbstractSymbol")

    generate!("AbstractSection")
    block_constructors!("AbstractSection")

    generate!("AbstractRelocation")
    block_constructors!("AbstractRelocation")

    generate!("AbstracDebugInfo")
    block_constructors!("AbstracDebugInfo")

    generate!("AbstractBinary_it_instructions")
    block_constructors!("AbstractBinary_it_instructions")

    generate!("AbstractBinary_it_functions")
    block_constructors!("AbstractBinary_it_functions")

    generate!("AbstractFunction")
    block_constructors!("AbstractFunction")

    // -------------------------------------------------------------------------
    // ELF
    // -------------------------------------------------------------------------
    generate!("ELF_Binary")

    generate_pod!("ELF_Binary_write_config_t")
    block_constructors!("ELF_Binary_write_config_t")

    generate!("ELF_ParserConfig")
    block_constructors!("ELF_ParserConfig")

    block_constructors!("Span")
    generate!("ELF_Binary_it_segments")
    block_constructors!("ELF_Binary_it_segments")
    generate!("ELF_Binary_it_sections")
    block_constructors!("ELF_Binary_it_sections")
    generate!("ELF_Binary_it_dynamic_entries")
    block_constructors!("ELF_Binary_it_dynamic_entries")
    generate!("ELF_Binary_it_dynamic_symbols")
    block_constructors!("ELF_Binary_it_dynamic_symbols")
    generate!("ELF_Binary_it_exported_symbols")
    block_constructors!("ELF_Binary_it_exported_symbols")
    generate!("ELF_Binary_it_imported_symbols")
    block_constructors!("ELF_Binary_it_imported_symbols")
    generate!("ELF_Binary_it_symtab_symbols")
    block_constructors!("ELF_Binary_it_symtab_symbols")
    generate!("ELF_Binary_it_notes")
    block_constructors!("ELF_Binary_it_notes")
    generate!("ELF_Binary_it_pltgot_relocations")
    block_constructors!("ELF_Binary_it_pltgot_relocations")
    generate!("ELF_Binary_it_dynamic_relocations")
    block_constructors!("ELF_Binary_it_dynamic_relocations")
    generate!("ELF_Binary_it_object_relocations")
    block_constructors!("ELF_Binary_it_object_relocations")
    generate!("ELF_Binary_it_symbols_version")
    block_constructors!("ELF_Binary_it_symbols_version")
    generate!("ELF_Binary_it_symbols_version_requirement")
    block_constructors!("ELF_Binary_it_symbols_version_requirement")
    generate!("ELF_Binary_it_symbols_version_definition")
    block_constructors!("ELF_Binary_it_symbols_version_definition")
    generate!("ELF_Binary_it_relocations")
    block_constructors!("ELF_Binary_it_relocations")
    generate!("ELF_DynamicEntry")
    block_constructors!("ELF_DynamicEntry")
    generate!("ELF_DynamicEntryArray")
    block_constructors!("ELF_DynamicEntryArray")
    generate!("ELF_DynamicEntryFlags")
    block_constructors!("ELF_DynamicEntryFlags")
    generate!("ELF_DynamicEntryLibrary")
    block_constructors!("ELF_DynamicEntryLibrary")
    generate!("ELF_DynamicEntryRpath")
    block_constructors!("ELF_DynamicEntryRpath")
    generate!("ELF_DynamicEntryRunPath")
    block_constructors!("ELF_DynamicEntryRunPath")
    generate!("ELF_DynamicSharedObject")
    block_constructors!("ELF_DynamicSharedObject")
    generate!("ELF_GnuHash")
    block_constructors!("ELF_GnuHash")
    generate!("ELF_Header")
    block_constructors!("ELF_Header")
    generate!("ELF_Relocation")
    block_constructors!("ELF_Relocation")
    generate!("ELF_Section")
    block_constructors!("ELF_Section")
    generate!("ELF_Segment")
    block_constructors!("ELF_Segment")
    generate!("ELF_Symbol")
    block_constructors!("ELF_Symbol")
    generate!("ELF_SymbolVersion")
    block_constructors!("ELF_SymbolVersion")
    generate!("ELF_SymbolVersionAux")
    block_constructors!("ELF_SymbolVersionAux")
    generate!("ELF_SymbolVersionAuxRequirement")
    block_constructors!("ELF_SymbolVersionAuxRequirement")
    generate!("ELF_SymbolVersionDefinition")
    block_constructors!("ELF_SymbolVersionDefinition")
    generate!("ELF_SymbolVersionDefinition_it_auxiliary_symbols")
    block_constructors!("ELF_SymbolVersionDefinition_it_auxiliary_symbols")
    generate!("ELF_SymbolVersionRequirement")
    block_constructors!("ELF_SymbolVersionRequirement")
    generate!("ELF_SymbolVersionRequirement_it_auxiliary_symbols")
    block_constructors!("ELF_SymbolVersionRequirement_it_auxiliary_symbols")
    generate!("ELF_SysvHash")
    block_constructors!("ELF_SysvHash")
    generate!("ELF_Utils")
    block_constructors!("ELF_Utils")
    generate!("ELF_Note")
    block_constructors!("ELF_Note")

    // -------------------------------------------------------------------------
    // PE
    // -------------------------------------------------------------------------
    generate!("PE_Binary")
    block_constructors!("PE_Binary")

    generate!("PE_Binary_write_config_t")
    block_constructors!("PE_Binary_write_config_t")

    generate!("PE_ParserConfig")
    block_constructors!("PE_ParserConfig")

    generate!("PE_Binary_it_debug")
    block_constructors!("PE_Binary_it_debug")
    generate!("PE_Binary_it_sections")
    block_constructors!("PE_Binary_it_sections")
    generate!("PE_Binary_it_relocations")
    block_constructors!("PE_Binary_it_relocations")
    generate!("PE_Binary_it_imports")
    block_constructors!("PE_Binary_it_imports")
    generate!("PE_Binary_it_delay_imports")
    block_constructors!("PE_Binary_it_delay_imports")
    generate!("PE_Binary_it_data_directories")
    block_constructors!("PE_Binary_it_data_directories")
    generate!("PE_Binary_it_signatures")
    block_constructors!("PE_Binary_it_signatures")
    generate!("PE_Binary_it_strings_table")
    block_constructors!("PE_Binary_it_strings_table")
    generate!("PE_Binary_it_symbols")
    block_constructors!("PE_Binary_it_symbols")
    generate!("PE_Binary_it_exceptions")
    block_constructors!("PE_Binary_it_exceptions")

    generate!("PE_CodeIntegrity")
    block_constructors!("PE_CodeIntegrity")
    generate!("PE_ContentInfo")
    block_constructors!("PE_ContentInfo")
    generate!("PE_ContentInfo_Content")
    block_constructors!("PE_ContentInfo_Content")
    generate!("PE_DataDirectory")
    block_constructors!("PE_DataDirectory")
    generate!("PE_DelayImport")
    block_constructors!("PE_DelayImport")
    generate!("PE_DelayImport_it_entries")
    block_constructors!("PE_DelayImport_it_entries")
    generate!("PE_DelayImportEntry")
    block_constructors!("PE_DelayImportEntry")
    generate!("PE_DosHeader")
    block_constructors!("PE_DosHeader")
    generate!("PE_Export")
    block_constructors!("PE_Export")
    generate!("PE_Export_it_entries")
    block_constructors!("PE_Export_it_entries")
    generate!("PE_ExportEntry")
    block_constructors!("PE_ExportEntry")
    generate!("PE_Header")
    block_constructors!("PE_Header")
    generate!("PE_Import")
    block_constructors!("PE_Import")
    generate!("PE_Import_it_entries")
    block_constructors!("PE_Import_it_entries")
    generate!("PE_ImportEntry")
    block_constructors!("PE_ImportEntry")
    generate!("PE_OptionalHeader")
    block_constructors!("PE_OptionalHeader")
    generate!("PE_Relocation")
    block_constructors!("PE_Relocation")
    generate!("PE_Relocation_it_entries")
    block_constructors!("PE_Relocation_it_entries")
    generate!("PE_RelocationEntry")
    block_constructors!("PE_RelocationEntry")
    generate!("PE_ResourceData")
    block_constructors!("PE_ResourceData")
    generate!("PE_ResourceDirectory")
    block_constructors!("PE_ResourceDirectory")
    generate!("PE_ResourceNode")
    block_constructors!("PE_ResourceNode")
    generate!("PE_ResourceNode_it_childs")
    block_constructors!("PE_ResourceNode_it_childs")
    generate!("PE_ResourcesManager")
    block_constructors!("PE_ResourcesManager")
    generate!("PE_RichEntry")
    block_constructors!("PE_RichEntry")
    generate!("PE_RichHeader")
    block_constructors!("PE_RichHeader")
    generate!("PE_RichHeader_it_entries")
    block_constructors!("PE_RichHeader_it_entries")
    generate!("PE_Section")
    block_constructors!("PE_Section")
    generate!("PE_SpcIndirectData")
    block_constructors!("PE_SpcIndirectData")
    generate!("PE_GenericContent")
    block_constructors!("PE_GenericContent")

    generate!("PE_Debug")
    block_constructors!("PE_Debug")
    generate!("PE_CodeView")
    block_constructors!("PE_CodeView")
    generate!("PE_CodeViewPDB")
    block_constructors!("PE_CodeViewPDB")
    generate!("PE_Pogo")
    block_constructors!("PE_Pogo")
    generate!("PE_Pogo_it_entries")
    block_constructors!("PE_Pogo_it_entries")
    generate!("PE_PogoEntry")
    block_constructors!("PE_PogoEntry")
    generate!("PE_Repro")
    block_constructors!("PE_Repro")
    generate!("PE_PDBChecksum")
    block_constructors!("PE_PDBChecksum")
    generate!("PE_VCFeature")
    block_constructors!("PE_VCFeature")
    generate!("PE_ExDllCharacteristics")
    block_constructors!("PE_ExDllCharacteristics")
    generate!("PE_FPO")
    block_constructors!("PE_FPO")
    generate!("PE_FPO_it_entries")
    block_constructors!("PE_FPO_it_entries")
    generate!("PE_FPO_entry_t")
    block_constructors!("PE_FPO_entry_t")
    generate!("PE_Signature")
    block_constructors!("PE_Signature")
    generate!("PE_Signature_it_signers")
    block_constructors!("PE_Signature_it_signers")
    generate!("PE_Signature_it_certificates")
    block_constructors!("PE_Signature_it_certificates")
    generate!("PE_SignerInfo")
    block_constructors!("PE_SignerInfo")
    generate!("PE_SignerInfo_it_authenticated_attributes")
    block_constructors!("PE_SignerInfo_it_authenticated_attributes")
    generate!("PE_SignerInfo_it_unauthenticated_attributes")
    block_constructors!("PE_SignerInfo_it_unauthenticated_attributes")
    generate!("PE_TLS")
    block_constructors!("PE_TLS")
    generate!("PE_Utils")
    block_constructors!("PE_Utils")
    generate!("PE_x509")
    block_constructors!("PE_x509")
    generate!("PE_RsaInfo")
    block_constructors!("PE_RsaInfo")
    generate!("PE_Attribute")
    block_constructors!("PE_Attribute")
    generate!("PE_ContentType")
    block_constructors!("PE_ContentType")
    generate!("PE_GenericType")
    block_constructors!("PE_GenericType")
    generate!("PE_MsSpcNestedSignature")
    block_constructors!("PE_MsSpcNestedSignature")
    generate!("PE_MsSpcStatementType")
    block_constructors!("PE_MsSpcStatementType")
    generate!("PE_PKCS9AtSequenceNumber")
    block_constructors!("PE_PKCS9AtSequenceNumber")
    generate!("PE_PKCS9CounterSignature")
    block_constructors!("PE_PKCS9CounterSignature")
    generate!("PE_PKCS9MessageDigest")
    block_constructors!("PE_PKCS9MessageDigest")
    generate!("PE_PKCS9SigningTime")
    block_constructors!("PE_PKCS9SigningTime")
    generate!("PE_SpcSpOpusInfo")
    block_constructors!("PE_SpcSpOpusInfo")
    generate!("PE_MsManifestBinaryID")
    block_constructors!("PE_MsManifestBinaryID")
    generate!("PE_MsCounterSign")
    block_constructors!("PE_MsCounterSign")
    generate!("PE_MsCounterSign_it_signers")
    block_constructors!("PE_MsCounterSign_it_signers")
    generate!("PE_MsCounterSign_it_certificates")
    block_constructors!("PE_MsCounterSign_it_certificates")
    generate!("PE_SpcRelaxedPeMarkerCheck")
    block_constructors!("PE_SpcRelaxedPeMarkerCheck")
    generate!("PE_PKCS9TSTInfo")
    block_constructors!("PE_PKCS9TSTInfo")
    generate!("PE_SigningCertificateV2")
    block_constructors!("PE_SigningCertificateV2")

    generate!("PE_LoadConfiguration")
    block_constructors!("PE_LoadConfiguration")

    generate!("PE_LoadConfiguration_guard_function_t")
    block_constructors!("PE_LoadConfiguration_guard_function_t")

    generate!("PE_LoadConfiguration_it_guard_cf_functions")
    block_constructors!("PE_LoadConfiguration_it_guard_cf_functions")

    generate!("PE_LoadConfiguration_it_guard_address_taken_iat_entries")
    block_constructors!("PE_LoadConfiguration_it_guard_address_taken_iat_entries")

    generate!("PE_LoadConfiguration_it_guard_long_jump_targets")
    block_constructors!("PE_LoadConfiguration_it_guard_long_jump_targets")

    generate!("PE_LoadConfiguration_it_dynamic_relocations")
    block_constructors!("PE_LoadConfiguration_it_dynamic_relocations")

    generate!("PE_LoadConfiguration_it_guard_eh_continuation")
    block_constructors!("PE_LoadConfiguration_it_guard_eh_continuation")

    generate!("PE_CHPEMetadata")
    block_constructors!("PE_CHPEMetadata")

    generate!("PE_CHPEMetadataARM64")
    block_constructors!("PE_CHPEMetadataARM64")

    generate!("PE_CHPEMetadataX86")
    block_constructors!("PE_CHPEMetadataX86")

    generate!("PE_CHPEMetadataARM64_it_const_range_entries")
    block_constructors!("PE_CHPEMetadataARM64_it_const_range_entries")

    generate!("PE_CHPEMetadataARM64_it_const_redirection_entries")
    block_constructors!("PE_CHPEMetadataARM64_it_const_redirection_entries")

    generate!("PE_CHPEMetadataARM64_range_entry_t")
    block_constructors!("PE_CHPEMetadataARM64_range_entry_t")

    generate!("PE_CHPEMetadataARM64_redirection_entry_t")
    block_constructors!("PE_CHPEMetadataARM64_redirection_entry_t")

    generate!("PE_ExceptionInfo")
    block_constructors!("PE_ExceptionInfo")

    generate!("PE_RuntimeFunctionX64")
    block_constructors!("PE_RuntimeFunctionX64")

    generate!("PE_RuntimeFunctionX64_unwind_info_t")
    block_constructors!("PE_RuntimeFunctionX64_unwind_info_t")

    generate!("PE_RuntimeFunctionX64_unwind_info_t_it_opcodes")
    block_constructors!("PE_RuntimeFunctionX64_unwind_info_t_it_opcodes")

    generate!("PE_unwind_x64_Code")
    block_constructors!("PE_unwind_x64_Code")

    generate!("PE_unwind_x64_Alloc")
    block_constructors!("PE_unwind_x64_Alloc")

    generate!("PE_unwind_x64_PushNonVol")
    block_constructors!("PE_unwind_x64_PushNonVol")

    generate!("PE_unwind_x64_PushMachFrame")
    block_constructors!("PE_unwind_x64_PushMachFrame")

    generate!("PE_unwind_x64_SetFPReg")
    block_constructors!("PE_unwind_x64_SetFPReg")

    generate!("PE_unwind_x64_SaveNonVolatile")
    block_constructors!("PE_unwind_x64_SaveNonVolatile")

    generate!("PE_unwind_x64_SaveXMM128")
    block_constructors!("PE_unwind_x64_SaveXMM128")

    generate!("PE_unwind_x64_Epilog")
    block_constructors!("PE_unwind_x64_Epilog")

    generate!("PE_unwind_x64_Spare")
    block_constructors!("PE_unwind_x64_Spare")

    generate!("PE_RuntimeFunctionAArch64")
    block_constructors!("PE_RuntimeFunctionAArch64")

    generate!("PE_unwind_aarch64_PackedFunction")
    block_constructors!("PE_unwind_aarch64_PackedFunction")

    generate!("PE_unwind_aarch64_UnpackedFunction")
    block_constructors!("PE_unwind_aarch64_UnpackedFunction")

    generate!("PE_unwind_aarch64_UnpackedFunction_epilog_scope_t")
    block_constructors!("PE_unwind_aarch64_UnpackedFunction_epilog_scope_t")

    generate!("PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes")
    block_constructors!("PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes")

    generate!("PE_DynamicRelocation")
    block_constructors!("PE_DynamicRelocation")

    generate!("PE_DynamicRelocationV1")
    block_constructors!("PE_DynamicRelocationV1")

    generate!("PE_DynamicRelocationV2")
    block_constructors!("PE_DynamicRelocationV2")

    generate!("PE_DynamicFixup")
    block_constructors!("PE_DynamicFixup")

    generate!("PE_DynamicFixupARM64Kernel")
    block_constructors!("PE_DynamicFixupARM64Kernel")

    generate!("PE_DynamicFixupARM64Kernel_entry")
    block_constructors!("PE_DynamicFixupARM64Kernel_entry")

    generate!("PE_DynamicFixupARM64Kernel_it_relocations")
    block_constructors!("PE_DynamicFixupARM64Kernel_it_relocations")

    generate!("PE_DynamicFixupARM64X")
    block_constructors!("PE_DynamicFixupARM64X")

    generate!("PE_DynamicFixupARM64X_entry")
    block_constructors!("PE_DynamicFixupARM64X_entry")
    generate!("PE_DynamicFixupARM64X_it_relocations")
    block_constructors!("PE_DynamicFixupARM64X_it_relocations")

    generate!("PE_DynamicFixupControlTransfer")
    block_constructors!("PE_DynamicFixupControlTransfer")

    generate!("PE_DynamicFixupControlTransfer_entry")
    block_constructors!("PE_DynamicFixupControlTransfer_entry")

    generate!("PE_DynamicFixupControlTransfer_it_relocations")
    block_constructors!("PE_DynamicFixupControlTransfer_it_relocations")

    generate!("PE_DynamicFixupGeneric")
    block_constructors!("PE_DynamicFixupGeneric")

    generate!("PE_DynamicFixupGeneric_it_relocations")
    block_constructors!("PE_DynamicFixupGeneric_it_relocations")

    generate!("PE_DynamicFixupUnknown")
    block_constructors!("PE_DynamicFixupUnknown")

    generate!("PE_FunctionOverride")
    block_constructors!("PE_FunctionOverride")

    generate!("PE_FunctionOverride_it_func_overriding_info")
    block_constructors!("PE_FunctionOverride_it_func_overriding_info")

    generate!("PE_FunctionOverride_it_bdd_info")
    block_constructors!("PE_FunctionOverride_it_bdd_info")

    generate!("PE_FunctionOverrideInfo")
    block_constructors!("PE_FunctionOverrideInfo")

    generate!("PE_FunctionOverride_image_bdd_dynamic_relocation_t")
    block_constructors!("PE_FunctionOverride_image_bdd_dynamic_relocation_t")

    generate!("PE_FunctionOverride_image_bdd_info_t")
    block_constructors!("PE_FunctionOverride_image_bdd_info_t")

    generate!("PE_FunctionOverride_image_bdd_info_t_it_relocations")
    block_constructors!("PE_FunctionOverride_image_bdd_info_t_it_relocations")

    generate!("PE_FunctionOverrideInfo_it_relocations")
    block_constructors!("PE_FunctionOverrideInfo_it_relocations")

    generate!("PE_EnclaveImport")
    block_constructors!("PE_EnclaveImport")

    generate!("PE_EnclaveConfiguration")
    block_constructors!("PE_EnclaveConfiguration")

    generate!("PE_EnclaveConfiguration_it_imports")
    block_constructors!("PE_EnclaveConfiguration_it_imports")

    generate!("PE_VolatileMetadata_range_t")
    block_constructors!("PE_VolatileMetadata_range_t")

    generate!("PE_VolatileMetadata")
    block_constructors!("PE_VolatileMetadata")

    generate!("PE_VolatileMetadata_it_ranges")
    block_constructors!("PE_VolatileMetadata_it_ranges")

    // -------------------------------------------------------------------------
    // Mach-O
    // -------------------------------------------------------------------------
    generate!("MachO_Binary")
    block_constructors!("MachO_Binary")

    generate_pod!("MachO_Binary_write_config_t")
    block_constructors!("MachO_Binary_write_config_t")

    generate!("MachO_Binary_it_stubs")
    block_constructors!("MachO_Binary_it_stubs")
    generate!("MachO_Binary_it_symbols")
    block_constructors!("MachO_Binary_it_symbols")
    generate!("MachO_Binary_it_relocations")
    block_constructors!("MachO_Binary_it_relocations")
    generate!("MachO_Binary_it_commands")
    block_constructors!("MachO_Binary_it_commands")
    generate!("MachO_Binary_it_symbols")
    block_constructors!("MachO_Binary_it_symbols")
    generate!("MachO_Binary_it_segments")
    block_constructors!("MachO_Binary_it_segments")
    generate!("MachO_Binary_it_sections")
    block_constructors!("MachO_Binary_it_sections")
    generate!("MachO_Binary_it_libraries")
    block_constructors!("MachO_Binary_it_libraries")
    generate!("MachO_Binary_it_sub_clients")
    block_constructors!("MachO_Binary_it_sub_clients")
    generate!("MachO_Binary_it_notes")
    block_constructors!("MachO_Binary_it_notes")
    generate!("MachO_Binary_it_bindings_info")
    block_constructors!("MachO_Binary_it_bindings_info")
    generate!("MachO_BindingInfo")
    block_constructors!("MachO_BindingInfo")
    generate!("MachO_BuildVersion")
    block_constructors!("MachO_BuildVersion")
    generate!("MachO_BuildToolVersion")
    block_constructors!("MachO_BuildToolVersion")
    generate!("MachO_ChainedBindingInfo")
    block_constructors!("MachO_ChainedBindingInfo")
    generate!("MachO_CodeSignature")
    block_constructors!("MachO_CodeSignature")
    generate!("MachO_CodeSignatureDir")
    block_constructors!("MachO_CodeSignatureDir")
    generate!("MachO_Command")
    block_constructors!("MachO_Command")
    generate!("MachO_DataCodeEntry")
    block_constructors!("MachO_DataCodeEntry")
    generate!("MachO_DataInCode")
    block_constructors!("MachO_DataInCode")
    generate!("MachO_Stub")
    block_constructors!("MachO_Stub")

    generate!("MachO_DataInCode_it_entries")
    block_constructors!("MachO_DataInCode_it_entries")

    generate!("MachO_DyldBindingInfo")
    block_constructors!("MachO_DyldBindingInfo")
    generate!("MachO_IndirectBindingInfo")
    block_constructors!("MachO_IndirectBindingInfo")
    generate!("MachO_DyldChainedFixups")
    block_constructors!("MachO_DyldChainedFixups")
    generate!("MachO_DyldChainedFixups_it_bindings")
    block_constructors!("MachO_DyldChainedFixups_it_bindings")
    generate!("MachO_DyldEnvironment")
    block_constructors!("MachO_DyldEnvironment")
    generate!("MachO_DyldExportsTrie")
    block_constructors!("MachO_DyldExportsTrie")
    generate!("MachO_DyldExportsTrie_it_exports")
    block_constructors!("MachO_DyldExportsTrie_it_exports")
    generate!("MachO_DyldInfo")
    block_constructors!("MachO_DyldInfo")
    generate!("MachO_DyldInfo_it_bindings")
    block_constructors!("MachO_DyldInfo_it_bindings")
    generate!("MachO_DyldInfo_it_exports")
    block_constructors!("MachO_DyldInfo_it_exports")
    generate!("MachO_Dylib")
    block_constructors!("MachO_Dylib")
    generate!("MachO_Dylinker")
    block_constructors!("MachO_Dylinker")
    generate!("MachO_DynamicSymbolCommand")
    block_constructors!("MachO_DynamicSymbolCommand")
    generate!("MachO_DynamicSymbolCommand_it_indirect_symbols")
    block_constructors!("MachO_DynamicSymbolCommand_it_indirect_symbols")
    generate!("MachO_EncryptionInfo")
    block_constructors!("MachO_EncryptionInfo")
    generate!("MachO_ExportInfo")
    block_constructors!("MachO_ExportInfo")
    generate!("MachO_FatBinary")
    block_constructors!("MachO_FatBinary")
    generate!("MachO_Fileset")
    block_constructors!("MachO_Fileset")
    generate!("MachO_AtomInfo")
    block_constructors!("MachO_AtomInfo")
    generate!("MachO_FunctionStarts")
    block_constructors!("MachO_FunctionStarts")
    generate!("MachO_FunctionVariants")
    block_constructors!("MachO_FunctionVariants")

    generate!("MachO_FunctionVariants_it_runtime_table")
    block_constructors!("MachO_FunctionVariants_it_runtime_table")

    generate!("MachO_FunctionVariants_RuntimeTable")
    block_constructors!("MachO_FunctionVariants_RuntimeTable")

    generate!("MachO_FunctionVariants_RuntimeTable_it_entries")
    block_constructors!("MachO_FunctionVariants_RuntimeTable_it_entries")

    generate!("MachO_FunctionVariants_RuntimeTableEntry")
    block_constructors!("MachO_FunctionVariants_RuntimeTableEntry")

    generate!("MachO_FunctionVariantFixups")
    block_constructors!("MachO_FunctionVariantFixups")
    generate!("MachO_Header")
    block_constructors!("MachO_Header")
    generate!("MachO_LinkerOptHint")
    block_constructors!("MachO_LinkerOptHint")
    generate!("MachO_Main")
    block_constructors!("MachO_Main")
    generate!("MachO_NoteCommand")
    block_constructors!("MachO_NoteCommand")
    generate!("MachO_Routine")
    block_constructors!("MachO_Routine")
    generate!("MachO_RPathCommand")
    block_constructors!("MachO_RPathCommand")
    generate!("MachO_Relocation")
    block_constructors!("MachO_Relocation")
    generate!("MachO_RelocationDyld")
    block_constructors!("MachO_RelocationDyld")
    generate!("MachO_RelocationFixup")
    block_constructors!("MachO_RelocationFixup")
    generate!("MachO_RelocationObject")
    block_constructors!("MachO_RelocationObject")
    generate!("MachO_Section")
    block_constructors!("MachO_Section")
    generate!("MachO_Section_it_relocations")
    block_constructors!("MachO_Section_it_relocations")
    generate!("MachO_SegmentCommand")
    block_constructors!("MachO_SegmentCommand")
    generate!("MachO_SegmentCommand_it_sections")
    block_constructors!("MachO_SegmentCommand_it_sections")
    generate!("MachO_SegmentCommand_it_relocations")
    block_constructors!("MachO_SegmentCommand_it_relocations")
    generate!("MachO_SegmentSplitInfo")
    block_constructors!("MachO_SegmentSplitInfo")
    generate!("MachO_SourceVersion")
    block_constructors!("MachO_SourceVersion")
    generate!("MachO_SubFramework")
    block_constructors!("MachO_SubFramework")
    generate!("MachO_SubClient")
    block_constructors!("MachO_SubClient")
    generate!("MachO_Symbol")
    block_constructors!("MachO_Symbol")
    generate!("MachO_SymbolCommand")
    block_constructors!("MachO_SymbolCommand")
    generate!("MachO_ThreadCommand")
    block_constructors!("MachO_ThreadCommand")
    generate!("MachO_TwoLevelHints")
    block_constructors!("MachO_TwoLevelHints")
    generate!("MachO_UUIDCommand")
    block_constructors!("MachO_UUIDCommand")
    generate!("MachO_Utils")
    block_constructors!("MachO_Utils")
    generate!("MachO_VersionMin")
    block_constructors!("MachO_VersionMin")
    generate!("MachO_UnknownCommand")
    block_constructors!("MachO_UnknownCommand")

    // -------------------------------------------------------------------------
    // PDB
    // -------------------------------------------------------------------------
    generate!("PDB_DebugInfo")
    block_constructors!("PDB_DebugInfo")
    generate!("PDB_DebugInfo_it_compilation_units")
    block_constructors!("PDB_DebugInfo_it_compilation_units")
    generate!("PDB_DebugInfo_it_types")
    block_constructors!("PDB_DebugInfo_it_types")
    generate!("PDB_DebugInfo_it_public_symbols")
    block_constructors!("PDB_DebugInfo_it_public_symbols")
    generate!("PDB_CompilationUnit")
    block_constructors!("PDB_CompilationUnit")
    generate!("PDB_PublicSymbol")
    block_constructors!("PDB_PublicSymbol")
    generate!("PDB_CompilationUnit_it_sources")
    block_constructors!("PDB_CompilationUnit_it_sources")
    generate!("PDB_CompilationUnit_it_functions")
    block_constructors!("PDB_CompilationUnit_it_functions")
    generate!("PDB_Function")
    block_constructors!("PDB_Function")
    generate!("PDB_Type")
    block_constructors!("PDB_Type")
    generate!("PDB_types_Simple")
    block_constructors!("PDB_types_Simple")
    generate!("PDB_types_Array")
    block_constructors!("PDB_types_Array")
    generate!("PDB_types_BitField")
    block_constructors!("PDB_types_BitField")
    generate!("PDB_types_ClassLike")
    block_constructors!("PDB_types_ClassLike")
    generate!("PDB_types_ClassLike_it_attributes")
    block_constructors!("PDB_types_ClassLike_it_attributes")
    generate!("PDB_types_ClassLike_it_methods")
    block_constructors!("PDB_types_ClassLike_it_methods")
    generate!("PDB_types_Class")
    block_constructors!("PDB_types_Class")
    generate!("PDB_types_Structure")
    block_constructors!("PDB_types_Structure")
    generate!("PDB_types_Interface")
    block_constructors!("PDB_types_Interface")
    generate!("PDB_types_Enum")
    block_constructors!("PDB_types_Enum")
    generate!("PDB_types_Function")
    block_constructors!("PDB_types_Function")
    generate!("PDB_types_Modifier")
    block_constructors!("PDB_types_Modifier")
    generate!("PDB_types_Pointer")
    block_constructors!("PDB_types_Pointer")
    generate!("PDB_types_Union")
    block_constructors!("PDB_types_Union")
    generate!("PDB_types_Attribute")
    block_constructors!("PDB_types_Attribute")
    generate!("PDB_types_Method")
    block_constructors!("PDB_types_Method")

    generate!("PDB_BuildMetadata")
    block_constructors!("PDB_BuildMetadata")

    // -------------------------------------------------------------------------
    // DWARF
    // -------------------------------------------------------------------------
    generate!("DWARF_DebugInfo")
    block_constructors!("DWARF_DebugInfo")
    generate!("DWARF_Editor")
    block_constructors!("DWARF_Editor")
    generate!("DWARF_editor_CompilationUnit")
    block_constructors!("DWARF_editor_CompilationUnit")

    generate!("DWARF_editor_Function")
    block_constructors!("DWARF_editor_Function")

    generate!("DWARF_editor_Function_Parameter")
    block_constructors!("DWARF_editor_Function_Parameter")

    generate!("DWARF_editor_Function_LexicalBlock")
    block_constructors!("DWARF_editor_Function_LexicalBlock")

    generate!("DWARF_editor_Function_Label")
    block_constructors!("DWARF_editor_Function_Label")

    generate!("DWARF_editor_Variable")
    block_constructors!("DWARF_editor_Variable")

    generate!("DWARF_editor_Type")
    block_constructors!("DWARF_editor_Type")

    generate!("DWARF_editor_PointerType")
    block_constructors!("DWARF_editor_PointerType")

    generate!("DWARF_editor_EnumType_Value")
    block_constructors!("DWARF_editor_EnumType_Value")

    generate!("DWARF_editor_EnumType")
    block_constructors!("DWARF_editor_EnumType")

    generate!("DWARF_editor_BaseType")
    block_constructors!("DWARF_editor_BaseType")

    generate!("DWARF_editor_ArrayType")
    block_constructors!("DWARF_editor_ArrayType")

    generate!("DWARF_editor_FunctionType_Parameter")
    block_constructors!("DWARF_editor_FunctionType_Parameter")

    generate!("DWARF_editor_FunctionType")
    block_constructors!("DWARF_editor_FunctionType")

    generate!("DWARF_editor_TypeDef")
    block_constructors!("DWARF_editor_TypeDef")

    generate!("DWARF_editor_FunctionType")
    block_constructors!("DWARF_editor_FunctionType")

    generate!("DWARF_editor_StructType_Member")
    block_constructors!("DWARF_editor_StructType_Member")

    generate!("DWARF_editor_StructType")
    block_constructors!("DWARF_editor_StructType")

    generate!("DWARF_DebugInfo_it_compilation_units")
    block_constructors!("DWARF_DebugInfo_it_compilation_units")
    generate!("DWARF_CompilationUnit")
    block_constructors!("DWARF_CompilationUnit")
    generate_pod!("DWARF_CompilationUnit_Language")
    block_constructors!("DWARF_CompilationUnit_Language")
    generate!("DWARF_Function")
    block_constructors!("DWARF_Function")
    generate!("DWARF_Parameter")
    block_constructors!("DWARF_Parameter")
    generate!("DWARF_parameters_Formal")
    block_constructors!("DWARF_parameters_Formal")
    generate!("DWARF_parameters_TemplateValue")
    block_constructors!("DWARF_parameters_TemplateValue")
    generate!("DWARF_parameters_TemplateType")
    block_constructors!("DWARF_parameters_TemplateType")
    generate!("DWARF_Function_it_variables")
    block_constructors!("DWARF_Function_it_variables")
    generate!("DWARF_Function_it_parameters")
    block_constructors!("DWARF_Function_it_parameters")
    generate!("DWARF_Function_it_thrown_types")
    block_constructors!("DWARF_Function_it_thrown_types")
    generate!("DWARF_Function_it_instructions")
    block_constructors!("DWARF_Function_it_instructions")
    generate!("DWARF_CompilationUnit_it_functions")
    block_constructors!("DWARF_CompilationUnit_it_functions")
    generate!("DWARF_CompilationUnit_it_types")
    block_constructors!("DWARF_CompilationUnit_it_types")
    generate!("DWARF_CompilationUnit_it_variables")
    block_constructors!("DWARF_CompilationUnit_it_variables")
    generate!("DWARF_Variable")
    block_constructors!("DWARF_Variable")
    generate!("DWARF_Type")
    block_constructors!("DWARF_Type")
    generate!("DWARF_types_ClassLike")
    block_constructors!("DWARF_types_ClassLike")
    generate!("DWARF_types_ClassLike_it_members")
    block_constructors!("DWARF_types_ClassLike_it_members")
    generate!("DWARF_types_ClassLike_it_functions")
    block_constructors!("DWARF_types_ClassLike_it_functions")
    generate!("DWARF_types_ClassLike_Member")
    block_constructors!("DWARF_types_ClassLike_Member")
    generate!("DWARF_types_Class")
    block_constructors!("DWARF_types_Class")
    generate!("DWARF_types_Structure")
    block_constructors!("DWARF_types_Structure")
    generate!("DWARF_types_Union")
    block_constructors!("DWARF_types_Union")
    generate!("DWARF_types_Packed")
    block_constructors!("DWARF_types_Packed")
    generate!("DWARF_types_Pointer")
    block_constructors!("DWARF_types_Pointer")
    generate!("DWARF_types_Const")
    block_constructors!("DWARF_types_Const")
    generate!("DWARF_types_Base")
    block_constructors!("DWARF_types_Base")
    generate!("DWARF_types_Array")
    block_constructors!("DWARF_types_Array")
    generate!("DWARF_types_array_size_info")
    block_constructors!("DWARF_types_array_size_info")
    generate!("DWARF_types_Typedef")
    block_constructors!("DWARF_types_Typedef")
    generate!("DWARF_types_Atomic")
    block_constructors!("DWARF_types_Atomic")
    generate!("DWARF_types_Coarray")
    block_constructors!("DWARF_types_Coarray")
    generate!("DWARF_types_Dynamic")
    block_constructors!("DWARF_types_Dynamic")
    generate!("DWARF_types_File")
    block_constructors!("DWARF_types_File")
    generate!("DWARF_types_Immutable")
    block_constructors!("DWARF_types_Immutable")
    generate!("DWARF_types_Interface")
    block_constructors!("DWARF_types_Interface")
    generate!("DWARF_types_PointerToMember")
    block_constructors!("DWARF_types_PointerToMember")
    generate!("DWARF_types_RValueReference")
    block_constructors!("DWARF_types_RValueReference")
    generate!("DWARF_types_Reference")
    block_constructors!("DWARF_types_Reference")
    generate!("DWARF_types_Restrict")
    block_constructors!("DWARF_types_Restrict")
    generate!("DWARF_types_SetTy")
    block_constructors!("DWARF_types_SetTy")
    generate!("DWARF_types_Shared")
    block_constructors!("DWARF_types_Shared")
    generate!("DWARF_types_StringTy")
    block_constructors!("DWARF_types_StringTy")
    generate!("DWARF_types_Subroutine")
    block_constructors!("DWARF_types_Subroutine")
    generate!("DWARF_types_Subroutine_it_parameters")
    block_constructors!("DWARF_types_Subroutine_it_parameters")
    generate!("DWARF_types_TemplateAlias")
    block_constructors!("DWARF_types_TemplateAlias")
    generate!("DWARF_types_TemplateAlias_it_parameters")
    block_constructors!("DWARF_types_TemplateAlias_it_parameters")
    generate!("DWARF_types_Thrown")
    block_constructors!("DWARF_types_Thrown")
    generate!("DWARF_types_Volatile")
    block_constructors!("DWARF_types_Volatile")
    generate!("DWARF_types_Enum")
    block_constructors!("DWARF_types_Enum")
    generate!("DWARF_Scope")
    block_constructors!("DWARF_Scope")

    // -------------------------------------------------------------------------
    // ObjC
    // -------------------------------------------------------------------------
    generate!("ObjC_Metadata")
    block_constructors!("ObjC_Metadata")
    generate!("ObjC_Metadata_it_classes")
    block_constructors!("ObjC_Metadata_it_classes")
    generate!("ObjC_Metadata_it_protocols")
    block_constructors!("ObjC_Metadata_it_protocols")

    generate!("ObjC_Class")
    block_constructors!("ObjC_Class")
    generate!("ObjC_Class_it_methods")
    block_constructors!("ObjC_Class_it_methods")
    generate!("ObjC_Class_it_protocols")
    block_constructors!("ObjC_Class_it_protocols")
    generate!("ObjC_Class_it_properties")
    block_constructors!("ObjC_Class_it_properties")
    generate!("ObjC_Class_it_ivars")
    block_constructors!("ObjC_Class_it_ivars")

    generate!("ObjC_IVar")
    block_constructors!("ObjC_IVar")

    generate!("ObjC_Method")
    block_constructors!("ObjC_Method")

    generate!("ObjC_Property")
    block_constructors!("ObjC_Property")

    generate!("ObjC_Protocol")
    block_constructors!("ObjC_Protocol")
    generate!("ObjC_Protocol_it_opt_methods")
    block_constructors!("ObjC_Protocol_it_opt_methods")
    generate!("ObjC_Protocol_it_req_methods")
    block_constructors!("ObjC_Protocol_it_req_methods")
    generate!("ObjC_Protocol_it_properties")
    block_constructors!("ObjC_Protocol_it_properties")

    generate_pod!("ObjC_DeclOpt")
    block_constructors!("ObjC_DeclOpt")

    // -------------------------------------------------------------------------
    // Dyld Shared Cache
    // -------------------------------------------------------------------------
    generate!("dsc_enable_cache")
    generate!("dsc_enable_cache_from_dir")

    generate!("dsc_DyldSharedCache")
    block_constructors!("dsc_DyldSharedCache")

    generate!("dsc_DyldSharedCache_it_libraries")
    block_constructors!("dsc_DyldSharedCache_it_libraries")

    generate!("dsc_DyldSharedCache_it_mapping_info")
    block_constructors!("dsc_DyldSharedCache_it_mapping_info")

    generate!("dsc_DyldSharedCache_it_subcaches")
    block_constructors!("dsc_DyldSharedCache_it_subcaches")

    generate!("dsc_DyldSharedCache_it_instructions")
    block_constructors!("dsc_DyldSharedCache_it_instructions")

    generate!("dsc_Dylib")
    block_constructors!("dsc_Dylib")

    generate_pod!("dsc_Dylib_extract_opt")
    block_constructors!("dsc_Dylib_extract_opt")

    generate!("dsc_MappingInfo")
    block_constructors!("dsc_MappingInfo")

    generate!("dsc_SubCache")
    block_constructors!("dsc_SubCache")

    // -------------------------------------------------------------------------
    // ASM Support
    // -------------------------------------------------------------------------
    generate!("asm_Engine")
    block_constructors!("asm_Engine")

    generate!("asm_Instruction")
    block_constructors!("asm_Instruction")

    /* AArch64 { */
        generate!("asm_aarch64_Instruction")
        block_constructors!("asm_aarch64_Instruction")

        generate!("asm_aarch64_Instruction_it_operands")
        block_constructors!("asm_aarch64_Instruction_it_operands")

        /* Operands { */
            generate!("asm_aarch64_Operand")
            block_constructors!("asm_aarch64_Operand")

            generate!("asm_aarch64_operands_Register")
            block_constructors!("asm_aarch64_operands_Register")

            generate_pod!("asm_aarch64_operands_Register_reg_t")
            block_constructors!("asm_aarch64_operands_Register_reg_t")

            generate!("asm_aarch64_operands_Memory")
            block_constructors!("asm_aarch64_operands_Memory")

            generate_pod!("asm_aarch64_operands_Memory_offset_t")
            block_constructors!("asm_aarch64_operands_Memory_offset_t")

            generate_pod!("asm_aarch64_operands_Memory_shift_info_t")
            block_constructors!("asm_aarch64_operands_Memory_shift_info_t")

            generate!("asm_aarch64_operands_Immediate")
            block_constructors!("asm_aarch64_operands_Immediate")

            generate!("asm_aarch64_operands_PCRelative")
            block_constructors!("asm_aarch64_operands_PCRelative")
        /* } */

    /* } AArch64 */

    /* X86 { */
        generate!("asm_x86_Instruction")
        block_constructors!("asm_x86_Instruction")

        generate!("asm_x86_Instruction_it_operands")
        block_constructors!("asm_x86_Instruction_it_operands")

        /* Operands { */
            generate!("asm_x86_Operand")
            block_constructors!("asm_x86_Operand")

            generate!("asm_x86_operands_Register")
            block_constructors!("asm_x86_operands_Register")

            generate!("asm_x86_operands_Memory")
            block_constructors!("asm_x86_operands_Memory")

            generate!("asm_x86_operands_Immediate")
            block_constructors!("asm_x86_operands_Immediate")

            generate!("asm_x86_operands_PCRelative")
            block_constructors!("asm_x86_operands_PCRelative")
        /* } */
    /* } X86 */

    /* Mips { */
        generate!("asm_mips_Instruction")
        block_constructors!("asm_mips_Instruction")
    /* } Mips */

    /* PowerPC { */
        generate!("asm_powerpc_Instruction")
        block_constructors!("asm_powerpc_Instruction")
    /* } PowerPC */

    /* RISC-V { */
        generate!("asm_riscv_Instruction")
        block_constructors!("asm_riscv_Instruction")
    /* } RISC-V */

    /* ARM { */
        generate!("asm_arm_Instruction")
        block_constructors!("asm_arm_Instruction")
    /* } ARM */

    /* eBPF { */
        generate!("asm_ebpf_Instruction")
        block_constructors!("asm_ebpf_Instruction")
    /* } eBPF */


    // -------------------------------------------------------------------------
    // COFF Support
    // -------------------------------------------------------------------------

    generate!("COFF_Symbol")
    block_constructors!("COFF_Symbol")

    generate!("COFF_Symbol_it_auxiliary_symbols")
    block_constructors!("COFF_Symbol_it_auxiliary_symbols")

    generate!("COFF_AuxiliarySymbol")
    block_constructors!("COFF_AuxiliarySymbol")

    generate!("COFF_AuxiliarySectionDefinition")
    block_constructors!("COFF_AuxiliarySectionDefinition")

    generate!("COFF_AuxiliaryCLRToken")
    block_constructors!("COFF_AuxiliaryCLRToken")

    generate!("COFF_AuxiliaryFile")
    block_constructors!("COFF_AuxiliaryFile")

    generate!("COFF_AuxiliaryFunctionDefinition")
    block_constructors!("COFF_AuxiliaryFunctionDefinition")

    generate!("COFF_AuxiliaryWeakExternal")
    block_constructors!("COFF_AuxiliaryWeakExternal")

    generate!("COFF_AuxiliarybfAndefSymbol")
    block_constructors!("COFF_AuxiliarybfAndefSymbol")

    generate!("COFF_String")
    block_constructors!("COFF_String")

    generate!("COFF_Section")
    block_constructors!("COFF_Section")

    generate!("COFF_Section_it_relocations")
    block_constructors!("COFF_Section_it_relocations")

    generate!("COFF_Section_it_symbols")
    block_constructors!("COFF_Section_it_symbols")

    generate!("COFF_Binary")
    block_constructors!("COFF_Binary")

    generate!("COFF_Binary_it_relocations")
    block_constructors!("COFF_Binary_it_relocations")

    generate!("COFF_Binary_it_symbols")
    block_constructors!("COFF_Binary_it_symbols")

    generate!("COFF_Binary_it_functions")
    block_constructors!("COFF_Binary_it_functions")

    generate!("COFF_Binary_it_sections")
    block_constructors!("COFF_Binary_it_sections")

    generate!("COFF_Binary_it_strings")
    block_constructors!("COFF_Binary_it_strings")

    generate!("COFF_Binary_it_instructions")
    block_constructors!("COFF_Binary_it_instructions")

    generate!("COFF_Relocation")
    block_constructors!("COFF_Relocation")

    generate!("COFF_Header")
    block_constructors!("COFF_Header")

    generate!("COFF_RegularHeader")
    block_constructors!("COFF_RegularHeader")

    generate!("COFF_BigObjHeader")
    block_constructors!("COFF_BigObjHeader")

    generate!("COFF_Utils")
    block_constructors!("COFF_Utils")

    generate!("COFF_Section_ComdataInfo")
    block_constructors!("COFF_Section_ComdataInfo")

    safety!(unsafe)
}

#[autocxx::extern_rust::extern_rust_function]
pub struct AssemblerConfig_r {}

impl AssemblerConfig_r {
    #[autocxx::extern_rust::extern_rust_function]
    fn resolve_symbol(&self, name: &str) -> i64 {
        unimplemented!();
    }
}
