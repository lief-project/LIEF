//! lief-ffi: low-level FFI bindings to LIEF (cxx-based).
//!
//! Generated bridge surface. Manual additions belong below the
//! re-export block.

pub mod asm;
pub mod coff;
pub mod debug_decl_opt;
pub mod debug_location;
pub mod dsc;
pub mod dwarf;
pub mod elf;
pub mod generic;
pub mod logging;
pub mod macho;
pub mod objc;
pub mod pdb;
pub mod pe;
pub mod stream;
pub mod utils;

// Re-exports of FFI types so the high-level `lief` crate can access
// them via the flat `lief_ffi::<TypeName>` path.
pub use crate::asm::aarch64::instruction::ffi::asm_aarch64_Instruction;
pub use crate::asm::aarch64::instruction::ffi::asm_aarch64_Instruction_it_operands;
pub use crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;
pub use crate::asm::aarch64::operands::immediate::ffi::asm_aarch64_operands_Immediate;
pub use crate::asm::aarch64::operands::memory::ffi::asm_aarch64_operands_Memory;
pub use crate::asm::aarch64::operands::pc_relative::ffi::asm_aarch64_operands_PCRelative;
pub use crate::asm::aarch64::operands::register::ffi::asm_aarch64_operands_Register;
pub use crate::asm::arm::instruction::ffi::asm_arm_Instruction;
pub use crate::asm::config::AssemblerConfig_r;
pub use crate::asm::ebpf::instruction::ffi::asm_ebpf_Instruction;
pub use crate::asm::instruction::ffi::asm_Instruction;
pub use crate::asm::mips::instruction::ffi::asm_mips_Instruction;
pub use crate::asm::powerpc::instruction::ffi::asm_powerpc_Instruction;
pub use crate::asm::riscv::instruction::ffi::asm_riscv_Instruction;
pub use crate::asm::x86::instruction::ffi::asm_x86_Instruction;
pub use crate::asm::x86::instruction::ffi::asm_x86_Instruction_it_operands;
pub use crate::asm::x86::operand::ffi::asm_x86_Operand;
pub use crate::asm::x86::operands::immediate::ffi::asm_x86_operands_Immediate;
pub use crate::asm::x86::operands::memory::ffi::asm_x86_operands_Memory;
pub use crate::asm::x86::operands::pc_relative::ffi::asm_x86_operands_PCRelative;
pub use crate::asm::x86::operands::register::ffi::asm_x86_operands_Register;
pub use crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;
pub use crate::coff::auxiliary_symbols::auxiliary_clr_token::ffi::COFF_AuxiliaryCLRToken;
pub use crate::coff::auxiliary_symbols::auxiliary_file::ffi::COFF_AuxiliaryFile;
pub use crate::coff::auxiliary_symbols::auxiliary_function_definition::ffi::COFF_AuxiliaryFunctionDefinition;
pub use crate::coff::auxiliary_symbols::auxiliary_section_definition::ffi::COFF_AuxiliarySectionDefinition;
pub use crate::coff::auxiliary_symbols::auxiliary_weak_external::ffi::COFF_AuxiliaryWeakExternal;
pub use crate::coff::auxiliary_symbols::auxiliarybf_andef_symbol::ffi::COFF_AuxiliarybfAndefSymbol;
pub use crate::coff::binary::ffi::COFF_Binary;
pub use crate::coff::binary::ffi::COFF_Binary_it_functions;
pub use crate::coff::binary::ffi::COFF_Binary_it_instructions;
pub use crate::coff::binary::ffi::COFF_Binary_it_relocations;
pub use crate::coff::binary::ffi::COFF_Binary_it_sections;
pub use crate::coff::binary::ffi::COFF_Binary_it_strings;
pub use crate::coff::binary::ffi::COFF_Binary_it_symbols;
pub use crate::coff::header::ffi::COFF_BigObjHeader;
pub use crate::coff::header::ffi::COFF_Header;
pub use crate::coff::header::ffi::COFF_RegularHeader;
pub use crate::coff::relocation::ffi::COFF_Relocation;
pub use crate::coff::section::ffi::COFF_Section;
pub use crate::coff::section::ffi::COFF_Section_ComdataInfo;
pub use crate::coff::section::ffi::COFF_Section_it_relocations;
pub use crate::coff::section::ffi::COFF_Section_it_symbols;
pub use crate::coff::string::ffi::COFF_String;
pub use crate::coff::symbol::ffi::COFF_Symbol;
pub use crate::coff::symbol::ffi::COFF_Symbol_it_auxiliary_symbols;
pub use crate::coff::utils::ffi::COFF_Utils;
pub use crate::debug_decl_opt::ffi::LIEF_DeclOpt;
pub use crate::debug_location::ffi::DebugLocation;
pub use crate::dsc::caching::ffi::dsc_enable_cache;
pub use crate::dsc::caching::ffi::dsc_enable_cache_from_dir;
pub use crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache;
pub use crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache_it_instructions;
pub use crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache_it_libraries;
pub use crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache_it_mapping_info;
pub use crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache_it_subcaches;
pub use crate::dsc::dylib::ffi::dsc_Dylib;
pub use crate::dsc::dylib::ffi::dsc_Dylib_extract_opt;
pub use crate::dsc::mapping_info::ffi::dsc_MappingInfo;
pub use crate::dsc::sub_cache::ffi::dsc_SubCache;
pub use crate::dsc::utils::ffi::dsc_Utils;
pub use crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit;
pub use crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit_Language;
pub use crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit_it_functions;
pub use crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit_it_types;
pub use crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit_it_variables;
pub use crate::dwarf::debug_info::ffi::DWARF_DebugInfo;
pub use crate::dwarf::debug_info::ffi::DWARF_DebugInfo_it_compilation_units;
pub use crate::dwarf::editor::array_type::ffi::DWARF_editor_ArrayType;
pub use crate::dwarf::editor::base_type::ffi::DWARF_editor_BaseType;
pub use crate::dwarf::editor::compilation_unit::ffi::DWARF_editor_CompilationUnit;
pub use crate::dwarf::editor::enum_type::ffi::DWARF_editor_EnumType;
pub use crate::dwarf::editor::enum_type::ffi::DWARF_editor_EnumType_Value;
pub use crate::dwarf::editor::ffi::DWARF_Editor;
pub use crate::dwarf::editor::function::ffi::DWARF_editor_Function;
pub use crate::dwarf::editor::function::ffi::DWARF_editor_Function_Label;
pub use crate::dwarf::editor::function::ffi::DWARF_editor_Function_LexicalBlock;
pub use crate::dwarf::editor::function::ffi::DWARF_editor_Function_Parameter;
pub use crate::dwarf::editor::function::ffi::DWARF_editor_Function_Range;
pub use crate::dwarf::editor::function_type::ffi::DWARF_editor_FunctionType;
pub use crate::dwarf::editor::function_type::ffi::DWARF_editor_FunctionType_Parameter;
pub use crate::dwarf::editor::pointer_type::ffi::DWARF_editor_PointerType;
pub use crate::dwarf::editor::struct_type::ffi::DWARF_editor_StructType;
pub use crate::dwarf::editor::struct_type::ffi::DWARF_editor_StructType_Member;
pub use crate::dwarf::editor::type_::ffi::DWARF_editor_Type;
pub use crate::dwarf::editor::type_def::ffi::DWARF_editor_TypeDef;
pub use crate::dwarf::editor::variable::ffi::DWARF_editor_Variable;
pub use crate::dwarf::function::ffi::DWARF_Function;
pub use crate::dwarf::function::ffi::DWARF_Function_it_instructions;
pub use crate::dwarf::function::ffi::DWARF_Function_it_lexical_blocks;
pub use crate::dwarf::function::ffi::DWARF_Function_it_parameters;
pub use crate::dwarf::function::ffi::DWARF_Function_it_thrown_types;
pub use crate::dwarf::function::ffi::DWARF_Function_it_variables;
pub use crate::dwarf::lexical_block::ffi::DWARF_LexicalBlock;
pub use crate::dwarf::lexical_block::ffi::DWARF_LexicalBlock_it_sub_blocks;
pub use crate::dwarf::parameter::ffi::DWARF_Parameter;
pub use crate::dwarf::parameter::ffi::DWARF_Parameter_Location;
pub use crate::dwarf::parameter::ffi::DWARF_Parameter_RegisterLocation;
pub use crate::dwarf::parameter::ffi::DWARF_parameters_Formal;
pub use crate::dwarf::parameter::ffi::DWARF_parameters_TemplateType;
pub use crate::dwarf::parameter::ffi::DWARF_parameters_TemplateValue;
pub use crate::dwarf::scope::ffi::DWARF_Scope;
pub use crate::dwarf::type_::ffi::DWARF_Type;
pub use crate::dwarf::types::array::ffi::DWARF_types_Array;
pub use crate::dwarf::types::array::ffi::DWARF_types_array_size_info;
pub use crate::dwarf::types::atomic::ffi::DWARF_types_Atomic;
pub use crate::dwarf::types::base::ffi::DWARF_types_Base;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_Class;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_ClassLike;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_ClassLike_Member;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_ClassLike_it_functions;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_ClassLike_it_members;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_Packed;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_Structure;
pub use crate::dwarf::types::class_like::ffi::DWARF_types_Union;
pub use crate::dwarf::types::coarray::ffi::DWARF_types_Coarray;
pub use crate::dwarf::types::const_::ffi::DWARF_types_Const;
pub use crate::dwarf::types::dynamic::ffi::DWARF_types_Dynamic;
pub use crate::dwarf::types::enum_::ffi::DWARF_types_Enum;
pub use crate::dwarf::types::enum_::ffi::DWARF_types_Enum_Entry;
pub use crate::dwarf::types::enum_::ffi::DWARF_types_Enum_it_entries;
pub use crate::dwarf::types::file::ffi::DWARF_types_File;
pub use crate::dwarf::types::immutable::ffi::DWARF_types_Immutable;
pub use crate::dwarf::types::interface::ffi::DWARF_types_Interface;
pub use crate::dwarf::types::pointer::ffi::DWARF_types_Pointer;
pub use crate::dwarf::types::pointer_to_member::ffi::DWARF_types_PointerToMember;
pub use crate::dwarf::types::r_value_ref::ffi::DWARF_types_RValueReference;
pub use crate::dwarf::types::reference::ffi::DWARF_types_Reference;
pub use crate::dwarf::types::restrict::ffi::DWARF_types_Restrict;
pub use crate::dwarf::types::set_ty::ffi::DWARF_types_SetTy;
pub use crate::dwarf::types::shared::ffi::DWARF_types_Shared;
pub use crate::dwarf::types::string_ty::ffi::DWARF_types_StringTy;
pub use crate::dwarf::types::subroutine::ffi::DWARF_types_Subroutine;
pub use crate::dwarf::types::subroutine::ffi::DWARF_types_Subroutine_it_parameters;
pub use crate::dwarf::types::template_alias::ffi::DWARF_types_TemplateAlias;
pub use crate::dwarf::types::template_alias::ffi::DWARF_types_TemplateAlias_it_parameters;
pub use crate::dwarf::types::thrown::ffi::DWARF_types_Thrown;
pub use crate::dwarf::types::typedef::ffi::DWARF_types_Typedef;
pub use crate::dwarf::types::volatile::ffi::DWARF_types_Volatile;
pub use crate::dwarf::variable::ffi::DWARF_Variable;
pub use crate::elf::binary::ffi::ELF_Binary;
pub use crate::elf::binary::ffi::ELF_Binary_it_dynamic_entries;
pub use crate::elf::binary::ffi::ELF_Binary_it_dynamic_relocations;
pub use crate::elf::binary::ffi::ELF_Binary_it_dynamic_symbols;
pub use crate::elf::binary::ffi::ELF_Binary_it_exported_symbols;
pub use crate::elf::binary::ffi::ELF_Binary_it_imported_symbols;
pub use crate::elf::binary::ffi::ELF_Binary_it_notes;
pub use crate::elf::binary::ffi::ELF_Binary_it_object_relocations;
pub use crate::elf::binary::ffi::ELF_Binary_it_pltgot_relocations;
pub use crate::elf::binary::ffi::ELF_Binary_it_relocations;
pub use crate::elf::binary::ffi::ELF_Binary_it_sections;
pub use crate::elf::binary::ffi::ELF_Binary_it_segments;
pub use crate::elf::binary::ffi::ELF_Binary_it_symbols;
pub use crate::elf::binary::ffi::ELF_Binary_it_symbols_version;
pub use crate::elf::binary::ffi::ELF_Binary_it_symbols_version_definition;
pub use crate::elf::binary::ffi::ELF_Binary_it_symbols_version_requirement;
pub use crate::elf::binary::ffi::ELF_Binary_it_symtab_symbols;
pub use crate::elf::binary::ffi::ELF_Binary_write_config_t;
pub use crate::elf::binary::ffi::ELF_ParserConfig;
pub use crate::elf::core_auxv::ffi::ELF_CoreAuxv;
pub use crate::elf::core_file::ffi::ELF_CoreFile;
pub use crate::elf::core_file::ffi::ELF_CoreFile_entry;
pub use crate::elf::core_file::ffi::ELF_CoreFile_it_files;
pub use crate::elf::core_pr_ps_info::ffi::ELF_CorePrPsInfo;
pub use crate::elf::core_pr_status::ffi::ELF_CorePrStatus;
pub use crate::elf::core_sig_info::ffi::ELF_CoreSigInfo;
pub use crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;
pub use crate::elf::dynamic_entry_array::ffi::ELF_DynamicEntryArray;
pub use crate::elf::dynamic_entry_auxiliary::ffi::ELF_DynamicEntryAuxiliary;
pub use crate::elf::dynamic_entry_filter::ffi::ELF_DynamicEntryFilter;
pub use crate::elf::dynamic_entry_flags::ffi::ELF_DynamicEntryFlags;
pub use crate::elf::dynamic_entry_library::ffi::ELF_DynamicEntryLibrary;
pub use crate::elf::dynamic_entry_rpath::ffi::ELF_DynamicEntryRpath;
pub use crate::elf::dynamic_entry_run_path::ffi::ELF_DynamicEntryRunPath;
pub use crate::elf::dynamic_shared_object::ffi::ELF_DynamicSharedObject;
pub use crate::elf::gnu_hash::ffi::ELF_GnuHash;
pub use crate::elf::header::ffi::ELF_Header;
pub use crate::elf::note::ffi::ELF_Note;
pub use crate::elf::note_abi::ffi::ELF_NoteAbi;
pub use crate::elf::note_android_ident::ffi::ELF_AndroidIdent;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_AArch64Feature;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_AArch64PAuth;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_Generic;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_Needed;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_Property;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_StackSize;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_X86Features;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_X86ISA;
pub use crate::elf::note_gnu_property::ffi::ELF_NoteGnuProperty_it_properties;
pub use crate::elf::note_qnx_stack::ffi::ELF_QNXStack;
pub use crate::elf::relocation::ffi::ELF_Relocation;
pub use crate::elf::section::ffi::ELF_Section;
pub use crate::elf::segment::ffi::ELF_Segment;
pub use crate::elf::symbol::ffi::ELF_Symbol;
pub use crate::elf::symbol_version::ffi::ELF_SymbolVersion;
pub use crate::elf::symbol_version_aux::ffi::ELF_SymbolVersionAux;
pub use crate::elf::symbol_version_aux_requirement::ffi::ELF_SymbolVersionAuxRequirement;
pub use crate::elf::symbol_version_definition::ffi::ELF_SymbolVersionDefinition;
pub use crate::elf::symbol_version_definition::ffi::ELF_SymbolVersionDefinition_it_auxiliary_symbols;
pub use crate::elf::symbol_version_requirement::ffi::ELF_SymbolVersionRequirement;
pub use crate::elf::symbol_version_requirement::ffi::ELF_SymbolVersionRequirement_it_auxiliary_symbols;
pub use crate::elf::sysvhash::ffi::ELF_SysvHash;
pub use crate::elf::utils::ffi::ELF_Utils;
pub use crate::generic::binary::ffi::AbstractBinary;
pub use crate::generic::binary::ffi::AbstractBinary_it_functions;
pub use crate::generic::binary::ffi::AbstractBinary_it_instructions;
pub use crate::generic::debug_info::ffi::AbstracDebugInfo;
pub use crate::generic::function::ffi::AbstractFunction;
pub use crate::generic::relocation::ffi::AbstractRelocation;
pub use crate::generic::section::ffi::AbstractSection;
pub use crate::generic::symbol::ffi::AbstractSymbol;
pub use crate::logging::ffi::LIEF_Logging;
pub use crate::logging::ffi::LIEF_Logging_Scoped;
pub use crate::macho::atom_info::ffi::MachO_AtomInfo;
pub use crate::macho::binary::ffi::MachO_Binary;
pub use crate::macho::binary::ffi::MachO_Binary_it_bindings_info;
pub use crate::macho::binary::ffi::MachO_Binary_it_commands;
pub use crate::macho::binary::ffi::MachO_Binary_it_fileset_binaries;
pub use crate::macho::binary::ffi::MachO_Binary_it_libraries;
pub use crate::macho::binary::ffi::MachO_Binary_it_notes;
pub use crate::macho::binary::ffi::MachO_Binary_it_relocations;
pub use crate::macho::binary::ffi::MachO_Binary_it_rpaths;
pub use crate::macho::binary::ffi::MachO_Binary_it_sections;
pub use crate::macho::binary::ffi::MachO_Binary_it_segments;
pub use crate::macho::binary::ffi::MachO_Binary_it_stubs;
pub use crate::macho::binary::ffi::MachO_Binary_it_sub_clients;
pub use crate::macho::binary::ffi::MachO_Binary_it_symbols;
pub use crate::macho::binary::ffi::MachO_Binary_write_config_t;
pub use crate::macho::binding_info::ffi::MachO_BindingInfo;
pub use crate::macho::build_tool_version::ffi::MachO_BuildToolVersion;
pub use crate::macho::build_version::ffi::MachO_BuildVersion;
pub use crate::macho::build_version::ffi::MachO_BuildVersion_it_tools;
pub use crate::macho::chained_binding_info::ffi::MachO_ChainedBindingInfo;
pub use crate::macho::code_signature::ffi::MachO_CodeSignature;
pub use crate::macho::code_signature_dir::ffi::MachO_CodeSignatureDir;
pub use crate::macho::data_code_entry::ffi::MachO_DataCodeEntry;
pub use crate::macho::data_in_code::ffi::MachO_DataInCode;
pub use crate::macho::data_in_code::ffi::MachO_DataInCode_it_entries;
pub use crate::macho::dyld_binding_info::ffi::MachO_DyldBindingInfo;
pub use crate::macho::dyld_chained_fixups::ffi::MachO_DyldChainedFixups;
pub use crate::macho::dyld_chained_fixups::ffi::MachO_DyldChainedFixups_it_bindings;
pub use crate::macho::dyld_environment::ffi::MachO_DyldEnvironment;
pub use crate::macho::dyld_exports_trie::ffi::MachO_DyldExportsTrie;
pub use crate::macho::dyld_exports_trie::ffi::MachO_DyldExportsTrie_it_exports;
pub use crate::macho::dyld_info::ffi::MachO_DyldInfo;
pub use crate::macho::dyld_info::ffi::MachO_DyldInfo_it_bindings;
pub use crate::macho::dyld_info::ffi::MachO_DyldInfo_it_exports;
pub use crate::macho::dylib::ffi::MachO_Dylib;
pub use crate::macho::dylinker::ffi::MachO_Dylinker;
pub use crate::macho::dynamic_symbol_command::ffi::MachO_DynamicSymbolCommand;
pub use crate::macho::dynamic_symbol_command::ffi::MachO_DynamicSymbolCommand_it_indirect_symbols;
pub use crate::macho::encryption_info::ffi::MachO_EncryptionInfo;
pub use crate::macho::export_info::ffi::MachO_ExportInfo;
pub use crate::macho::fat_binary::ffi::MachO_FatBinary;
pub use crate::macho::fat_binary::ffi::MachO_ParserConfig;
pub use crate::macho::fileset::ffi::MachO_Fileset;
pub use crate::macho::function_starts::ffi::MachO_FunctionStarts;
pub use crate::macho::function_variant_fixups::ffi::MachO_FunctionVariantFixups;
pub use crate::macho::function_variant_fixups::ffi::MachO_FunctionVariantFixups_Fixup;
pub use crate::macho::function_variant_fixups::ffi::MachO_FunctionVariantFixups_it_fixups;
pub use crate::macho::function_variants::ffi::MachO_FunctionVariants;
pub use crate::macho::function_variants::ffi::MachO_FunctionVariants_RuntimeTable;
pub use crate::macho::function_variants::ffi::MachO_FunctionVariants_RuntimeTableEntry;
pub use crate::macho::function_variants::ffi::MachO_FunctionVariants_RuntimeTable_it_entries;
pub use crate::macho::function_variants::ffi::MachO_FunctionVariants_it_runtime_table;
pub use crate::macho::header::ffi::MachO_Header;
pub use crate::macho::indirect_binding_info::ffi::MachO_IndirectBindingInfo;
pub use crate::macho::linker_opt_hint::ffi::MachO_LinkerOptHint;
pub use crate::macho::load_command::ffi::MachO_Command;
pub use crate::macho::main::ffi::MachO_Main;
pub use crate::macho::note_command::ffi::MachO_NoteCommand;
pub use crate::macho::r_path_command::ffi::MachO_RPathCommand;
pub use crate::macho::relocation::ffi::MachO_Relocation;
pub use crate::macho::relocation_dyld::ffi::MachO_RelocationDyld;
pub use crate::macho::relocation_fixup::ffi::MachO_RelocationFixup;
pub use crate::macho::relocation_object::ffi::MachO_RelocationObject;
pub use crate::macho::routine::ffi::MachO_Routine;
pub use crate::macho::section::ffi::MachO_Section;
pub use crate::macho::section::ffi::MachO_Section_it_relocations;
pub use crate::macho::segment_command::ffi::MachO_SegmentCommand;
pub use crate::macho::segment_command::ffi::MachO_SegmentCommand_it_relocations;
pub use crate::macho::segment_command::ffi::MachO_SegmentCommand_it_sections;
pub use crate::macho::segment_split_info::ffi::MachO_SegmentSplitInfo;
pub use crate::macho::source_version::ffi::MachO_SourceVersion;
pub use crate::macho::stub::ffi::MachO_Stub;
pub use crate::macho::sub_client::ffi::MachO_SubClient;
pub use crate::macho::sub_framework::ffi::MachO_SubFramework;
pub use crate::macho::symbol::ffi::MachO_Symbol;
pub use crate::macho::symbol_command::ffi::MachO_SymbolCommand;
pub use crate::macho::thread_command::ffi::MachO_ThreadCommand;
pub use crate::macho::thread_local_variables::ffi::MachO_ThreadLocalVariables;
pub use crate::macho::thread_local_variables::ffi::MachO_ThreadLocalVariables_Thunk;
pub use crate::macho::thread_local_variables::ffi::MachO_ThreadLocalVariables_it_thunks;
pub use crate::macho::two_level_hints::ffi::MachO_TwoLevelHints;
pub use crate::macho::unknown_command::ffi::MachO_UnknownCommand;
pub use crate::macho::utils::ffi::MachO_Utils;
pub use crate::macho::uuid_command::ffi::MachO_UUIDCommand;
pub use crate::macho::version_min::ffi::MachO_VersionMin;
pub use crate::objc::class::ffi::ObjC_Class;
pub use crate::objc::class::ffi::ObjC_Class_it_ivars;
pub use crate::objc::class::ffi::ObjC_Class_it_methods;
pub use crate::objc::class::ffi::ObjC_Class_it_properties;
pub use crate::objc::class::ffi::ObjC_Class_it_protocols;
pub use crate::objc::decl_opt::ffi::ObjC_DeclOpt;
pub use crate::objc::i_var::ffi::ObjC_IVar;
pub use crate::objc::metadata::ffi::ObjC_Metadata;
pub use crate::objc::metadata::ffi::ObjC_Metadata_it_classes;
pub use crate::objc::metadata::ffi::ObjC_Metadata_it_protocols;
pub use crate::objc::method::ffi::ObjC_Method;
pub use crate::objc::property::ffi::ObjC_Property;
pub use crate::objc::protocol::ffi::ObjC_Protocol;
pub use crate::objc::protocol::ffi::ObjC_Protocol_it_opt_methods;
pub use crate::objc::protocol::ffi::ObjC_Protocol_it_properties;
pub use crate::objc::protocol::ffi::ObjC_Protocol_it_req_methods;
pub use crate::pdb::build_metadata::ffi::PDB_BuildMetadata;
pub use crate::pdb::compilation_unit::ffi::PDB_CompilationUnit;
pub use crate::pdb::compilation_unit::ffi::PDB_CompilationUnit_it_functions;
pub use crate::pdb::compilation_unit::ffi::PDB_CompilationUnit_it_sources;
pub use crate::pdb::debug_info::ffi::PDB_DebugInfo;
pub use crate::pdb::debug_info::ffi::PDB_DebugInfo_it_compilation_units;
pub use crate::pdb::debug_info::ffi::PDB_DebugInfo_it_public_symbols;
pub use crate::pdb::debug_info::ffi::PDB_DebugInfo_it_types;
pub use crate::pdb::function::ffi::PDB_Function;
pub use crate::pdb::public_symbol::ffi::PDB_PublicSymbol;
pub use crate::pdb::type_::ffi::PDB_Type;
pub use crate::pdb::types::array::ffi::PDB_types_Array;
pub use crate::pdb::types::attribute::ffi::PDB_types_Attribute;
pub use crate::pdb::types::bit_field::ffi::PDB_types_BitField;
pub use crate::pdb::types::class_like::ffi::PDB_types_Class;
pub use crate::pdb::types::class_like::ffi::PDB_types_ClassLike;
pub use crate::pdb::types::class_like::ffi::PDB_types_ClassLike_it_attributes;
pub use crate::pdb::types::class_like::ffi::PDB_types_ClassLike_it_methods;
pub use crate::pdb::types::class_like::ffi::PDB_types_Interface;
pub use crate::pdb::types::class_like::ffi::PDB_types_Structure;
pub use crate::pdb::types::enum_::ffi::PDB_types_Enum;
pub use crate::pdb::types::enum_::ffi::PDB_types_Enum_Entry;
pub use crate::pdb::types::enum_::ffi::PDB_types_Enum_it_entries;
pub use crate::pdb::types::function::ffi::PDB_types_Function;
pub use crate::pdb::types::function::ffi::PDB_types_Function_it_parameters;
pub use crate::pdb::types::method::ffi::PDB_types_Method;
pub use crate::pdb::types::modifier::ffi::PDB_types_Modifier;
pub use crate::pdb::types::pointer::ffi::PDB_types_Pointer;
pub use crate::pdb::types::simple::ffi::PDB_types_Simple;
pub use crate::pdb::types::union_::ffi::PDB_types_Union;
pub use crate::pdb::utils::ffi::PDB_Utils;
pub use crate::pe::binary::ffi::PE_Binary;
pub use crate::pe::binary::ffi::PE_Binary_it_data_directories;
pub use crate::pe::binary::ffi::PE_Binary_it_debug;
pub use crate::pe::binary::ffi::PE_Binary_it_delay_imports;
pub use crate::pe::binary::ffi::PE_Binary_it_exceptions;
pub use crate::pe::binary::ffi::PE_Binary_it_imports;
pub use crate::pe::binary::ffi::PE_Binary_it_relocations;
pub use crate::pe::binary::ffi::PE_Binary_it_sections;
pub use crate::pe::binary::ffi::PE_Binary_it_signatures;
pub use crate::pe::binary::ffi::PE_Binary_it_strings_table;
pub use crate::pe::binary::ffi::PE_Binary_it_symbols;
pub use crate::pe::binary::ffi::PE_Binary_write_config_t;
pub use crate::pe::binary::ffi::PE_ParserConfig;
pub use crate::pe::code_integrity::ffi::PE_CodeIntegrity;
pub use crate::pe::data_directories::ffi::PE_DataDirectory;
pub use crate::pe::debug::code_view::ffi::PE_CodeView;
pub use crate::pe::debug::code_view_pdb::ffi::PE_CodeViewPDB;
pub use crate::pe::debug::debug::ffi::PE_Debug;
pub use crate::pe::debug::ex_dll_characteristics::ffi::PE_ExDllCharacteristics;
pub use crate::pe::debug::fpo::ffi::PE_FPO_entry_t;
pub use crate::pe::debug::fpo::ffi::PE_FPO_it_entries;
pub use crate::pe::debug::fpo::ffi::PE_FPO;
pub use crate::pe::debug::pdb_checksum::ffi::PE_PDBChecksum;
pub use crate::pe::debug::pogo::ffi::PE_Pogo;
pub use crate::pe::debug::pogo::ffi::PE_Pogo_it_entries;
pub use crate::pe::debug::pogo_entry::ffi::PE_PogoEntry;
pub use crate::pe::debug::repro::ffi::PE_Repro;
pub use crate::pe::debug::vc_feature::ffi::PE_VCFeature;
pub use crate::pe::delay_import::ffi::PE_DelayImport;
pub use crate::pe::delay_import::ffi::PE_DelayImport_it_entries;
pub use crate::pe::delay_import_entry::ffi::PE_DelayImportEntry;
pub use crate::pe::dos_header::ffi::PE_DosHeader;
pub use crate::pe::exception_info::ffi::PE_ExceptionInfo;
pub use crate::pe::export::ffi::PE_Export;
pub use crate::pe::export::ffi::PE_Export_it_entries;
pub use crate::pe::export_entry::ffi::PE_ExportEntry;
pub use crate::pe::factory::ffi::PE_Factory;
pub use crate::pe::header::ffi::PE_Header;
pub use crate::pe::import::ffi::PE_Import;
pub use crate::pe::import::ffi::PE_Import_it_entries;
pub use crate::pe::import_entry::ffi::PE_ImportEntry;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadata;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_code_range_entry_point_t;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_it_const_code_range_entry_point;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_it_const_range_entries;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_it_const_redirection_entries;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_range_entry_t;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataARM64_redirection_entry_t;
pub use crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadataX86;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixup;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64Kernel;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64Kernel_entry;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64Kernel_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64X;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64X_entry;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupARM64X_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupControlTransfer;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupControlTransfer_entry;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupControlTransfer_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupGeneric;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupGeneric_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixupUnknown;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverrideInfo;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverrideInfo_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride_image_bdd_dynamic_relocation_t;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride_image_bdd_info_t;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride_image_bdd_info_t_it_relocations;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride_it_bdd_info;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_FunctionOverride_it_func_overriding_info;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_relocation::ffi::PE_DynamicRelocation;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_relocation::ffi::PE_DynamicRelocationV1;
pub use crate::pe::load_configuration::dynamic_relocation::dynamic_relocation::ffi::PE_DynamicRelocationV2;
pub use crate::pe::load_configuration::enclave_configuration::ffi::PE_EnclaveConfiguration;
pub use crate::pe::load_configuration::enclave_configuration::ffi::PE_EnclaveConfiguration_it_imports;
pub use crate::pe::load_configuration::enclave_configuration::ffi::PE_EnclaveImport;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_guard_function_t;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_it_dynamic_relocations;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_it_guard_address_taken_iat_entries;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_it_guard_cf_functions;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_it_guard_eh_continuation;
pub use crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration_it_guard_long_jump_targets;
pub use crate::pe::load_configuration::volatile_metadata::ffi::PE_VolatileMetadata;
pub use crate::pe::load_configuration::volatile_metadata::ffi::PE_VolatileMetadata_it_ranges;
pub use crate::pe::load_configuration::volatile_metadata::ffi::PE_VolatileMetadata_range_t;
pub use crate::pe::optional_header::ffi::PE_OptionalHeader;
pub use crate::pe::relocation::ffi::PE_Relocation;
pub use crate::pe::relocation::ffi::PE_Relocation_it_entries;
pub use crate::pe::relocation_entry::ffi::PE_RelocationEntry;
pub use crate::pe::resource_accelerator::ffi::PE_ResourceAccelerator;
pub use crate::pe::resource_data::ffi::PE_ResourceData;
pub use crate::pe::resource_directory::ffi::PE_ResourceDirectory;
pub use crate::pe::resource_icon::ffi::PE_ResourceIcon;
pub use crate::pe::resource_node::ffi::PE_ResourceNode;
pub use crate::pe::resource_node::ffi::PE_ResourceNode_it_childs;
pub use crate::pe::resource_version::ffi::PE_ResourceStringFileInfo;
pub use crate::pe::resource_version::ffi::PE_ResourceStringFileInfo_it_children;
pub use crate::pe::resource_version::ffi::PE_ResourceStringTable;
pub use crate::pe::resource_version::ffi::PE_ResourceStringTable_entry_t;
pub use crate::pe::resource_version::ffi::PE_ResourceStringTable_it_entries;
pub use crate::pe::resource_version::ffi::PE_ResourceVar;
pub use crate::pe::resource_version::ffi::PE_ResourceVarFileInfo;
pub use crate::pe::resource_version::ffi::PE_ResourceVarFileInfo_it_vars;
pub use crate::pe::resource_version::ffi::PE_ResourceVersion;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager_it_accelerator;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager_it_icons;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager_it_string_table_entry;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager_it_version;
pub use crate::pe::resources_manager::ffi::PE_ResourcesManager_string_entry_t;
pub use crate::pe::rich_entry::ffi::PE_RichEntry;
pub use crate::pe::rich_header::ffi::PE_RichHeader;
pub use crate::pe::rich_header::ffi::PE_RichHeader_it_entries;
pub use crate::pe::runtime_function_a_arch64::ffi::PE_RuntimeFunctionAArch64;
pub use crate::pe::runtime_function_a_arch64::ffi::PE_unwind_aarch64_PackedFunction;
pub use crate::pe::runtime_function_a_arch64::ffi::PE_unwind_aarch64_UnpackedFunction;
pub use crate::pe::runtime_function_a_arch64::ffi::PE_unwind_aarch64_UnpackedFunction_epilog_scope_t;
pub use crate::pe::runtime_function_a_arch64::ffi::PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes;
pub use crate::pe::runtime_function_x64::ffi::PE_RuntimeFunctionX64;
pub use crate::pe::runtime_function_x64::ffi::PE_RuntimeFunctionX64_unwind_info_t;
pub use crate::pe::runtime_function_x64::ffi::PE_RuntimeFunctionX64_unwind_info_t_it_opcodes;
pub use crate::pe::section::ffi::PE_Section;
pub use crate::pe::signature::attributes::attribute::ffi::PE_Attribute;
pub use crate::pe::signature::attributes::content_type::ffi::PE_ContentType;
pub use crate::pe::signature::attributes::generic_type::ffi::PE_GenericType;
pub use crate::pe::signature::attributes::ms_counter_sign::ffi::PE_MsCounterSign;
pub use crate::pe::signature::attributes::ms_counter_sign::ffi::PE_MsCounterSign_it_certificates;
pub use crate::pe::signature::attributes::ms_counter_sign::ffi::PE_MsCounterSign_it_signers;
pub use crate::pe::signature::attributes::ms_manifest_binary_id::ffi::PE_MsManifestBinaryID;
pub use crate::pe::signature::attributes::ms_spc_nested_signature::ffi::PE_MsSpcNestedSignature;
pub use crate::pe::signature::attributes::ms_spc_statement_type::ffi::PE_MsSpcStatementType;
pub use crate::pe::signature::attributes::pkcs9_at_sequence_number::ffi::PE_PKCS9AtSequenceNumber;
pub use crate::pe::signature::attributes::pkcs9_counter_signature::ffi::PE_PKCS9CounterSignature;
pub use crate::pe::signature::attributes::pkcs9_message_digest::ffi::PE_PKCS9MessageDigest;
pub use crate::pe::signature::attributes::pkcs9_signing_time::ffi::PE_PKCS9SigningTime;
pub use crate::pe::signature::attributes::signing_certificate_v2::ffi::PE_SigningCertificateV2;
pub use crate::pe::signature::attributes::spc_relaxed_pe_marker_check::ffi::PE_SpcRelaxedPeMarkerCheck;
pub use crate::pe::signature::attributes::spc_sp_opus_info::ffi::PE_SpcSpOpusInfo;
pub use crate::pe::signature::content_info::ffi::PE_ContentInfo;
pub use crate::pe::signature::content_info::ffi::PE_ContentInfo_Content;
pub use crate::pe::signature::generic_content::ffi::PE_GenericContent;
pub use crate::pe::signature::pkcs9_tst_info::ffi::PE_PKCS9TSTInfo;
pub use crate::pe::signature::rsa_info::ffi::PE_RsaInfo;
pub use crate::pe::signature::signature::ffi::PE_Signature;
pub use crate::pe::signature::signature::ffi::PE_Signature_it_certificates;
pub use crate::pe::signature::signature::ffi::PE_Signature_it_signers;
pub use crate::pe::signature::signer_info::ffi::PE_SignerInfo;
pub use crate::pe::signature::signer_info::ffi::PE_SignerInfo_it_authenticated_attributes;
pub use crate::pe::signature::signer_info::ffi::PE_SignerInfo_it_unauthenticated_attributes;
pub use crate::pe::signature::spc_indirect_data::ffi::PE_SpcIndirectData;
pub use crate::pe::signature::x509::ffi::PE_x509;
pub use crate::pe::tls::ffi::PE_TLS;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_Alloc;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_Code;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_Epilog;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_PushMachFrame;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_PushNonVol;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_SaveNonVolatile;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_SaveXMM128;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_SetFPReg;
pub use crate::pe::unwind_code_x64::ffi::PE_unwind_x64_Spare;
pub use crate::pe::utils::ffi::PE_Utils;
pub use crate::stream::ffi::RustStream;
pub use crate::utils::ffi::demangle;
pub use crate::utils::ffi::dump;
pub use crate::utils::ffi::dump_with_limit;
pub use crate::utils::ffi::extended_version;
pub use crate::utils::ffi::extended_version_info;
pub use crate::utils::ffi::is_extended;
pub use crate::utils::ffi::version;
pub use crate::utils::ffi::LIEFVersion;
pub use crate::utils::ffi::Range;

// AsRef impls for inheritance chains. The unsafe pointer cast is safe
// because every type uses the Mirror<T> pattern with single inheritance
// so the parent class is at offset 0 within the child.
impl AsRef<AbstractSymbol> for AbstractFunction {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const AbstractFunction as *const AbstractSymbol) }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliaryCLRToken {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe { &*(self as *const COFF_AuxiliaryCLRToken as *const COFF_AuxiliarySymbol) }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliaryFile {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe { &*(self as *const COFF_AuxiliaryFile as *const COFF_AuxiliarySymbol) }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliaryFunctionDefinition {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe {
            &*(self as *const COFF_AuxiliaryFunctionDefinition as *const COFF_AuxiliarySymbol)
        }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliarySectionDefinition {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe { &*(self as *const COFF_AuxiliarySectionDefinition as *const COFF_AuxiliarySymbol) }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliaryWeakExternal {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe { &*(self as *const COFF_AuxiliaryWeakExternal as *const COFF_AuxiliarySymbol) }
    }
}
impl AsRef<COFF_AuxiliarySymbol> for COFF_AuxiliarybfAndefSymbol {
    fn as_ref(&self) -> &COFF_AuxiliarySymbol {
        unsafe { &*(self as *const COFF_AuxiliarybfAndefSymbol as *const COFF_AuxiliarySymbol) }
    }
}
impl AsRef<COFF_Header> for COFF_BigObjHeader {
    fn as_ref(&self) -> &COFF_Header {
        unsafe { &*(self as *const COFF_BigObjHeader as *const COFF_Header) }
    }
}
impl AsRef<COFF_Header> for COFF_RegularHeader {
    fn as_ref(&self) -> &COFF_Header {
        unsafe { &*(self as *const COFF_RegularHeader as *const COFF_Header) }
    }
}
impl AsRef<AbstractRelocation> for COFF_Relocation {
    fn as_ref(&self) -> &AbstractRelocation {
        unsafe { &*(self as *const COFF_Relocation as *const AbstractRelocation) }
    }
}
impl AsRef<AbstractSection> for COFF_Section {
    fn as_ref(&self) -> &AbstractSection {
        unsafe { &*(self as *const COFF_Section as *const AbstractSection) }
    }
}
impl AsRef<AbstractSymbol> for COFF_Symbol {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const COFF_Symbol as *const AbstractSymbol) }
    }
}
impl AsRef<AbstracDebugInfo> for DWARF_DebugInfo {
    fn as_ref(&self) -> &AbstracDebugInfo {
        unsafe { &*(self as *const DWARF_DebugInfo as *const AbstracDebugInfo) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_ArrayType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_ArrayType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_BaseType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_BaseType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_EnumType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_EnumType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_FunctionType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_FunctionType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_PointerType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_PointerType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_StructType {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_StructType as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_editor_Type> for DWARF_editor_TypeDef {
    fn as_ref(&self) -> &DWARF_editor_Type {
        unsafe { &*(self as *const DWARF_editor_TypeDef as *const DWARF_editor_Type) }
    }
}
impl AsRef<DWARF_Parameter> for DWARF_parameters_Formal {
    fn as_ref(&self) -> &DWARF_Parameter {
        unsafe { &*(self as *const DWARF_parameters_Formal as *const DWARF_Parameter) }
    }
}
impl AsRef<DWARF_Parameter> for DWARF_parameters_TemplateType {
    fn as_ref(&self) -> &DWARF_Parameter {
        unsafe { &*(self as *const DWARF_parameters_TemplateType as *const DWARF_Parameter) }
    }
}
impl AsRef<DWARF_Parameter> for DWARF_parameters_TemplateValue {
    fn as_ref(&self) -> &DWARF_Parameter {
        unsafe { &*(self as *const DWARF_parameters_TemplateValue as *const DWARF_Parameter) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Array {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Array as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Atomic {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Atomic as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Base {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Base as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_types_ClassLike> for DWARF_types_Class {
    fn as_ref(&self) -> &DWARF_types_ClassLike {
        unsafe { &*(self as *const DWARF_types_Class as *const DWARF_types_ClassLike) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_ClassLike {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_ClassLike as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Coarray {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Coarray as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Const {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Const as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Dynamic {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Dynamic as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Enum {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Enum as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_File {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_File as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Immutable {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Immutable as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Interface {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Interface as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_types_ClassLike> for DWARF_types_Packed {
    fn as_ref(&self) -> &DWARF_types_ClassLike {
        unsafe { &*(self as *const DWARF_types_Packed as *const DWARF_types_ClassLike) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Pointer {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Pointer as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_PointerToMember {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_PointerToMember as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_RValueReference {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_RValueReference as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Reference {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Reference as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Restrict {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Restrict as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_SetTy {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_SetTy as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Shared {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Shared as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_StringTy {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_StringTy as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_types_ClassLike> for DWARF_types_Structure {
    fn as_ref(&self) -> &DWARF_types_ClassLike {
        unsafe { &*(self as *const DWARF_types_Structure as *const DWARF_types_ClassLike) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Subroutine {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Subroutine as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_TemplateAlias {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_TemplateAlias as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Thrown {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Thrown as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Typedef {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Typedef as *const DWARF_Type) }
    }
}
impl AsRef<DWARF_types_ClassLike> for DWARF_types_Union {
    fn as_ref(&self) -> &DWARF_types_ClassLike {
        unsafe { &*(self as *const DWARF_types_Union as *const DWARF_types_ClassLike) }
    }
}
impl AsRef<DWARF_Type> for DWARF_types_Volatile {
    fn as_ref(&self) -> &DWARF_Type {
        unsafe { &*(self as *const DWARF_types_Volatile as *const DWARF_Type) }
    }
}
impl AsRef<ELF_Note> for ELF_AndroidIdent {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_AndroidIdent as *const ELF_Note) }
    }
}
impl AsRef<AbstractBinary> for ELF_Binary {
    fn as_ref(&self) -> &AbstractBinary {
        unsafe { &*(self as *const ELF_Binary as *const AbstractBinary) }
    }
}
impl AsRef<ELF_Note> for ELF_CoreAuxv {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_CoreAuxv as *const ELF_Note) }
    }
}
impl AsRef<ELF_Note> for ELF_CoreFile {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_CoreFile as *const ELF_Note) }
    }
}
impl AsRef<ELF_Note> for ELF_CorePrPsInfo {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_CorePrPsInfo as *const ELF_Note) }
    }
}
impl AsRef<ELF_Note> for ELF_CorePrStatus {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_CorePrStatus as *const ELF_Note) }
    }
}
impl AsRef<ELF_Note> for ELF_CoreSigInfo {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_CoreSigInfo as *const ELF_Note) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryArray {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryArray as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryAuxiliary {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryAuxiliary as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryFilter {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryFilter as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryFlags {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryFlags as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryLibrary {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryLibrary as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryRpath {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryRpath as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicEntryRunPath {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicEntryRunPath as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_DynamicEntry> for ELF_DynamicSharedObject {
    fn as_ref(&self) -> &ELF_DynamicEntry {
        unsafe { &*(self as *const ELF_DynamicSharedObject as *const ELF_DynamicEntry) }
    }
}
impl AsRef<ELF_Note> for ELF_NoteAbi {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_NoteAbi as *const ELF_Note) }
    }
}
impl AsRef<ELF_Note> for ELF_NoteGnuProperty {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_NoteGnuProperty as *const ELF_Note) }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_AArch64Feature {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_AArch64Feature
                as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_AArch64PAuth {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_AArch64PAuth
                as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_Generic {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_Generic as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_Needed {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_Needed as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_NoteNoCopyOnProtected {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_NoteNoCopyOnProtected
                as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_StackSize {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_StackSize as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_X86Features {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_X86Features
                as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_NoteGnuProperty_Property> for ELF_NoteGnuProperty_X86ISA {
    fn as_ref(&self) -> &ELF_NoteGnuProperty_Property {
        unsafe {
            &*(self as *const ELF_NoteGnuProperty_X86ISA as *const ELF_NoteGnuProperty_Property)
        }
    }
}
impl AsRef<ELF_Note> for ELF_QNXStack {
    fn as_ref(&self) -> &ELF_Note {
        unsafe { &*(self as *const ELF_QNXStack as *const ELF_Note) }
    }
}
impl AsRef<AbstractRelocation> for ELF_Relocation {
    fn as_ref(&self) -> &AbstractRelocation {
        unsafe { &*(self as *const ELF_Relocation as *const AbstractRelocation) }
    }
}
impl AsRef<AbstractSection> for ELF_Section {
    fn as_ref(&self) -> &AbstractSection {
        unsafe { &*(self as *const ELF_Section as *const AbstractSection) }
    }
}
impl AsRef<AbstractSymbol> for ELF_Symbol {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const ELF_Symbol as *const AbstractSymbol) }
    }
}
impl AsRef<ELF_SymbolVersionAux> for ELF_SymbolVersionAuxRequirement {
    fn as_ref(&self) -> &ELF_SymbolVersionAux {
        unsafe { &*(self as *const ELF_SymbolVersionAuxRequirement as *const ELF_SymbolVersionAux) }
    }
}
impl AsRef<MachO_Command> for MachO_AtomInfo {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_AtomInfo as *const MachO_Command) }
    }
}
impl AsRef<AbstractBinary> for MachO_Binary {
    fn as_ref(&self) -> &AbstractBinary {
        unsafe { &*(self as *const MachO_Binary as *const AbstractBinary) }
    }
}
impl AsRef<MachO_Command> for MachO_BuildVersion {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_BuildVersion as *const MachO_Command) }
    }
}
impl AsRef<MachO_BindingInfo> for MachO_ChainedBindingInfo {
    fn as_ref(&self) -> &MachO_BindingInfo {
        unsafe { &*(self as *const MachO_ChainedBindingInfo as *const MachO_BindingInfo) }
    }
}
impl AsRef<MachO_Command> for MachO_CodeSignature {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_CodeSignature as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_CodeSignatureDir {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_CodeSignatureDir as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_DataInCode {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DataInCode as *const MachO_Command) }
    }
}
impl AsRef<MachO_BindingInfo> for MachO_DyldBindingInfo {
    fn as_ref(&self) -> &MachO_BindingInfo {
        unsafe { &*(self as *const MachO_DyldBindingInfo as *const MachO_BindingInfo) }
    }
}
impl AsRef<MachO_Command> for MachO_DyldChainedFixups {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DyldChainedFixups as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_DyldEnvironment {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DyldEnvironment as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_DyldExportsTrie {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DyldExportsTrie as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_DyldInfo {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DyldInfo as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_Dylib {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_Dylib as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_Dylinker {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_Dylinker as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_DynamicSymbolCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_DynamicSymbolCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_EncryptionInfo {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_EncryptionInfo as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_Fileset {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_Fileset as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_FunctionStarts {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_FunctionStarts as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_FunctionVariantFixups {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_FunctionVariantFixups as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_FunctionVariants {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_FunctionVariants as *const MachO_Command) }
    }
}
impl AsRef<MachO_BindingInfo> for MachO_IndirectBindingInfo {
    fn as_ref(&self) -> &MachO_BindingInfo {
        unsafe { &*(self as *const MachO_IndirectBindingInfo as *const MachO_BindingInfo) }
    }
}
impl AsRef<MachO_Command> for MachO_LinkerOptHint {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_LinkerOptHint as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_Main {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_Main as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_NoteCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_NoteCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_RPathCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_RPathCommand as *const MachO_Command) }
    }
}
impl AsRef<AbstractRelocation> for MachO_Relocation {
    fn as_ref(&self) -> &AbstractRelocation {
        unsafe { &*(self as *const MachO_Relocation as *const AbstractRelocation) }
    }
}
impl AsRef<MachO_Relocation> for MachO_RelocationDyld {
    fn as_ref(&self) -> &MachO_Relocation {
        unsafe { &*(self as *const MachO_RelocationDyld as *const MachO_Relocation) }
    }
}
impl AsRef<MachO_Relocation> for MachO_RelocationFixup {
    fn as_ref(&self) -> &MachO_Relocation {
        unsafe { &*(self as *const MachO_RelocationFixup as *const MachO_Relocation) }
    }
}
impl AsRef<MachO_Relocation> for MachO_RelocationObject {
    fn as_ref(&self) -> &MachO_Relocation {
        unsafe { &*(self as *const MachO_RelocationObject as *const MachO_Relocation) }
    }
}
impl AsRef<MachO_Command> for MachO_Routine {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_Routine as *const MachO_Command) }
    }
}
impl AsRef<AbstractSection> for MachO_Section {
    fn as_ref(&self) -> &AbstractSection {
        unsafe { &*(self as *const MachO_Section as *const AbstractSection) }
    }
}
impl AsRef<MachO_Command> for MachO_SegmentCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SegmentCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_SegmentSplitInfo {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SegmentSplitInfo as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_SourceVersion {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SourceVersion as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_SubClient {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SubClient as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_SubFramework {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SubFramework as *const MachO_Command) }
    }
}
impl AsRef<AbstractSymbol> for MachO_Symbol {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const MachO_Symbol as *const AbstractSymbol) }
    }
}
impl AsRef<MachO_Command> for MachO_SymbolCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_SymbolCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_ThreadCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_ThreadCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Section> for MachO_ThreadLocalVariables {
    fn as_ref(&self) -> &MachO_Section {
        unsafe { &*(self as *const MachO_ThreadLocalVariables as *const MachO_Section) }
    }
}
impl AsRef<MachO_Command> for MachO_TwoLevelHints {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_TwoLevelHints as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_UUIDCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_UUIDCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_UnknownCommand {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_UnknownCommand as *const MachO_Command) }
    }
}
impl AsRef<MachO_Command> for MachO_VersionMin {
    fn as_ref(&self) -> &MachO_Command {
        unsafe { &*(self as *const MachO_VersionMin as *const MachO_Command) }
    }
}
impl AsRef<AbstracDebugInfo> for PDB_DebugInfo {
    fn as_ref(&self) -> &AbstracDebugInfo {
        unsafe { &*(self as *const PDB_DebugInfo as *const AbstracDebugInfo) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Array {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Array as *const PDB_Type) }
    }
}
impl AsRef<PDB_Type> for PDB_types_BitField {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_BitField as *const PDB_Type) }
    }
}
impl AsRef<PDB_types_ClassLike> for PDB_types_Class {
    fn as_ref(&self) -> &PDB_types_ClassLike {
        unsafe { &*(self as *const PDB_types_Class as *const PDB_types_ClassLike) }
    }
}
impl AsRef<PDB_Type> for PDB_types_ClassLike {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_ClassLike as *const PDB_Type) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Enum {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Enum as *const PDB_Type) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Function {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Function as *const PDB_Type) }
    }
}
impl AsRef<PDB_types_ClassLike> for PDB_types_Interface {
    fn as_ref(&self) -> &PDB_types_ClassLike {
        unsafe { &*(self as *const PDB_types_Interface as *const PDB_types_ClassLike) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Modifier {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Modifier as *const PDB_Type) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Pointer {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Pointer as *const PDB_Type) }
    }
}
impl AsRef<PDB_Type> for PDB_types_Simple {
    fn as_ref(&self) -> &PDB_Type {
        unsafe { &*(self as *const PDB_types_Simple as *const PDB_Type) }
    }
}
impl AsRef<PDB_types_ClassLike> for PDB_types_Structure {
    fn as_ref(&self) -> &PDB_types_ClassLike {
        unsafe { &*(self as *const PDB_types_Structure as *const PDB_types_ClassLike) }
    }
}
impl AsRef<PDB_types_ClassLike> for PDB_types_Union {
    fn as_ref(&self) -> &PDB_types_ClassLike {
        unsafe { &*(self as *const PDB_types_Union as *const PDB_types_ClassLike) }
    }
}
impl AsRef<AbstractBinary> for PE_Binary {
    fn as_ref(&self) -> &AbstractBinary {
        unsafe { &*(self as *const PE_Binary as *const AbstractBinary) }
    }
}
impl AsRef<PE_CHPEMetadata> for PE_CHPEMetadataARM64 {
    fn as_ref(&self) -> &PE_CHPEMetadata {
        unsafe { &*(self as *const PE_CHPEMetadataARM64 as *const PE_CHPEMetadata) }
    }
}
impl AsRef<PE_CHPEMetadata> for PE_CHPEMetadataX86 {
    fn as_ref(&self) -> &PE_CHPEMetadata {
        unsafe { &*(self as *const PE_CHPEMetadataX86 as *const PE_CHPEMetadata) }
    }
}
impl AsRef<PE_Debug> for PE_CodeView {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_CodeView as *const PE_Debug) }
    }
}
impl AsRef<PE_CodeView> for PE_CodeViewPDB {
    fn as_ref(&self) -> &PE_CodeView {
        unsafe { &*(self as *const PE_CodeViewPDB as *const PE_CodeView) }
    }
}
impl AsRef<AbstractSymbol> for PE_DelayImportEntry {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const PE_DelayImportEntry as *const AbstractSymbol) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_DynamicFixupARM64Kernel {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_DynamicFixupARM64Kernel as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_DynamicFixupARM64X {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_DynamicFixupARM64X as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_DynamicFixupControlTransfer {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_DynamicFixupControlTransfer as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_DynamicFixupGeneric {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_DynamicFixupGeneric as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_DynamicFixupUnknown {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_DynamicFixupUnknown as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_DynamicRelocation> for PE_DynamicRelocationV1 {
    fn as_ref(&self) -> &PE_DynamicRelocation {
        unsafe { &*(self as *const PE_DynamicRelocationV1 as *const PE_DynamicRelocation) }
    }
}
impl AsRef<PE_DynamicRelocation> for PE_DynamicRelocationV2 {
    fn as_ref(&self) -> &PE_DynamicRelocation {
        unsafe { &*(self as *const PE_DynamicRelocationV2 as *const PE_DynamicRelocation) }
    }
}
impl AsRef<PE_Debug> for PE_ExDllCharacteristics {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_ExDllCharacteristics as *const PE_Debug) }
    }
}
impl AsRef<AbstractSymbol> for PE_ExportEntry {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const PE_ExportEntry as *const AbstractSymbol) }
    }
}
impl AsRef<PE_Debug> for PE_FPO {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_FPO as *const PE_Debug) }
    }
}
impl AsRef<PE_DynamicFixup> for PE_FunctionOverride {
    fn as_ref(&self) -> &PE_DynamicFixup {
        unsafe { &*(self as *const PE_FunctionOverride as *const PE_DynamicFixup) }
    }
}
impl AsRef<PE_ContentInfo_Content> for PE_GenericContent {
    fn as_ref(&self) -> &PE_ContentInfo_Content {
        unsafe { &*(self as *const PE_GenericContent as *const PE_ContentInfo_Content) }
    }
}
impl AsRef<AbstractSymbol> for PE_ImportEntry {
    fn as_ref(&self) -> &AbstractSymbol {
        unsafe { &*(self as *const PE_ImportEntry as *const AbstractSymbol) }
    }
}
impl AsRef<PE_Debug> for PE_PDBChecksum {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_PDBChecksum as *const PE_Debug) }
    }
}
impl AsRef<PE_ContentInfo_Content> for PE_PKCS9TSTInfo {
    fn as_ref(&self) -> &PE_ContentInfo_Content {
        unsafe { &*(self as *const PE_PKCS9TSTInfo as *const PE_ContentInfo_Content) }
    }
}
impl AsRef<PE_Debug> for PE_Pogo {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_Pogo as *const PE_Debug) }
    }
}
impl AsRef<AbstractRelocation> for PE_RelocationEntry {
    fn as_ref(&self) -> &AbstractRelocation {
        unsafe { &*(self as *const PE_RelocationEntry as *const AbstractRelocation) }
    }
}
impl AsRef<PE_Debug> for PE_Repro {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_Repro as *const PE_Debug) }
    }
}
impl AsRef<PE_ResourceNode> for PE_ResourceData {
    fn as_ref(&self) -> &PE_ResourceNode {
        unsafe { &*(self as *const PE_ResourceData as *const PE_ResourceNode) }
    }
}
impl AsRef<PE_ResourceNode> for PE_ResourceDirectory {
    fn as_ref(&self) -> &PE_ResourceNode {
        unsafe { &*(self as *const PE_ResourceDirectory as *const PE_ResourceNode) }
    }
}
impl AsRef<PE_ExceptionInfo> for PE_RuntimeFunctionAArch64 {
    fn as_ref(&self) -> &PE_ExceptionInfo {
        unsafe { &*(self as *const PE_RuntimeFunctionAArch64 as *const PE_ExceptionInfo) }
    }
}
impl AsRef<PE_ExceptionInfo> for PE_RuntimeFunctionX64 {
    fn as_ref(&self) -> &PE_ExceptionInfo {
        unsafe { &*(self as *const PE_RuntimeFunctionX64 as *const PE_ExceptionInfo) }
    }
}
impl AsRef<AbstractSection> for PE_Section {
    fn as_ref(&self) -> &AbstractSection {
        unsafe { &*(self as *const PE_Section as *const AbstractSection) }
    }
}
impl AsRef<PE_ContentInfo_Content> for PE_SpcIndirectData {
    fn as_ref(&self) -> &PE_ContentInfo_Content {
        unsafe { &*(self as *const PE_SpcIndirectData as *const PE_ContentInfo_Content) }
    }
}
impl AsRef<PE_Debug> for PE_VCFeature {
    fn as_ref(&self) -> &PE_Debug {
        unsafe { &*(self as *const PE_VCFeature as *const PE_Debug) }
    }
}
impl AsRef<PE_RuntimeFunctionAArch64> for PE_unwind_aarch64_PackedFunction {
    fn as_ref(&self) -> &PE_RuntimeFunctionAArch64 {
        unsafe {
            &*(self as *const PE_unwind_aarch64_PackedFunction as *const PE_RuntimeFunctionAArch64)
        }
    }
}
impl AsRef<PE_RuntimeFunctionAArch64> for PE_unwind_aarch64_UnpackedFunction {
    fn as_ref(&self) -> &PE_RuntimeFunctionAArch64 {
        unsafe {
            &*(self as *const PE_unwind_aarch64_UnpackedFunction
                as *const PE_RuntimeFunctionAArch64)
        }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_Alloc {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_Alloc as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_Epilog {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_Epilog as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_PushMachFrame {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_PushMachFrame as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_PushNonVol {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_PushNonVol as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_SaveNonVolatile {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_SaveNonVolatile as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_SaveXMM128 {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_SaveXMM128 as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_SetFPReg {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_SetFPReg as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<PE_unwind_x64_Code> for PE_unwind_x64_Spare {
    fn as_ref(&self) -> &PE_unwind_x64_Code {
        unsafe { &*(self as *const PE_unwind_x64_Spare as *const PE_unwind_x64_Code) }
    }
}
impl AsRef<asm_Instruction> for asm_aarch64_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_aarch64_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_aarch64_Operand> for asm_aarch64_operands_Immediate {
    fn as_ref(&self) -> &asm_aarch64_Operand {
        unsafe { &*(self as *const asm_aarch64_operands_Immediate as *const asm_aarch64_Operand) }
    }
}
impl AsRef<asm_aarch64_Operand> for asm_aarch64_operands_Memory {
    fn as_ref(&self) -> &asm_aarch64_Operand {
        unsafe { &*(self as *const asm_aarch64_operands_Memory as *const asm_aarch64_Operand) }
    }
}
impl AsRef<asm_aarch64_Operand> for asm_aarch64_operands_PCRelative {
    fn as_ref(&self) -> &asm_aarch64_Operand {
        unsafe { &*(self as *const asm_aarch64_operands_PCRelative as *const asm_aarch64_Operand) }
    }
}
impl AsRef<asm_aarch64_Operand> for asm_aarch64_operands_Register {
    fn as_ref(&self) -> &asm_aarch64_Operand {
        unsafe { &*(self as *const asm_aarch64_operands_Register as *const asm_aarch64_Operand) }
    }
}
impl AsRef<asm_Instruction> for asm_arm_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_arm_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_Instruction> for asm_ebpf_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_ebpf_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_Instruction> for asm_mips_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_mips_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_Instruction> for asm_powerpc_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_powerpc_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_Instruction> for asm_riscv_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_riscv_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_Instruction> for asm_x86_Instruction {
    fn as_ref(&self) -> &asm_Instruction {
        unsafe { &*(self as *const asm_x86_Instruction as *const asm_Instruction) }
    }
}
impl AsRef<asm_x86_Operand> for asm_x86_operands_Immediate {
    fn as_ref(&self) -> &asm_x86_Operand {
        unsafe { &*(self as *const asm_x86_operands_Immediate as *const asm_x86_Operand) }
    }
}
impl AsRef<asm_x86_Operand> for asm_x86_operands_Memory {
    fn as_ref(&self) -> &asm_x86_Operand {
        unsafe { &*(self as *const asm_x86_operands_Memory as *const asm_x86_Operand) }
    }
}
impl AsRef<asm_x86_Operand> for asm_x86_operands_PCRelative {
    fn as_ref(&self) -> &asm_x86_Operand {
        unsafe { &*(self as *const asm_x86_operands_PCRelative as *const asm_x86_Operand) }
    }
}
impl AsRef<asm_x86_Operand> for asm_x86_operands_Register {
    fn as_ref(&self) -> &asm_x86_Operand {
        unsafe { &*(self as *const asm_x86_operands_Register as *const asm_x86_Operand) }
    }
}
