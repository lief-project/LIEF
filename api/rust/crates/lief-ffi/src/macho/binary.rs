#[repr(C)]
pub struct write_config_t {
    pub linkedit: bool,
}

unsafe impl cxx::ExternType for write_config_t {
    type Id = cxx::type_id!("MachO_Binary_write_config_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Binary.hpp");

        type Range = crate::utils::ffi::Range;
        type Span = crate::utils::ffi::Span;
        type AbstractBinary_it_functions = crate::generic::binary::ffi::AbstractBinary_it_functions;
        type MachO_AtomInfo = crate::macho::atom_info::ffi::MachO_AtomInfo;
        type MachO_BindingInfo = crate::macho::binding_info::ffi::MachO_BindingInfo;
        type MachO_BuildVersion = crate::macho::build_version::ffi::MachO_BuildVersion;
        type MachO_CodeSignature = crate::macho::code_signature::ffi::MachO_CodeSignature;
        type MachO_CodeSignatureDir = crate::macho::code_signature_dir::ffi::MachO_CodeSignatureDir;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_DataInCode = crate::macho::data_in_code::ffi::MachO_DataInCode;
        type MachO_DyldChainedFixups =
            crate::macho::dyld_chained_fixups::ffi::MachO_DyldChainedFixups;
        type MachO_DyldEnvironment = crate::macho::dyld_environment::ffi::MachO_DyldEnvironment;
        type MachO_DyldExportsTrie = crate::macho::dyld_exports_trie::ffi::MachO_DyldExportsTrie;
        type MachO_DyldInfo = crate::macho::dyld_info::ffi::MachO_DyldInfo;
        type MachO_Dylib = crate::macho::dylib::ffi::MachO_Dylib;
        type MachO_Dylinker = crate::macho::dylinker::ffi::MachO_Dylinker;
        type MachO_DynamicSymbolCommand =
            crate::macho::dynamic_symbol_command::ffi::MachO_DynamicSymbolCommand;
        type MachO_EncryptionInfo = crate::macho::encryption_info::ffi::MachO_EncryptionInfo;
        type MachO_ExportInfo = crate::macho::export_info::ffi::MachO_ExportInfo;
        type MachO_FunctionStarts = crate::macho::function_starts::ffi::MachO_FunctionStarts;
        type MachO_FunctionVariantFixups =
            crate::macho::function_variant_fixups::ffi::MachO_FunctionVariantFixups;
        type MachO_FunctionVariants = crate::macho::function_variants::ffi::MachO_FunctionVariants;
        type MachO_LazyLoadDylibInfo =
            crate::macho::lazy_load_dylib_info::ffi::MachO_LazyLoadDylibInfo;
        type MachO_Header = crate::macho::header::ffi::MachO_Header;
        type MachO_LinkerOptHint = crate::macho::linker_opt_hint::ffi::MachO_LinkerOptHint;
        type MachO_Main = crate::macho::main::ffi::MachO_Main;
        type MachO_NoteCommand = crate::macho::note_command::ffi::MachO_NoteCommand;
        type MachO_RPathCommand = crate::macho::r_path_command::ffi::MachO_RPathCommand;
        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;
        type MachO_Routine = crate::macho::routine::ffi::MachO_Routine;
        type MachO_Section = crate::macho::section::ffi::MachO_Section;
        type MachO_SegmentCommand = crate::macho::segment_command::ffi::MachO_SegmentCommand;
        type MachO_SegmentSplitInfo = crate::macho::segment_split_info::ffi::MachO_SegmentSplitInfo;
        type MachO_SourceVersion = crate::macho::source_version::ffi::MachO_SourceVersion;
        type MachO_Stub = crate::macho::stub::ffi::MachO_Stub;
        type MachO_SubClient = crate::macho::sub_client::ffi::MachO_SubClient;
        type MachO_SubFramework = crate::macho::sub_framework::ffi::MachO_SubFramework;
        type MachO_Symbol = crate::macho::symbol::ffi::MachO_Symbol;
        type MachO_SymbolCommand = crate::macho::symbol_command::ffi::MachO_SymbolCommand;
        type MachO_ThreadCommand = crate::macho::thread_command::ffi::MachO_ThreadCommand;
        type MachO_TwoLevelHints = crate::macho::two_level_hints::ffi::MachO_TwoLevelHints;
        type MachO_UUIDCommand = crate::macho::uuid_command::ffi::MachO_UUIDCommand;
        type MachO_VersionMin = crate::macho::version_min::ffi::MachO_VersionMin;
        type ObjC_Metadata = crate::objc::metadata::ffi::ObjC_Metadata;

        type MachO_Binary_write_config_t = crate::macho::binary::write_config_t;

        type MachO_Binary;

        fn overlay(self: &MachO_Binary) -> Span;
        #[Self = "MachO_Binary"]
        fn is_exported(symbol: &MachO_Symbol) -> bool;
        fn header(self: &MachO_Binary) -> UniquePtr<MachO_Header>;
        fn commands(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_commands>;
        fn symbols(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_symbols>;
        fn sections(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_sections>;
        fn segments(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_segments>;
        fn libraries(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_libraries>;
        fn lazy_load_dylib_infos(
            self: &MachO_Binary,
        ) -> UniquePtr<MachO_Binary_it_lazy_load_dylib_info>;
        fn relocations(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_relocations>;
        fn rpaths(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_rpaths>;
        fn bindings(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_bindings_info>;
        fn symbol_stubs(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_stubs>;
        fn notes(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_notes>;
        fn dyld_info(self: &MachO_Binary) -> UniquePtr<MachO_DyldInfo>;
        fn uuid(self: &MachO_Binary) -> UniquePtr<MachO_UUIDCommand>;
        fn main_command(self: &MachO_Binary) -> UniquePtr<MachO_Main>;
        fn dylinker(self: &MachO_Binary) -> UniquePtr<MachO_Dylinker>;
        fn function_starts(self: &MachO_Binary) -> UniquePtr<MachO_FunctionStarts>;
        fn source_version(self: &MachO_Binary) -> UniquePtr<MachO_SourceVersion>;
        fn thread_command(self: &MachO_Binary) -> UniquePtr<MachO_ThreadCommand>;
        fn routine_command(self: &MachO_Binary) -> UniquePtr<MachO_Routine>;
        fn rpath(self: &MachO_Binary) -> UniquePtr<MachO_RPathCommand>;
        fn symbol_command(self: &MachO_Binary) -> UniquePtr<MachO_SymbolCommand>;
        fn dynamic_symbol_command(self: &MachO_Binary) -> UniquePtr<MachO_DynamicSymbolCommand>;
        fn code_signature(self: &MachO_Binary) -> UniquePtr<MachO_CodeSignature>;
        fn code_signature_dir(self: &MachO_Binary) -> UniquePtr<MachO_CodeSignatureDir>;
        fn data_in_code(self: &MachO_Binary) -> UniquePtr<MachO_DataInCode>;
        fn segment_split_info(self: &MachO_Binary) -> UniquePtr<MachO_SegmentSplitInfo>;
        fn encryption_info(self: &MachO_Binary) -> UniquePtr<MachO_EncryptionInfo>;
        fn sub_framework(self: &MachO_Binary) -> UniquePtr<MachO_SubFramework>;
        fn subclients(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_sub_clients>;
        fn dyld_environment(self: &MachO_Binary) -> UniquePtr<MachO_DyldEnvironment>;
        fn build_version(self: &MachO_Binary) -> UniquePtr<MachO_BuildVersion>;
        fn dyld_chained_fixups(self: &MachO_Binary) -> UniquePtr<MachO_DyldChainedFixups>;
        fn dyld_exports_trie(self: &MachO_Binary) -> UniquePtr<MachO_DyldExportsTrie>;
        fn two_level_hints(self: &MachO_Binary) -> UniquePtr<MachO_TwoLevelHints>;
        fn linker_opt_hint(self: &MachO_Binary) -> UniquePtr<MachO_LinkerOptHint>;
        fn atom_info(self: &MachO_Binary) -> UniquePtr<MachO_AtomInfo>;
        fn function_variants(self: &MachO_Binary) -> UniquePtr<MachO_FunctionVariants>;
        fn function_variant_fixups(self: &MachO_Binary) -> UniquePtr<MachO_FunctionVariantFixups>;
        fn version_min(self: &MachO_Binary) -> UniquePtr<MachO_VersionMin>;
        fn support_arm64_ptr_auth(self: &MachO_Binary) -> bool;
        fn objc_metadata(self: &MachO_Binary) -> UniquePtr<ObjC_Metadata>;
        fn platform(self: &MachO_Binary) -> u32;
        fn functions(self: &MachO_Binary) -> UniquePtr<AbstractBinary_it_functions>;
        fn is_ios(self: &MachO_Binary) -> bool;
        fn is_macos(self: &MachO_Binary) -> bool;
        fn find_library(self: &MachO_Binary, name: &CxxString) -> UniquePtr<MachO_Dylib>;
        fn write(self: Pin<&mut MachO_Binary>, output: &CxxString);
        fn tlv_initial_content_range(self: &MachO_Binary) -> Range;
        fn write_with_config(
            self: Pin<&mut MachO_Binary>,
            output: &CxxString,
            config: &MachO_Binary_write_config_t,
        );

        fn add_library(self: Pin<&mut MachO_Binary>, name: &CxxString) -> UniquePtr<MachO_Dylib>;
        fn filesets(self: &MachO_Binary) -> UniquePtr<MachO_Binary_it_fileset_binaries>;
        fn has_filesets(self: &MachO_Binary) -> bool;
        fn fileset_name(self: &MachO_Binary) -> UniquePtr<CxxString>;
        fn fileset_addr(self: &MachO_Binary) -> u64;
        fn virtual_address_to_offset(
            self: &MachO_Binary,
            virtual_address: u64,
            error: Pin<&mut u32>,
        ) -> u64;
        fn segment_from_offset(self: &MachO_Binary, offset: u64)
            -> UniquePtr<MachO_SegmentCommand>;
        fn segment_from_virtual_address(
            self: &MachO_Binary,
            va: u64,
        ) -> UniquePtr<MachO_SegmentCommand>;
        fn section_from_virtual_address(self: &MachO_Binary, va: u64) -> UniquePtr<MachO_Section>;
        fn get_segment(self: &MachO_Binary, name: &CxxString) -> UniquePtr<MachO_SegmentCommand>;
        fn get_section(
            self: &MachO_Binary,
            segname: &CxxString,
            secname: &CxxString,
        ) -> UniquePtr<MachO_Section>;
        fn fat_offset(self: &MachO_Binary) -> u64;
        fn is_valid_addr(self: &MachO_Binary, address: u64) -> bool;
        fn has_symbol(self: &MachO_Binary, name: &CxxString) -> bool;
        fn get_symbol(self: &MachO_Binary, name: &CxxString) -> UniquePtr<MachO_Symbol>;
        fn has_section(self: &MachO_Binary, name: &CxxString) -> bool;
        fn section_from_offset(self: &MachO_Binary, offset: u64) -> UniquePtr<MachO_Section>;
        fn has_segment(self: &MachO_Binary, name: &CxxString) -> bool;
        fn remove_command(self: Pin<&mut MachO_Binary>, index: u32) -> bool;
        fn remove_section(self: Pin<&mut MachO_Binary>, name: &CxxString, clear: bool);
        fn remove_section_seg(
            self: Pin<&mut MachO_Binary>,
            segname: &CxxString,
            secname: &CxxString,
            clear: bool,
        );
        fn remove_signature(self: Pin<&mut MachO_Binary>) -> bool;
        fn remove_symbol(self: Pin<&mut MachO_Binary>, name: &CxxString) -> bool;
        fn can_remove(self: &MachO_Binary, sym: &MachO_Symbol) -> bool;
        fn can_remove_symbol(self: &MachO_Binary, name: &CxxString) -> bool;
        fn unexport_name(self: Pin<&mut MachO_Binary>, name: &CxxString) -> bool;
        fn extend(self: Pin<&mut MachO_Binary>, command: &MachO_Command, size: u64) -> bool;
        fn extend_segment(
            self: Pin<&mut MachO_Binary>,
            segment: &MachO_SegmentCommand,
            size: u64,
        ) -> bool;
        fn add_exported_function(
            self: Pin<&mut MachO_Binary>,
            address: u64,
            name: &CxxString,
        ) -> UniquePtr<MachO_ExportInfo>;
        fn add_local_symbol(
            self: Pin<&mut MachO_Binary>,
            address: u64,
            name: &CxxString,
        ) -> UniquePtr<MachO_Symbol>;
        fn shift(self: Pin<&mut MachO_Binary>, value: u64, err: Pin<&mut u32>) -> bool;
        fn shift_linkedit(self: Pin<&mut MachO_Binary>, width: u64, err: Pin<&mut u32>) -> bool;
        fn add_command(
            self: Pin<&mut MachO_Binary>,
            command: &MachO_Command,
        ) -> UniquePtr<MachO_Command>;
        fn remove_commands_by_type(self: Pin<&mut MachO_Binary>, type_: u64) -> bool;
        fn has_command_type(self: &MachO_Binary, type_: u64) -> bool;
        fn get_command_type(self: &MachO_Binary, type_: u64) -> UniquePtr<MachO_Command>;
        fn unexport_symbol(self: Pin<&mut MachO_Binary>, sym: &MachO_Symbol) -> bool;
        fn add_section_default(
            self: Pin<&mut MachO_Binary>,
            section: &MachO_Section,
        ) -> UniquePtr<MachO_Section>;

        type MachO_Binary_it_bindings_info;

        fn next(self: Pin<&mut MachO_Binary_it_bindings_info>) -> UniquePtr<MachO_BindingInfo>;
        fn size(self: &MachO_Binary_it_bindings_info) -> u64;

        type MachO_Binary_it_commands;

        fn next(self: Pin<&mut MachO_Binary_it_commands>) -> UniquePtr<MachO_Command>;
        fn size(self: &MachO_Binary_it_commands) -> u64;

        type MachO_Binary_it_fileset_binaries;

        fn next(self: Pin<&mut MachO_Binary_it_fileset_binaries>) -> UniquePtr<MachO_Binary>;
        fn size(self: &MachO_Binary_it_fileset_binaries) -> u64;

        type MachO_Binary_it_libraries;

        fn next(self: Pin<&mut MachO_Binary_it_libraries>) -> UniquePtr<MachO_Dylib>;
        fn size(self: &MachO_Binary_it_libraries) -> u64;

        type MachO_Binary_it_lazy_load_dylib_info;

        fn next(
            self: Pin<&mut MachO_Binary_it_lazy_load_dylib_info>,
        ) -> UniquePtr<MachO_LazyLoadDylibInfo>;
        fn size(self: &MachO_Binary_it_lazy_load_dylib_info) -> u64;

        type MachO_Binary_it_notes;

        fn next(self: Pin<&mut MachO_Binary_it_notes>) -> UniquePtr<MachO_NoteCommand>;
        fn size(self: &MachO_Binary_it_notes) -> u64;

        type MachO_Binary_it_relocations;

        fn next(self: Pin<&mut MachO_Binary_it_relocations>) -> UniquePtr<MachO_Relocation>;
        fn size(self: &MachO_Binary_it_relocations) -> u64;

        type MachO_Binary_it_rpaths;

        fn next(self: Pin<&mut MachO_Binary_it_rpaths>) -> UniquePtr<MachO_RPathCommand>;
        fn size(self: &MachO_Binary_it_rpaths) -> u64;

        type MachO_Binary_it_sections;

        fn next(self: Pin<&mut MachO_Binary_it_sections>) -> UniquePtr<MachO_Section>;
        fn size(self: &MachO_Binary_it_sections) -> u64;

        type MachO_Binary_it_segments;

        fn next(self: Pin<&mut MachO_Binary_it_segments>) -> UniquePtr<MachO_SegmentCommand>;
        fn size(self: &MachO_Binary_it_segments) -> u64;

        type MachO_Binary_it_stubs;

        fn next(self: Pin<&mut MachO_Binary_it_stubs>) -> UniquePtr<MachO_Stub>;
        fn size(self: &MachO_Binary_it_stubs) -> u64;

        type MachO_Binary_it_sub_clients;

        fn next(self: Pin<&mut MachO_Binary_it_sub_clients>) -> UniquePtr<MachO_SubClient>;
        fn size(self: &MachO_Binary_it_sub_clients) -> u64;

        type MachO_Binary_it_symbols;

        fn next(self: Pin<&mut MachO_Binary_it_symbols>) -> UniquePtr<MachO_Symbol>;
        fn size(self: &MachO_Binary_it_symbols) -> u64;
    }
    impl UniquePtr<MachO_Binary> {}
    impl UniquePtr<MachO_Binary_write_config_t> {}
    impl UniquePtr<MachO_Binary_it_bindings_info> {}
    impl UniquePtr<MachO_Binary_it_commands> {}
    impl UniquePtr<MachO_Binary_it_fileset_binaries> {}
    impl UniquePtr<MachO_Binary_it_libraries> {}
    impl UniquePtr<MachO_Binary_it_lazy_load_dylib_info> {}
    impl UniquePtr<MachO_Binary_it_notes> {}
    impl UniquePtr<MachO_Binary_it_relocations> {}
    impl UniquePtr<MachO_Binary_it_rpaths> {}
    impl UniquePtr<MachO_Binary_it_sections> {}
    impl UniquePtr<MachO_Binary_it_segments> {}
    impl UniquePtr<MachO_Binary_it_stubs> {}
    impl UniquePtr<MachO_Binary_it_sub_clients> {}
    impl UniquePtr<MachO_Binary_it_symbols> {}
}
