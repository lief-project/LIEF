#[repr(C)]
pub struct write_config_t {
    pub dt_hash: bool,
    pub dyn_str: bool,
    pub dynamic_section: bool,
    pub fini_array: bool,
    pub gnu_hash: bool,
    pub init_array: bool,
    pub interpreter: bool,
    pub jmprel: bool,
    pub notes: bool,
    pub preinit_array: bool,
    pub relr: bool,
    pub android_rela: bool,
    pub rela: bool,
    pub static_symtab: bool,
    pub sym_verdef: bool,
    pub sym_verneed: bool,
    pub sym_versym: bool,
    pub symtab: bool,
    pub coredump_notes: bool,
    pub force_relocate: bool,
    pub keep_empty_version_requirement: bool,
    pub skip_dynamic: bool,
}

unsafe impl cxx::ExternType for write_config_t {
    type Id = cxx::type_id!("ELF_Binary_write_config_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Binary.hpp");

        type Span = crate::utils::ffi::Span;
        type AbstractBinary_it_functions = crate::generic::binary::ffi::AbstractBinary_it_functions;
        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;
        type ELF_DynamicEntryLibrary =
            crate::elf::dynamic_entry_library::ffi::ELF_DynamicEntryLibrary;
        type ELF_GnuHash = crate::elf::gnu_hash::ffi::ELF_GnuHash;
        type ELF_Header = crate::elf::header::ffi::ELF_Header;
        type ELF_Note = crate::elf::note::ffi::ELF_Note;
        type ELF_Relocation = crate::elf::relocation::ffi::ELF_Relocation;
        type ELF_Section = crate::elf::section::ffi::ELF_Section;
        type ELF_Segment = crate::elf::segment::ffi::ELF_Segment;
        type ELF_Symbol = crate::elf::symbol::ffi::ELF_Symbol;
        type ELF_SymbolVersion = crate::elf::symbol_version::ffi::ELF_SymbolVersion;
        type ELF_SymbolVersionDefinition =
            crate::elf::symbol_version_definition::ffi::ELF_SymbolVersionDefinition;
        type ELF_SymbolVersionRequirement =
            crate::elf::symbol_version_requirement::ffi::ELF_SymbolVersionRequirement;
        type ELF_SysvHash = crate::elf::sysvhash::ffi::ELF_SysvHash;

        type ELF_Binary_write_config_t = crate::elf::binary::write_config_t;

        type LIEF_ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::LIEF_ELF_DynamicEntry;

        type ELF_Binary;

        fn get_content_from_virtual_address(
            self: &ELF_Binary,
            virtual_address: u64,
            size: u64,
        ) -> Span;
        fn get_overlay(self: &ELF_Binary) -> Span;
        #[Self = "ELF_Binary"]
        fn parse(path: &CxxString) -> UniquePtr<ELF_Binary>;
        #[Self = "ELF_Binary"]
        fn parse_with_config(path: &CxxString, config: &ELF_ParserConfig) -> UniquePtr<ELF_Binary>;
        fn header(self: &ELF_Binary) -> UniquePtr<ELF_Header>;
        fn gnu_hash(self: &ELF_Binary) -> UniquePtr<ELF_GnuHash>;
        fn sysv_hash(self: &ELF_Binary) -> UniquePtr<ELF_SysvHash>;
        fn sections(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_sections>;
        fn segments(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_segments>;
        fn dynamic_entries(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_dynamic_entries>;
        fn dynamic_symbols(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_dynamic_symbols>;
        fn exported_symbols(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_exported_symbols>;
        fn imported_symbols(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_imported_symbols>;
        fn symtab_symbols(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_symtab_symbols>;
        fn notes(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_notes>;
        fn relocations(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_relocations>;
        fn pltgot_relocations(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_pltgot_relocations>;
        fn dynamic_relocations(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_dynamic_relocations>;
        fn object_relocations(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_object_relocations>;
        fn symbols_version(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_symbols_version>;
        fn symbols_version_requirement(
            self: &ELF_Binary,
        ) -> UniquePtr<ELF_Binary_it_symbols_version_requirement>;
        fn symbols_version_definition(
            self: &ELF_Binary,
        ) -> UniquePtr<ELF_Binary_it_symbols_version_definition>;
        fn section_by_name(self: &ELF_Binary, name: &CxxString) -> UniquePtr<ELF_Section>;
        fn relocation_for_symbol(self: &ELF_Binary, name: &CxxString) -> UniquePtr<ELF_Relocation>;
        fn get_dynamic_symbol(self: &ELF_Binary, name: &CxxString) -> UniquePtr<ELF_Symbol>;
        fn get_symtab_symbol(self: &ELF_Binary, name: &CxxString) -> UniquePtr<ELF_Symbol>;
        fn get_library(self: &ELF_Binary, name: &CxxString) -> UniquePtr<ELF_DynamicEntryLibrary>;
        fn section_from_offset(
            self: &ELF_Binary,
            offset: u64,
            skip_nobits: bool,
        ) -> UniquePtr<ELF_Section>;
        fn section_from_virtual_address(
            self: &ELF_Binary,
            address: u64,
            skip_nobits: bool,
        ) -> UniquePtr<ELF_Section>;
        fn segment_from_virtual_address(self: &ELF_Binary, address: u64) -> UniquePtr<ELF_Segment>;
        fn segment_from_offset(self: &ELF_Binary, offset: u64) -> UniquePtr<ELF_Segment>;
        fn virtual_address_to_offset(
            self: &ELF_Binary,
            virtual_address: u64,
            error: Pin<&mut u32>,
        ) -> u64;
        fn virtual_size(self: &ELF_Binary) -> u64;
        fn interpreter(self: &ELF_Binary) -> UniquePtr<CxxString>;
        fn set_interpreter(self: Pin<&mut ELF_Binary>, name: &CxxString);
        fn get_relocated_dynamic_array(self: &ELF_Binary, tag: u64) -> UniquePtr<CxxVector<u64>>;
        fn is_targeting_android(self: &ELF_Binary) -> bool;
        fn add_library(
            self: Pin<&mut ELF_Binary>,
            library: &CxxString,
        ) -> UniquePtr<ELF_DynamicEntryLibrary>;
        fn functions(self: &ELF_Binary) -> UniquePtr<AbstractBinary_it_functions>;
        fn remove_library(self: Pin<&mut ELF_Binary>, name: &CxxString);
        fn find_version_requirement(
            self: &ELF_Binary,
            libname: &CxxString,
        ) -> UniquePtr<ELF_SymbolVersionRequirement>;
        fn remove_version_requirement(self: Pin<&mut ELF_Binary>, libname: &CxxString) -> bool;
        fn symbols(self: &ELF_Binary) -> UniquePtr<ELF_Binary_it_symbols>;
        fn strings(self: &ELF_Binary, min_size: u64) -> UniquePtr<CxxVector<CxxString>>;
        fn last_offset_section(self: &ELF_Binary) -> u64;
        fn last_offset_segment(self: &ELF_Binary) -> u64;
        fn next_virtual_address(self: &ELF_Binary) -> u64;
        fn eof_offset(self: &ELF_Binary) -> u64;
        fn dtor_functions(self: &ELF_Binary) -> UniquePtr<AbstractBinary_it_functions>;
        fn has_section(self: &ELF_Binary, name: &CxxString) -> bool;
        fn has_section_with_offset(self: &ELF_Binary, offset: u64) -> bool;
        fn has_section_with_va(self: &ELF_Binary, va: u64) -> bool;
        fn has_library(self: &ELF_Binary, name: &CxxString) -> bool;
        fn has_dynamic_symbol(self: &ELF_Binary, name: &CxxString) -> bool;
        fn has_symtab_symbol(self: &ELF_Binary, name: &CxxString) -> bool;
        fn dynsym_idx(self: &ELF_Binary, name: &CxxString) -> i64;
        fn symtab_idx(self: &ELF_Binary, name: &CxxString) -> i64;
        fn patch_pltgot_by_name(self: Pin<&mut ELF_Binary>, symbol_name: &CxxString, address: u64);
        fn add_section(
            self: Pin<&mut ELF_Binary>,
            section: &ELF_Section,
            loaded: bool,
            pos: u32,
        ) -> UniquePtr<ELF_Section>;
        fn add_dynamic_relocation(
            self: Pin<&mut ELF_Binary>,
            reloc: &ELF_Relocation,
        ) -> UniquePtr<ELF_Relocation>;
        fn add_pltgot_relocation(
            self: Pin<&mut ELF_Binary>,
            reloc: &ELF_Relocation,
        ) -> UniquePtr<ELF_Relocation>;
        fn add_symtab_symbol(
            self: Pin<&mut ELF_Binary>,
            symbol: &ELF_Symbol,
        ) -> UniquePtr<ELF_Symbol>;
        fn add_dynamic_symbol(
            self: Pin<&mut ELF_Binary>,
            symbol: &ELF_Symbol,
        ) -> UniquePtr<ELF_Symbol>;
        fn add_exported_function(
            self: Pin<&mut ELF_Binary>,
            address: u64,
            name: &CxxString,
        ) -> UniquePtr<ELF_Symbol>;
        fn export_symbol_by_name(
            self: Pin<&mut ELF_Binary>,
            symbol_name: &CxxString,
            value: u64,
        ) -> UniquePtr<ELF_Symbol>;
        fn remove_symtab_symbol_by_name(self: Pin<&mut ELF_Binary>, name: &CxxString);
        fn remove_dynamic_symbol_by_name(self: Pin<&mut ELF_Binary>, name: &CxxString);
        fn remove_section(self: Pin<&mut ELF_Binary>, section: &ELF_Section, clear: bool);
        fn extend_segment(
            self: Pin<&mut ELF_Binary>,
            segment: &ELF_Segment,
            size: u64,
        ) -> UniquePtr<ELF_Segment>;
        fn extend_section(
            self: Pin<&mut ELF_Binary>,
            section: &ELF_Section,
            size: u64,
        ) -> UniquePtr<ELF_Section>;
        fn strip(self: Pin<&mut ELF_Binary>);
        fn get_section_idx_by_name(self: &ELF_Binary, name: &CxxString) -> i64;
        fn relocate_phdr_table(self: Pin<&mut ELF_Binary>, type_: u32) -> u64;
        fn write(self: Pin<&mut ELF_Binary>, output: &CxxString);
        fn remove_dynamic_entries_by_tag(self: Pin<&mut ELF_Binary>, tag: u64);
        fn remove_dynamic_entry(self: Pin<&mut ELF_Binary>, entry: &ELF_DynamicEntry);
        unsafe fn remove_dynamic_entry_from_ptr(
            self: Pin<&mut ELF_Binary>,
            ptr: *const LIEF_ELF_DynamicEntry,
        );
        unsafe fn set_overlay(self: Pin<&mut ELF_Binary>, data: *const u8, size: u64);
        fn add_dynamic_entry(
            self: Pin<&mut ELF_Binary>,
            entry: &ELF_DynamicEntry,
        ) -> UniquePtr<ELF_DynamicEntry>;
        fn relocation_by_addr(self: &ELF_Binary, addr: u64) -> UniquePtr<ELF_Relocation>;
        fn dynamic_entry_by_tag(self: &ELF_Binary, tag: u64) -> UniquePtr<ELF_DynamicEntry>;
        fn segment_by_type(self: &ELF_Binary, ty: u64) -> UniquePtr<ELF_Segment>;
        fn add_segment(self: Pin<&mut ELF_Binary>, segment: &ELF_Segment)
            -> UniquePtr<ELF_Segment>;
        fn remove_segment(self: Pin<&mut ELF_Binary>, segment: &ELF_Segment, clear: bool);
        fn remove_segments_by_type(self: Pin<&mut ELF_Binary>, ty: u64, clear: bool);
        fn has_dynamic_entry_tag(self: &ELF_Binary, tag: u64) -> bool;
        fn has_segment_type(self: &ELF_Binary, ty: u64) -> bool;
        fn has_note_type(self: &ELF_Binary, ty: u32) -> bool;
        fn has_section_type(self: &ELF_Binary, ty: u64) -> bool;
        fn get_note_by_type(self: &ELF_Binary, ty: u32) -> UniquePtr<ELF_Note>;
        fn get_section_by_type(self: &ELF_Binary, ty: u64) -> UniquePtr<ELF_Section>;
        fn add_note(self: Pin<&mut ELF_Binary>, note: &ELF_Note) -> UniquePtr<ELF_Note>;
        fn export_symbol_obj(
            self: Pin<&mut ELF_Binary>,
            symbol: &ELF_Symbol,
        ) -> UniquePtr<ELF_Symbol>;
        fn remove_note(self: Pin<&mut ELF_Binary>, note: &ELF_Note);
        fn get_section_idx_by_section(self: &ELF_Binary, section: &ELF_Section) -> i64;

        type ELF_Binary_it_dynamic_entries;

        fn next(self: Pin<&mut ELF_Binary_it_dynamic_entries>) -> UniquePtr<ELF_DynamicEntry>;
        fn size(self: &ELF_Binary_it_dynamic_entries) -> u64;

        type ELF_Binary_it_dynamic_relocations;

        fn next(self: Pin<&mut ELF_Binary_it_dynamic_relocations>) -> UniquePtr<ELF_Relocation>;
        fn size(self: &ELF_Binary_it_dynamic_relocations) -> u64;

        type ELF_Binary_it_dynamic_symbols;

        fn next(self: Pin<&mut ELF_Binary_it_dynamic_symbols>) -> UniquePtr<ELF_Symbol>;
        fn size(self: &ELF_Binary_it_dynamic_symbols) -> u64;

        type ELF_Binary_it_exported_symbols;

        fn next(self: Pin<&mut ELF_Binary_it_exported_symbols>) -> UniquePtr<ELF_Symbol>;
        fn size(self: &ELF_Binary_it_exported_symbols) -> u64;

        type ELF_Binary_it_imported_symbols;

        fn next(self: Pin<&mut ELF_Binary_it_imported_symbols>) -> UniquePtr<ELF_Symbol>;
        fn size(self: &ELF_Binary_it_imported_symbols) -> u64;

        type ELF_Binary_it_notes;

        fn next(self: Pin<&mut ELF_Binary_it_notes>) -> UniquePtr<ELF_Note>;
        fn size(self: &ELF_Binary_it_notes) -> u64;

        type ELF_Binary_it_object_relocations;

        fn next(self: Pin<&mut ELF_Binary_it_object_relocations>) -> UniquePtr<ELF_Relocation>;
        fn size(self: &ELF_Binary_it_object_relocations) -> u64;

        type ELF_Binary_it_pltgot_relocations;

        fn next(self: Pin<&mut ELF_Binary_it_pltgot_relocations>) -> UniquePtr<ELF_Relocation>;
        fn size(self: &ELF_Binary_it_pltgot_relocations) -> u64;

        type ELF_Binary_it_relocations;

        fn next(self: Pin<&mut ELF_Binary_it_relocations>) -> UniquePtr<ELF_Relocation>;
        fn size(self: &ELF_Binary_it_relocations) -> u64;

        type ELF_Binary_it_sections;

        fn next(self: Pin<&mut ELF_Binary_it_sections>) -> UniquePtr<ELF_Section>;
        fn size(self: &ELF_Binary_it_sections) -> u64;

        type ELF_Binary_it_segments;

        fn next(self: Pin<&mut ELF_Binary_it_segments>) -> UniquePtr<ELF_Segment>;
        fn size(self: &ELF_Binary_it_segments) -> u64;

        type ELF_Binary_it_symbols;

        fn next(self: Pin<&mut ELF_Binary_it_symbols>) -> UniquePtr<ELF_Symbol>;
        fn size(self: &ELF_Binary_it_symbols) -> u64;

        type ELF_Binary_it_symbols_version;

        fn next(self: Pin<&mut ELF_Binary_it_symbols_version>) -> UniquePtr<ELF_SymbolVersion>;
        fn size(self: &ELF_Binary_it_symbols_version) -> u64;

        type ELF_Binary_it_symbols_version_definition;

        fn next(
            self: Pin<&mut ELF_Binary_it_symbols_version_definition>,
        ) -> UniquePtr<ELF_SymbolVersionDefinition>;
        fn size(self: &ELF_Binary_it_symbols_version_definition) -> u64;

        type ELF_Binary_it_symbols_version_requirement;

        fn next(
            self: Pin<&mut ELF_Binary_it_symbols_version_requirement>,
        ) -> UniquePtr<ELF_SymbolVersionRequirement>;
        fn size(self: &ELF_Binary_it_symbols_version_requirement) -> u64;

        type ELF_Binary_it_symtab_symbols;

        fn next(self: Pin<&mut ELF_Binary_it_symtab_symbols>) -> UniquePtr<ELF_Symbol>;
        fn size(self: &ELF_Binary_it_symtab_symbols) -> u64;

        fn write_with_config(
            self: Pin<&mut ELF_Binary>,
            output: &CxxString,
            config: &ELF_Binary_write_config_t,
        );

        type ELF_ParserConfig;

        #[Self = "ELF_ParserConfig"]
        fn create() -> UniquePtr<ELF_ParserConfig>;
        fn set_parse_relocations(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_parse_dyn_symbols(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_parse_symtab_symbols(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_parse_symbol_versions(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_parse_notes(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_parse_overlay(self: Pin<&mut ELF_ParserConfig>, value: bool);
        fn set_count_mtd(self: Pin<&mut ELF_ParserConfig>, value: u32);
        fn set_page_size(self: Pin<&mut ELF_ParserConfig>, value: u64);
    }
    impl UniquePtr<ELF_Binary> {}
    impl UniquePtr<ELF_Binary_it_dynamic_entries> {}
    impl UniquePtr<ELF_Binary_it_dynamic_relocations> {}
    impl UniquePtr<ELF_Binary_it_dynamic_symbols> {}
    impl UniquePtr<ELF_Binary_it_exported_symbols> {}
    impl UniquePtr<ELF_Binary_it_imported_symbols> {}
    impl UniquePtr<ELF_Binary_it_notes> {}
    impl UniquePtr<ELF_Binary_it_object_relocations> {}
    impl UniquePtr<ELF_Binary_it_pltgot_relocations> {}
    impl UniquePtr<ELF_Binary_it_relocations> {}
    impl UniquePtr<ELF_Binary_it_sections> {}
    impl UniquePtr<ELF_Binary_it_segments> {}
    impl UniquePtr<ELF_Binary_it_symbols> {}
    impl UniquePtr<ELF_Binary_it_symbols_version> {}
    impl UniquePtr<ELF_Binary_it_symbols_version_definition> {}
    impl UniquePtr<ELF_Binary_it_symbols_version_requirement> {}
    impl UniquePtr<ELF_Binary_it_symtab_symbols> {}
    impl UniquePtr<ELF_ParserConfig> {}
}
