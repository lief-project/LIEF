#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Binary.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type AbstractBinary_it_functions = crate::generic::binary::ffi::AbstractBinary_it_functions;
        type COFF_String = crate::coff::string::ffi::COFF_String;
        type COFF_Symbol = crate::coff::symbol::ffi::COFF_Symbol;
        type PE_CodeViewPDB = crate::pe::debug::code_view_pdb::ffi::PE_CodeViewPDB;
        type PE_DataDirectory = crate::pe::data_directories::ffi::PE_DataDirectory;
        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;
        type PE_DelayImport = crate::pe::delay_import::ffi::PE_DelayImport;
        type PE_DosHeader = crate::pe::dos_header::ffi::PE_DosHeader;
        type PE_ExceptionInfo = crate::pe::exception_info::ffi::PE_ExceptionInfo;
        type PE_Export = crate::pe::export::ffi::PE_Export;
        type PE_Header = crate::pe::header::ffi::PE_Header;
        type PE_Import = crate::pe::import::ffi::PE_Import;
        type PE_LoadConfiguration =
            crate::pe::load_configuration::load_configuration::ffi::PE_LoadConfiguration;
        type PE_OptionalHeader = crate::pe::optional_header::ffi::PE_OptionalHeader;
        type PE_Relocation = crate::pe::relocation::ffi::PE_Relocation;
        type PE_ResourceNode = crate::pe::resource_node::ffi::PE_ResourceNode;
        type PE_ResourcesManager = crate::pe::resources_manager::ffi::PE_ResourcesManager;
        type PE_RichHeader = crate::pe::rich_header::ffi::PE_RichHeader;
        type PE_Section = crate::pe::section::ffi::PE_Section;
        type PE_Signature = crate::pe::signature::signature::ffi::PE_Signature;
        type PE_TLS = crate::pe::tls::ffi::PE_TLS;

        type PE_Binary;

        fn get_content_from_virtual_address(
            self: &PE_Binary,
            virtual_address: u64,
            size: u64,
        ) -> Span;
        fn dos_stub(self: &PE_Binary) -> Span;
        fn overlay(self: &PE_Binary) -> Span;
        #[Self = "PE_Binary"]
        fn parse(path: &CxxString) -> UniquePtr<PE_Binary>;
        #[Self = "PE_Binary"]
        fn parse_with_config(path: &CxxString, config: &PE_ParserConfig) -> UniquePtr<PE_Binary>;
        fn debug(self: &PE_Binary) -> UniquePtr<PE_Binary_it_debug>;
        fn signatures(self: &PE_Binary) -> UniquePtr<PE_Binary_it_signatures>;
        fn sections(self: &PE_Binary) -> UniquePtr<PE_Binary_it_sections>;
        fn relocations(self: &PE_Binary) -> UniquePtr<PE_Binary_it_relocations>;
        fn imports(self: &PE_Binary) -> UniquePtr<PE_Binary_it_imports>;
        fn delay_imports(self: &PE_Binary) -> UniquePtr<PE_Binary_it_delay_imports>;
        fn data_directories(self: &PE_Binary) -> UniquePtr<PE_Binary_it_data_directories>;
        fn tls(self: &PE_Binary) -> UniquePtr<PE_TLS>;
        fn rich_header(self: &PE_Binary) -> UniquePtr<PE_RichHeader>;
        fn get_export(self: &PE_Binary) -> UniquePtr<PE_Export>;
        fn resources(self: &PE_Binary) -> UniquePtr<PE_ResourceNode>;
        fn load_configuration(self: &PE_Binary) -> UniquePtr<PE_LoadConfiguration>;
        fn dos_header(self: &PE_Binary) -> UniquePtr<PE_DosHeader>;
        fn header(self: &PE_Binary) -> UniquePtr<PE_Header>;
        fn optional_header(self: &PE_Binary) -> UniquePtr<PE_OptionalHeader>;
        fn compute_checksum(self: &PE_Binary) -> u32;
        fn resources_manager(self: &PE_Binary) -> UniquePtr<PE_ResourcesManager>;
        fn verify_signature(self: &PE_Binary, flags: u32) -> u32;
        fn authentihash(self: &PE_Binary, algo: u32) -> UniquePtr<CxxVector<u8>>;
        fn overlay_offset(self: &PE_Binary) -> u64;
        fn rva_to_offset(self: &PE_Binary, rva: u64) -> u64;
        fn va_to_offset(self: &PE_Binary, rva: u64) -> u64;
        fn offset_to_rva(self: &PE_Binary, offset: u64) -> u64;
        fn virtual_size(self: &PE_Binary) -> u64;
        fn sizeof_headers(self: &PE_Binary) -> u64;
        fn section_from_offset(self: &PE_Binary, offset: u64) -> UniquePtr<PE_Section>;
        fn section_from_rva(self: &PE_Binary, address: u64) -> UniquePtr<PE_Section>;
        fn section_by_name(self: &PE_Binary, name: &CxxString) -> UniquePtr<PE_Section>;
        fn add_section(self: Pin<&mut PE_Binary>, section: &PE_Section) -> UniquePtr<PE_Section>;
        fn import_by_name(self: &PE_Binary, name: &CxxString) -> UniquePtr<PE_Import>;
        fn delay_import_by_name(self: &PE_Binary, name: &CxxString) -> UniquePtr<PE_DelayImport>;
        fn export_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn import_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn rsrc_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn exceptions_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn cert_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn relocation_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn debug_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn tls_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn load_config_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn iat_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn delay_dir(self: &PE_Binary) -> UniquePtr<PE_DataDirectory>;
        fn functions(self: &PE_Binary) -> UniquePtr<AbstractBinary_it_functions>;
        fn add_import(self: Pin<&mut PE_Binary>, name: &CxxString) -> UniquePtr<PE_Import>;
        fn add_import_pos(
            self: Pin<&mut PE_Binary>,
            name: &CxxString,
            pos: u32,
        ) -> UniquePtr<PE_Import>;
        fn remove_import(self: Pin<&mut PE_Binary>, name: &CxxString);
        fn remove_all_imports(self: Pin<&mut PE_Binary>);
        fn remove_tls(self: Pin<&mut PE_Binary>);
        fn set_tls(self: Pin<&mut PE_Binary>, tls: &PE_TLS);
        fn set_resources(self: Pin<&mut PE_Binary>, node: &PE_ResourceNode);
        fn add_debug_info(self: Pin<&mut PE_Binary>, entry: &PE_Debug) -> UniquePtr<PE_Debug>;
        fn remove_debug(self: Pin<&mut PE_Binary>, entry: &PE_Debug) -> bool;
        fn clear_debug(self: Pin<&mut PE_Binary>) -> bool;
        fn codeview_pdb(self: &PE_Binary) -> UniquePtr<PE_CodeViewPDB>;
        fn coff_string_table(self: &PE_Binary) -> UniquePtr<PE_Binary_it_strings_table>;
        fn symbols(self: &PE_Binary) -> UniquePtr<PE_Binary_it_symbols>;
        fn exceptions(self: &PE_Binary) -> UniquePtr<PE_Binary_it_exceptions>;
        fn find_exception_at(self: &PE_Binary, rva: u32) -> UniquePtr<PE_ExceptionInfo>;
        fn is_arm64x(self: &PE_Binary) -> bool;
        fn is_arm64ec(self: &PE_Binary) -> bool;
        fn nested_pe_binary(self: &PE_Binary) -> UniquePtr<PE_Binary>;
        fn write(self: Pin<&mut PE_Binary>, output: &CxxString);
        fn write_with_config(
            self: Pin<&mut PE_Binary>,
            output: &CxxString,
            config: &PE_Binary_write_config_t,
        );
        fn set_export(self: Pin<&mut PE_Binary>, exp: &PE_Export);
        fn is_reproducible_build(self: &PE_Binary) -> bool;
        fn has_import(self: &PE_Binary, name: &CxxString) -> bool;
        fn has_delay_import(self: &PE_Binary, name: &CxxString) -> bool;
        fn exception_functions(self: &PE_Binary) -> UniquePtr<AbstractBinary_it_functions>;
        fn remove_section(self: Pin<&mut PE_Binary>, name: &CxxString, clear: bool);
        fn fill_address(self: Pin<&mut PE_Binary>, address: u64, size: u64, value: u8);
        fn remove_all_relocations(self: Pin<&mut PE_Binary>);
        fn verify_with_signature(self: &PE_Binary, sig: &PE_Signature, flags: u32) -> u32;
        fn data_directory_by_type(self: &PE_Binary, type_: u32) -> UniquePtr<PE_DataDirectory>;
        fn find_coff_string_at(self: &PE_Binary, offset: u32) -> UniquePtr<COFF_String>;

        type PE_Binary_it_data_directories;

        fn next(self: Pin<&mut PE_Binary_it_data_directories>) -> UniquePtr<PE_DataDirectory>;
        fn size(self: &PE_Binary_it_data_directories) -> u64;

        type PE_Binary_it_debug;

        fn next(self: Pin<&mut PE_Binary_it_debug>) -> UniquePtr<PE_Debug>;
        fn size(self: &PE_Binary_it_debug) -> u64;

        type PE_Binary_it_delay_imports;

        fn next(self: Pin<&mut PE_Binary_it_delay_imports>) -> UniquePtr<PE_DelayImport>;
        fn size(self: &PE_Binary_it_delay_imports) -> u64;

        type PE_Binary_it_exceptions;

        fn next(self: Pin<&mut PE_Binary_it_exceptions>) -> UniquePtr<PE_ExceptionInfo>;
        fn size(self: &PE_Binary_it_exceptions) -> u64;

        type PE_Binary_it_imports;

        fn next(self: Pin<&mut PE_Binary_it_imports>) -> UniquePtr<PE_Import>;
        fn size(self: &PE_Binary_it_imports) -> u64;

        type PE_Binary_it_relocations;

        fn next(self: Pin<&mut PE_Binary_it_relocations>) -> UniquePtr<PE_Relocation>;
        fn size(self: &PE_Binary_it_relocations) -> u64;

        type PE_Binary_it_sections;

        fn next(self: Pin<&mut PE_Binary_it_sections>) -> UniquePtr<PE_Section>;
        fn size(self: &PE_Binary_it_sections) -> u64;

        type PE_Binary_it_signatures;

        fn next(self: Pin<&mut PE_Binary_it_signatures>) -> UniquePtr<PE_Signature>;
        fn size(self: &PE_Binary_it_signatures) -> u64;

        type PE_Binary_it_strings_table;

        fn next(self: Pin<&mut PE_Binary_it_strings_table>) -> UniquePtr<COFF_String>;
        fn size(self: &PE_Binary_it_strings_table) -> u64;

        type PE_Binary_it_symbols;

        fn next(self: Pin<&mut PE_Binary_it_symbols>) -> UniquePtr<COFF_Symbol>;
        fn size(self: &PE_Binary_it_symbols) -> u64;

        type PE_Binary_write_config_t;

        #[Self = "PE_Binary_write_config_t"]
        fn create() -> UniquePtr<PE_Binary_write_config_t>;
        fn set_resources(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_overlay(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_rsrc_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_idata_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_tls_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_reloc_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_export_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_debug_section(self: Pin<&mut PE_Binary_write_config_t>, sec: &CxxString);
        fn set_import(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_exports(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_relocations(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_load_config(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_tls(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_debug(self: Pin<&mut PE_Binary_write_config_t>, value: bool);
        fn set_dos_stub(self: Pin<&mut PE_Binary_write_config_t>, value: bool);

        type PE_ParserConfig;

        #[Self = "PE_ParserConfig"]
        fn create() -> UniquePtr<PE_ParserConfig>;
        fn set_parse_signature(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_exports(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_imports(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_rsrc(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_reloc(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_exceptions(self: Pin<&mut PE_ParserConfig>, value: bool);
        fn set_parse_arm64x_binary(self: Pin<&mut PE_ParserConfig>, value: bool);
    }
    impl UniquePtr<PE_Binary> {}
    impl UniquePtr<PE_Binary_it_data_directories> {}
    impl UniquePtr<PE_Binary_it_debug> {}
    impl UniquePtr<PE_Binary_it_delay_imports> {}
    impl UniquePtr<PE_Binary_it_exceptions> {}
    impl UniquePtr<PE_Binary_it_imports> {}
    impl UniquePtr<PE_Binary_it_relocations> {}
    impl UniquePtr<PE_Binary_it_sections> {}
    impl UniquePtr<PE_Binary_it_signatures> {}
    impl UniquePtr<PE_Binary_it_strings_table> {}
    impl UniquePtr<PE_Binary_it_symbols> {}
    impl UniquePtr<PE_Binary_write_config_t> {}
    impl UniquePtr<PE_ParserConfig> {}
}
