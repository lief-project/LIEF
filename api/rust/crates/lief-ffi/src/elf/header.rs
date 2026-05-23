#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Header.hpp");

        type ELF_Header;

        fn entrypoint(self: &ELF_Header) -> u64;
        fn file_type(self: &ELF_Header) -> u32;
        fn machine_type(self: &ELF_Header) -> u32;
        fn object_file_version(self: &ELF_Header) -> u32;
        fn identity_class(self: &ELF_Header) -> u32;
        fn identity_os_abi(self: &ELF_Header) -> u32;
        fn identity_version(self: &ELF_Header) -> u32;
        fn identity_data(self: &ELF_Header) -> u32;
        fn identity_abi_version(self: &ELF_Header) -> u32;
        fn program_headers_offset(self: &ELF_Header) -> u64;
        fn section_headers_offset(self: &ELF_Header) -> u64;
        fn processor_flag(self: &ELF_Header) -> u32;
        fn header_size(self: &ELF_Header) -> u32;
        fn program_header_size(self: &ELF_Header) -> u32;
        fn numberof_segments(self: &ELF_Header) -> u32;
        fn section_header_size(self: &ELF_Header) -> u32;
        fn numberof_sections(self: &ELF_Header) -> u32;
        fn section_name_table_idx(self: &ELF_Header) -> u32;
        fn set_osabi(self: Pin<&mut ELF_Header>, value: u32);
    }

    impl UniquePtr<ELF_Header> {}
}
