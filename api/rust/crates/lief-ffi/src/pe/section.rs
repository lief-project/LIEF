#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type COFF_String = crate::coff::string::ffi::COFF_String;

        type PE_Section;

        fn padding(self: &PE_Section) -> Span;
        #[Self = "PE_Section"]
        fn create() -> UniquePtr<PE_Section>;
        #[Self = "PE_Section"]
        fn create_with_name(name: &CxxString) -> UniquePtr<PE_Section>;
        #[Self = "PE_Section"]
        unsafe fn create_with_content(
            name: &CxxString,
            buffer: *const u8,
            size: usize,
        ) -> UniquePtr<PE_Section>;
        fn sizeof_raw_data(self: &PE_Section) -> u32;
        fn virtual_size(self: &PE_Section) -> u32;
        fn pointerto_raw_data(self: &PE_Section) -> u32;
        fn pointerto_relocation(self: &PE_Section) -> u32;
        fn pointerto_line_numbers(self: &PE_Section) -> u32;
        fn numberof_relocations(self: &PE_Section) -> u16;
        fn numberof_line_numbers(self: &PE_Section) -> u16;
        fn characteristics(self: &PE_Section) -> u32;
        fn is_discardable(self: &PE_Section) -> bool;
        fn coff_string(self: &PE_Section) -> UniquePtr<COFF_String>;
        fn set_virtual_size(self: Pin<&mut PE_Section>, virtual_size: u32);
    }
    impl UniquePtr<PE_Section> {}
}
