#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/DataDirectories.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Section = crate::pe::section::ffi::PE_Section;

        type PE_DataDirectory;

        fn content(self: &PE_DataDirectory) -> Span;
        fn RVA(self: &PE_DataDirectory) -> u32;
        fn size(self: &PE_DataDirectory) -> u32;
        fn get_type(self: &PE_DataDirectory) -> u32;
        fn section(self: &PE_DataDirectory) -> UniquePtr<PE_Section>;
    }

    impl UniquePtr<PE_DataDirectory> {}
}
