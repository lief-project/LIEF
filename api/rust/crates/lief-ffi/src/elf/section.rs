#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type ELF_Section;

        #[Self = "ELF_Section"]
        fn create() -> UniquePtr<ELF_Section>;
        #[Self = "ELF_Section"]
        fn create_with_name(name: &CxxString) -> UniquePtr<ELF_Section>;
        #[Self = "ELF_Section"]
        unsafe fn create_with_content(
            name: &CxxString,
            buffer: *const u8,
            size: usize,
        ) -> UniquePtr<ELF_Section>;
        fn get_type(self: &ELF_Section) -> u64;
        fn flags(self: &ELF_Section) -> u64;
        fn alignment(self: &ELF_Section) -> u64;
        fn information(self: &ELF_Section) -> u64;
        fn entry_size(self: &ELF_Section) -> u64;
        fn link(self: &ELF_Section) -> u64;
        fn file_offset(self: &ELF_Section) -> u64;
        fn original_size(self: &ELF_Section) -> u64;
        fn content(self: &ELF_Section) -> Span;
        fn to_string(self: &ELF_Section) -> UniquePtr<CxxString>;
        fn set_type(self: Pin<&mut ELF_Section>, value: u64);
        fn set_flags(self: Pin<&mut ELF_Section>, value: u64);
        fn set_alignment(self: Pin<&mut ELF_Section>, value: u64);
    }

    impl UniquePtr<ELF_Section> {}
}
