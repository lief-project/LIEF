#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type ELF_Section;

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
    }

    impl UniquePtr<ELF_Section> {}
}
