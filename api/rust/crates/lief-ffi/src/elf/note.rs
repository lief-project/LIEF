#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Note.hpp");

        type Span = crate::utils::ffi::Span;
        type ELF_Note;

        fn name(self: &ELF_Note) -> UniquePtr<CxxString>;
        fn get_type(self: &ELF_Note) -> u32;
        fn original_type(self: &ELF_Note) -> u32;
        fn size(self: &ELF_Note) -> u64;
        fn description(self: &ELF_Note) -> Span;
    }

    impl UniquePtr<ELF_Note> {}
}
