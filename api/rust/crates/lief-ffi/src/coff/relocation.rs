#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/Relocation.hpp");
        include!("LIEF/rust/COFF/Section.hpp");
        include!("LIEF/rust/COFF/Symbol.hpp");

        type COFF_Section = crate::coff::section::ffi::COFF_Section;
        type COFF_Symbol = crate::coff::symbol::ffi::COFF_Symbol;

        type COFF_Relocation;

        fn symbol_idx(self: &COFF_Relocation) -> u32;
        fn symbol(self: &COFF_Relocation) -> UniquePtr<COFF_Symbol>;
        fn get_type(self: &COFF_Relocation) -> u32;
        fn section(self: &COFF_Relocation) -> UniquePtr<COFF_Section>;
        fn to_string(self: &COFF_Relocation) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<COFF_Relocation> {}
}
