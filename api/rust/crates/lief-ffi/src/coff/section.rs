#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/Section.hpp");
        include!("LIEF/rust/COFF/Symbol.hpp");
        include!("LIEF/rust/COFF/Relocation.hpp");

        type COFF_Relocation = crate::coff::relocation::ffi::COFF_Relocation;
        type COFF_String = crate::coff::string::ffi::COFF_String;
        type COFF_Symbol = crate::coff::symbol::ffi::COFF_Symbol;

        type COFF_Section;

        fn sizeof_raw_data(self: &COFF_Section) -> u32;
        fn virtual_size(self: &COFF_Section) -> u32;
        fn pointerto_raw_data(self: &COFF_Section) -> u32;
        fn pointerto_relocation(self: &COFF_Section) -> u32;
        fn pointerto_line_numbers(self: &COFF_Section) -> u32;
        fn numberof_relocations(self: &COFF_Section) -> u16;
        fn numberof_line_numbers(self: &COFF_Section) -> u16;
        fn characteristics(self: &COFF_Section) -> u32;
        fn is_discardable(self: &COFF_Section) -> bool;
        fn has_extended_relocations(self: &COFF_Section) -> bool;
        fn relocations(self: &COFF_Section) -> UniquePtr<COFF_Section_it_relocations>;
        fn symbols(self: &COFF_Section) -> UniquePtr<COFF_Section_it_symbols>;
        fn comdat_info(self: &COFF_Section) -> UniquePtr<COFF_Section_ComdataInfo>;
        fn coff_string(self: &COFF_Section) -> UniquePtr<COFF_String>;
        fn to_string(self: &COFF_Section) -> UniquePtr<CxxString>;

        type COFF_Section_ComdataInfo;

        fn symbol(self: &COFF_Section_ComdataInfo) -> UniquePtr<COFF_Symbol>;
        fn kind(self: &COFF_Section_ComdataInfo) -> u8;

        type COFF_Section_it_relocations;

        fn next(self: Pin<&mut COFF_Section_it_relocations>) -> UniquePtr<COFF_Relocation>;
        fn size(self: &COFF_Section_it_relocations) -> u64;

        type COFF_Section_it_symbols;

        fn next(self: Pin<&mut COFF_Section_it_symbols>) -> UniquePtr<COFF_Symbol>;
        fn size(self: &COFF_Section_it_symbols) -> u64;
    }

    impl UniquePtr<COFF_Section> {}
    impl UniquePtr<COFF_Section_ComdataInfo> {}
    impl UniquePtr<COFF_Section_it_relocations> {}
    impl UniquePtr<COFF_Section_it_symbols> {}
}
