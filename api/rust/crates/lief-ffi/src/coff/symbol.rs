#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/Symbol.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;
        type COFF_Section = crate::coff::section::ffi::COFF_Section;

        type COFF_Symbol;

        fn storage_class(self: &COFF_Symbol) -> u32;
        fn base_type(self: &COFF_Symbol) -> u32;
        fn complex_type(self: &COFF_Symbol) -> u32;
        fn section_idx(self: &COFF_Symbol) -> i16;
        fn section(self: &COFF_Symbol) -> UniquePtr<COFF_Section>;
        fn is_external(self: &COFF_Symbol) -> bool;
        fn is_function(self: &COFF_Symbol) -> bool;
        fn is_absolute(self: &COFF_Symbol) -> bool;
        fn is_weak_external(self: &COFF_Symbol) -> bool;
        fn is_undefined(self: &COFF_Symbol) -> bool;
        fn is_function_line_info(self: &COFF_Symbol) -> bool;
        fn is_file_record(self: &COFF_Symbol) -> bool;
        fn auxiliary_symbols(self: &COFF_Symbol) -> UniquePtr<COFF_Symbol_it_auxiliary_symbols>;
        fn demangled_name(self: &COFF_Symbol) -> UniquePtr<CxxString>;
        fn to_string(self: &COFF_Symbol) -> UniquePtr<CxxString>;

        type COFF_Symbol_it_auxiliary_symbols;

        fn next(
            self: Pin<&mut COFF_Symbol_it_auxiliary_symbols>,
        ) -> UniquePtr<COFF_AuxiliarySymbol>;
        fn size(self: &COFF_Symbol_it_auxiliary_symbols) -> u64;
    }

    impl UniquePtr<COFF_Symbol> {}
    impl UniquePtr<COFF_Symbol_it_auxiliary_symbols> {}
}
