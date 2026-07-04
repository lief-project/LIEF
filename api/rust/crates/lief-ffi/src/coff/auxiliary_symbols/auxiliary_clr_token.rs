#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliaryCLRToken.hpp");
        include!("LIEF/rust/COFF/Section.hpp");

        type Span = crate::utils::ffi::Span;
        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;
        type COFF_Symbol = crate::coff::symbol::ffi::COFF_Symbol;

        type COFF_AuxiliaryCLRToken;

        fn rgb_reserved(self: &COFF_AuxiliaryCLRToken) -> Span;
        #[Self = "COFF_AuxiliaryCLRToken"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
        fn aux_type(self: &COFF_AuxiliaryCLRToken) -> u8;
        fn reserved(self: &COFF_AuxiliaryCLRToken) -> u8;
        fn symbol_idx(self: &COFF_AuxiliaryCLRToken) -> u32;
        fn symbol(self: &COFF_AuxiliaryCLRToken) -> UniquePtr<COFF_Symbol>;
    }
    impl UniquePtr<COFF_AuxiliaryCLRToken> {}
}
