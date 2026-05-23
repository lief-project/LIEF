#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliarybfAndefSymbol.hpp");

        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;

        type COFF_AuxiliarybfAndefSymbol;

        #[Self = "COFF_AuxiliarybfAndefSymbol"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
    }
    impl UniquePtr<COFF_AuxiliarybfAndefSymbol> {}
}
