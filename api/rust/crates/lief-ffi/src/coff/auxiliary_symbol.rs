#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbol.hpp");

        type Span = crate::utils::ffi::Span;
        type COFF_AuxiliarySymbol;

        fn payload(self: &COFF_AuxiliarySymbol) -> Span;
    }

    impl UniquePtr<COFF_AuxiliarySymbol> {}
}
