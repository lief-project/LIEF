#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliaryWeakExternal.hpp");

        type Span = crate::utils::ffi::Span;
        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;

        type COFF_AuxiliaryWeakExternal;

        fn padding(self: &COFF_AuxiliaryWeakExternal) -> Span;
        #[Self = "COFF_AuxiliaryWeakExternal"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
        fn sym_idx(self: &COFF_AuxiliaryWeakExternal) -> u32;
        fn characteristics(self: &COFF_AuxiliaryWeakExternal) -> u32;
    }
    impl UniquePtr<COFF_AuxiliaryWeakExternal> {}
}
