#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliaryFile.hpp");

        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;

        type COFF_AuxiliaryFile;

        #[Self = "COFF_AuxiliaryFile"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
        fn filename(self: &COFF_AuxiliaryFile) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<COFF_AuxiliaryFile> {}
}
