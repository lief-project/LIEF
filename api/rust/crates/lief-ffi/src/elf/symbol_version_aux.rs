#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/SymbolVersionAux.hpp");

        type ELF_SymbolVersionAux;

        fn name(self: &ELF_SymbolVersionAux) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<ELF_SymbolVersionAux> {}
}
