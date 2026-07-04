#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/SymbolVersionAuxRequirement.hpp");

        type ELF_SymbolVersionAuxRequirement;

        fn hash(self: &ELF_SymbolVersionAuxRequirement) -> u32;
        fn flags(self: &ELF_SymbolVersionAuxRequirement) -> u16;
        fn other(self: &ELF_SymbolVersionAuxRequirement) -> u16;
        fn name(self: &ELF_SymbolVersionAuxRequirement) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<ELF_SymbolVersionAuxRequirement> {}
}
