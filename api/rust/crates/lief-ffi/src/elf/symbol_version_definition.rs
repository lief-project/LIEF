#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/SymbolVersionDefinition.hpp");

        type ELF_SymbolVersionAux = crate::elf::symbol_version_aux::ffi::ELF_SymbolVersionAux;

        type ELF_SymbolVersionDefinition;

        fn version(self: &ELF_SymbolVersionDefinition) -> u16;
        fn flags(self: &ELF_SymbolVersionDefinition) -> u16;
        fn ndx(self: &ELF_SymbolVersionDefinition) -> u16;
        fn hash(self: &ELF_SymbolVersionDefinition) -> u32;
        fn sym_aux(
            self: &ELF_SymbolVersionDefinition,
        ) -> UniquePtr<ELF_SymbolVersionDefinition_it_auxiliary_symbols>;

        type ELF_SymbolVersionDefinition_it_auxiliary_symbols;

        fn next(
            self: Pin<&mut ELF_SymbolVersionDefinition_it_auxiliary_symbols>,
        ) -> UniquePtr<ELF_SymbolVersionAux>;
        fn size(self: &ELF_SymbolVersionDefinition_it_auxiliary_symbols) -> u64;
    }

    impl UniquePtr<ELF_SymbolVersionDefinition> {}
    impl UniquePtr<ELF_SymbolVersionDefinition_it_auxiliary_symbols> {}
}
