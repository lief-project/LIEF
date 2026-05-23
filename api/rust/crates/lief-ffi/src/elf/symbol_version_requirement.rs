#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/SymbolVersionRequirement.hpp");

        type ELF_SymbolVersionAuxRequirement =
            crate::elf::symbol_version_aux_requirement::ffi::ELF_SymbolVersionAuxRequirement;

        type ELF_SymbolVersionRequirement;

        fn version(self: &ELF_SymbolVersionRequirement) -> u16;
        fn cnt(self: &ELF_SymbolVersionRequirement) -> u32;
        fn name(self: &ELF_SymbolVersionRequirement) -> UniquePtr<CxxString>;
        fn auxiliary_symbols(
            self: &ELF_SymbolVersionRequirement,
        ) -> UniquePtr<ELF_SymbolVersionRequirement_it_auxiliary_symbols>;
        fn set_name(self: Pin<&mut ELF_SymbolVersionRequirement>, name: &CxxString);
        fn find_aux(
            self: &ELF_SymbolVersionRequirement,
            name: &CxxString,
        ) -> UniquePtr<ELF_SymbolVersionAuxRequirement>;
        fn remove_aux_requirement_by_name(
            self: Pin<&mut ELF_SymbolVersionRequirement>,
            name: &CxxString,
        ) -> bool;
        fn set_version(self: Pin<&mut ELF_SymbolVersionRequirement>, version: u16);

        type ELF_SymbolVersionRequirement_it_auxiliary_symbols;

        fn next(
            self: Pin<&mut ELF_SymbolVersionRequirement_it_auxiliary_symbols>,
        ) -> UniquePtr<ELF_SymbolVersionAuxRequirement>;
        fn size(self: &ELF_SymbolVersionRequirement_it_auxiliary_symbols) -> u64;
    }

    impl UniquePtr<ELF_SymbolVersionRequirement> {}
    impl UniquePtr<ELF_SymbolVersionRequirement_it_auxiliary_symbols> {}
}
