#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliarySectionDefinition.hpp");

        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;

        type COFF_AuxiliarySectionDefinition;

        #[Self = "COFF_AuxiliarySectionDefinition"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
        fn length(self: &COFF_AuxiliarySectionDefinition) -> u32;
        fn nb_relocs(self: &COFF_AuxiliarySectionDefinition) -> u16;
        fn nb_line_numbers(self: &COFF_AuxiliarySectionDefinition) -> u16;
        fn checksum(self: &COFF_AuxiliarySectionDefinition) -> u32;
        fn section_idx(self: &COFF_AuxiliarySectionDefinition) -> u32;
        fn selection(self: &COFF_AuxiliarySectionDefinition) -> u8;
        fn reserved(self: &COFF_AuxiliarySectionDefinition) -> u8;
    }
    impl UniquePtr<COFF_AuxiliarySectionDefinition> {}
}
