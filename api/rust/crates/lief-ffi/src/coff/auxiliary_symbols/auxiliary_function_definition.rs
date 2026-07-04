#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/AuxiliarySymbols/AuxiliaryFunctionDefinition.hpp");

        type COFF_AuxiliarySymbol = crate::coff::auxiliary_symbol::ffi::COFF_AuxiliarySymbol;

        type COFF_AuxiliaryFunctionDefinition;

        #[Self = "COFF_AuxiliaryFunctionDefinition"]
        fn classof(entry: &COFF_AuxiliarySymbol) -> bool;
        fn tag_index(self: &COFF_AuxiliaryFunctionDefinition) -> u32;
        fn total_size(self: &COFF_AuxiliaryFunctionDefinition) -> u32;
        fn ptr_to_line_number(self: &COFF_AuxiliaryFunctionDefinition) -> u32;
        fn ptr_to_next_func(self: &COFF_AuxiliaryFunctionDefinition) -> u32;
        fn padding(self: &COFF_AuxiliaryFunctionDefinition) -> u16;
    }
    impl UniquePtr<COFF_AuxiliaryFunctionDefinition> {}
}
