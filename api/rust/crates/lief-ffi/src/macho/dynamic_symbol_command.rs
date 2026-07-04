#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DynamicSymbolCommand.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_Symbol = crate::macho::symbol::ffi::MachO_Symbol;

        type MachO_DynamicSymbolCommand;

        #[Self = "MachO_DynamicSymbolCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn idx_local_symbol(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_local_symbols(self: &MachO_DynamicSymbolCommand) -> u32;
        fn idx_external_define_symbol(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_external_define_symbols(self: &MachO_DynamicSymbolCommand) -> u32;
        fn idx_undefined_symbol(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_undefined_symbols(self: &MachO_DynamicSymbolCommand) -> u32;
        fn toc_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_toc(self: &MachO_DynamicSymbolCommand) -> u32;
        fn module_table_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_module_table(self: &MachO_DynamicSymbolCommand) -> u32;
        fn external_reference_symbol_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_external_reference_symbols(self: &MachO_DynamicSymbolCommand) -> u32;
        fn indirect_symbol_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_indirect_symbols(self: &MachO_DynamicSymbolCommand) -> u32;
        fn external_relocation_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_external_relocations(self: &MachO_DynamicSymbolCommand) -> u32;
        fn local_relocation_offset(self: &MachO_DynamicSymbolCommand) -> u32;
        fn nb_local_relocations(self: &MachO_DynamicSymbolCommand) -> u32;
        fn indirect_symbols(
            self: &MachO_DynamicSymbolCommand,
        ) -> UniquePtr<MachO_DynamicSymbolCommand_it_indirect_symbols>;

        type MachO_DynamicSymbolCommand_it_indirect_symbols;

        fn next(
            self: Pin<&mut MachO_DynamicSymbolCommand_it_indirect_symbols>,
        ) -> UniquePtr<MachO_Symbol>;
        fn size(self: &MachO_DynamicSymbolCommand_it_indirect_symbols) -> u64;
    }

    impl UniquePtr<MachO_DynamicSymbolCommand> {}
    impl UniquePtr<MachO_DynamicSymbolCommand_it_indirect_symbols> {}
}
