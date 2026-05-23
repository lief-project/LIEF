#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SymbolCommand.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_SymbolCommand;

        fn string_table(self: &MachO_SymbolCommand) -> Span;
        fn symbol_table(self: &MachO_SymbolCommand) -> Span;
        #[Self = "MachO_SymbolCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn symbol_offset(self: &MachO_SymbolCommand) -> u32;
        fn numberof_symbols(self: &MachO_SymbolCommand) -> u32;
        fn strings_offset(self: &MachO_SymbolCommand) -> u32;
        fn strings_size(self: &MachO_SymbolCommand) -> u32;
        fn original_str_size(self: &MachO_SymbolCommand) -> u32;
        fn original_nb_symbols(self: &MachO_SymbolCommand) -> u32;
    }

    impl UniquePtr<MachO_SymbolCommand> {}
}
