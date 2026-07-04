#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/UnknownCommand.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_UnknownCommand;

        #[Self = "MachO_UnknownCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn original_command(self: &MachO_UnknownCommand) -> u64;
    }
    impl UniquePtr<MachO_UnknownCommand> {}
}
