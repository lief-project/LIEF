#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/UUIDCommand.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_UUIDCommand;

        #[Self = "MachO_UUIDCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn uuid(self: &MachO_UUIDCommand) -> UniquePtr<CxxVector<u64>>;
    }

    impl UniquePtr<MachO_UUIDCommand> {}
}
