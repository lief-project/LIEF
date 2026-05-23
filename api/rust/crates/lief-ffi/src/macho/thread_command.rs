#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/ThreadCommand.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_ThreadCommand;

        fn state(self: &MachO_ThreadCommand) -> Span;
        #[Self = "MachO_ThreadCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn flavor(self: &MachO_ThreadCommand) -> u32;
        fn count(self: &MachO_ThreadCommand) -> u32;
        fn architecture(self: &MachO_ThreadCommand) -> i32;
        fn pc(self: &MachO_ThreadCommand) -> u64;
    }

    impl UniquePtr<MachO_ThreadCommand> {}
}
