#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Main.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_Main;

        #[Self = "MachO_Main"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn entrypoint(self: &MachO_Main) -> u64;
        fn stack_size(self: &MachO_Main) -> u64;
    }

    impl UniquePtr<MachO_Main> {}
}
