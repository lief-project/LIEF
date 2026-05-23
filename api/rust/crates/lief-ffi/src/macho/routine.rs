#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Routine.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_Routine;

        #[Self = "MachO_Routine"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn init_address(self: &MachO_Routine) -> u64;
        fn init_module(self: &MachO_Routine) -> u64;
        fn reserved1(self: &MachO_Routine) -> u64;
        fn reserved2(self: &MachO_Routine) -> u64;
        fn reserved3(self: &MachO_Routine) -> u64;
        fn reserved4(self: &MachO_Routine) -> u64;
        fn reserved5(self: &MachO_Routine) -> u64;
        fn reserved6(self: &MachO_Routine) -> u64;
    }

    impl UniquePtr<MachO_Routine> {}
}
