#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/RPathCommand.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_RPathCommand;

        #[Self = "MachO_RPathCommand"]
        fn create(path: &CxxString) -> UniquePtr<MachO_RPathCommand>;
        #[Self = "MachO_RPathCommand"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn path(self: &MachO_RPathCommand) -> UniquePtr<CxxString>;
        fn path_offset(self: &MachO_RPathCommand) -> u32;
        fn set_path(self: Pin<&mut MachO_RPathCommand>, path: &CxxString);
    }
    impl UniquePtr<MachO_RPathCommand> {}
}
