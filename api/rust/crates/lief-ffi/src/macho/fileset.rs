#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Fileset.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_Fileset;

        #[Self = "MachO_Fileset"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn name(self: &MachO_Fileset) -> UniquePtr<CxxString>;
        fn virtual_address(self: &MachO_Fileset) -> u64;
        fn file_offset(self: &MachO_Fileset) -> u64;
    }
    impl UniquePtr<MachO_Fileset> {}
}
