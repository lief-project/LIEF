#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SubFramework.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_SubFramework;

        #[Self = "MachO_SubFramework"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn umbrella(self: &MachO_SubFramework) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<MachO_SubFramework> {}
}
