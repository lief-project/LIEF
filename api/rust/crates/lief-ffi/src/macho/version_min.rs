#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/VersionMin.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_VersionMin;

        #[Self = "MachO_VersionMin"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn version(self: &MachO_VersionMin) -> UniquePtr<CxxVector<u64>>;
        fn sdk(self: &MachO_VersionMin) -> UniquePtr<CxxVector<u64>>;
    }

    impl UniquePtr<MachO_VersionMin> {}
}
