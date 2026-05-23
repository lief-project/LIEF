#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SourceVersion.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_SourceVersion;

        #[Self = "MachO_SourceVersion"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn version(self: &MachO_SourceVersion) -> UniquePtr<CxxVector<u64>>;
    }

    impl UniquePtr<MachO_SourceVersion> {}
}
