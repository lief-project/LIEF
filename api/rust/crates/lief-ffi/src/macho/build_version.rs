#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/BuildVersion.hpp");

        type MachO_BuildToolVersion = crate::macho::build_tool_version::ffi::MachO_BuildToolVersion;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_BuildVersion;

        #[Self = "MachO_BuildVersion"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn sdk(self: &MachO_BuildVersion) -> UniquePtr<CxxVector<u64>>;
        fn minos(self: &MachO_BuildVersion) -> UniquePtr<CxxVector<u64>>;
        fn platform(self: &MachO_BuildVersion) -> u32;
        fn tools(self: &MachO_BuildVersion) -> UniquePtr<MachO_BuildVersion_it_tools>;

        type MachO_BuildVersion_it_tools;

        fn next(self: Pin<&mut MachO_BuildVersion_it_tools>) -> UniquePtr<MachO_BuildToolVersion>;
        fn size(self: &MachO_BuildVersion_it_tools) -> u64;
    }

    impl UniquePtr<MachO_BuildVersion> {}
    impl UniquePtr<MachO_BuildVersion_it_tools> {}
}
