#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/Dylib.hpp");

        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_Dylib;

        #[Self = "MachO_Dylib"]
        fn id_dylib(
            name: &CxxString,
            timestamp: u32,
            current_version: u32,
            compat_version: u32,
        ) -> UniquePtr<MachO_Dylib>;
        #[Self = "MachO_Dylib"]
        fn load_dylib(
            name: &CxxString,
            timestamp: u32,
            current_version: u32,
            compat_version: u32,
        ) -> UniquePtr<MachO_Dylib>;
        #[Self = "MachO_Dylib"]
        fn reexport_dylib(
            name: &CxxString,
            timestamp: u32,
            current_version: u32,
            compat_version: u32,
        ) -> UniquePtr<MachO_Dylib>;
        #[Self = "MachO_Dylib"]
        fn weak_dylib(
            name: &CxxString,
            timestamp: u32,
            current_version: u32,
            compat_version: u32,
        ) -> UniquePtr<MachO_Dylib>;
        #[Self = "MachO_Dylib"]
        fn lazy_load_dylib(
            name: &CxxString,
            timestamp: u32,
            current_version: u32,
            compat_version: u32,
        ) -> UniquePtr<MachO_Dylib>;
        #[Self = "MachO_Dylib"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn name(self: &MachO_Dylib) -> UniquePtr<CxxString>;
        fn timestamp(self: &MachO_Dylib) -> u32;
        fn name_offset(self: &MachO_Dylib) -> u32;
        fn current_version(self: &MachO_Dylib) -> UniquePtr<CxxVector<u64>>;
        fn compatibility_version(self: &MachO_Dylib) -> UniquePtr<CxxVector<u64>>;
        fn set_name(self: Pin<&mut MachO_Dylib>, name: &CxxString);
    }
    impl UniquePtr<MachO_Dylib> {}
}
