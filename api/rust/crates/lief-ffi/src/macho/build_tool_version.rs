#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/BuildToolVersion.hpp");

        type MachO_BuildToolVersion;

        fn tool(self: &MachO_BuildToolVersion) -> u32;
        fn version(self: &MachO_BuildToolVersion) -> UniquePtr<CxxVector<u64>>;
    }

    impl UniquePtr<MachO_BuildToolVersion> {}
}
