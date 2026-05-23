#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/BuildMetadata.hpp");

        type PDB_BuildMetadata;

        fn frontend_version(self: &PDB_BuildMetadata) -> UniquePtr<CxxVector<u16>>;
        fn backend_version(self: &PDB_BuildMetadata) -> UniquePtr<CxxVector<u16>>;
        fn version(self: &PDB_BuildMetadata) -> UniquePtr<CxxString>;
        fn language(self: &PDB_BuildMetadata) -> u8;
        fn target_cpu(self: &PDB_BuildMetadata) -> u16;
        fn env(self: &PDB_BuildMetadata) -> UniquePtr<CxxVector<CxxString>>;
        fn build_info(self: &PDB_BuildMetadata) -> UniquePtr<CxxVector<CxxString>>;
        fn to_string(self: &PDB_BuildMetadata) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PDB_BuildMetadata> {}
}
