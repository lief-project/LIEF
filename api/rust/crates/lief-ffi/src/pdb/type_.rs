#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/Type.hpp");

        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;

        type PDB_Type;

        fn kind(self: &PDB_Type) -> u32;
        fn name(self: &PDB_Type, is_set: Pin<&mut u32>) -> UniquePtr<CxxString>;
        fn size(self: &PDB_Type, is_set: Pin<&mut u32>) -> u64;
        fn to_decl(self: &PDB_Type) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &PDB_Type, opt: &LIEF_DeclOpt) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PDB_Type> {}
}
