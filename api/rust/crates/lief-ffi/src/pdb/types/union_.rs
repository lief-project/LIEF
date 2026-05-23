#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Union.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Union;

        #[Self = "PDB_types_Union"]
        fn classof(type_: &PDB_Type) -> bool;
    }
    impl UniquePtr<PDB_types_Union> {}
}
