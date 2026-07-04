#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Modifier.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Modifier;

        #[Self = "PDB_types_Modifier"]
        fn classof(type_: &PDB_Type) -> bool;
        fn underlying_type(self: &PDB_types_Modifier) -> UniquePtr<PDB_Type>;
    }
    impl UniquePtr<PDB_types_Modifier> {}
}
