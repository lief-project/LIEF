#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/BitField.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_BitField;

        #[Self = "PDB_types_BitField"]
        fn classof(type_: &PDB_Type) -> bool;
    }
    impl UniquePtr<PDB_types_BitField> {}
}
