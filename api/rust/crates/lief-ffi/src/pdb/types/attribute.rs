#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Attribute.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Attribute;

        fn name(self: &PDB_types_Attribute) -> UniquePtr<CxxString>;
        fn field_offset(self: &PDB_types_Attribute) -> u64;
        fn get_type(self: &PDB_types_Attribute) -> UniquePtr<PDB_Type>;
    }

    impl UniquePtr<PDB_types_Attribute> {}
}
