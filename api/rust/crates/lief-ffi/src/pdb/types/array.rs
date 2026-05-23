#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Array.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Array;

        #[Self = "PDB_types_Array"]
        fn classof(type_: &PDB_Type) -> bool;
        fn numberof_elements(self: &PDB_types_Array) -> u64;
        fn element_type(self: &PDB_types_Array) -> UniquePtr<PDB_Type>;
        fn index_type(self: &PDB_types_Array) -> UniquePtr<PDB_Type>;
    }
    impl UniquePtr<PDB_types_Array> {}
}
