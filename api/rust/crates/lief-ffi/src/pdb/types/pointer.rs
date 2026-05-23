#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Pointer.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Pointer;

        #[Self = "PDB_types_Pointer"]
        fn classof(type_: &PDB_Type) -> bool;
        fn underlying_type(self: &PDB_types_Pointer) -> UniquePtr<PDB_Type>;
    }
    impl UniquePtr<PDB_types_Pointer> {}
}
