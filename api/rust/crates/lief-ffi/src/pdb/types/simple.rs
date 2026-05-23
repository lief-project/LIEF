#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Simple.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Simple;

        #[Self = "PDB_types_Simple"]
        fn classof(type_: &PDB_Type) -> bool;
        fn get_type(self: &PDB_types_Simple) -> u32;
        fn modes(self: &PDB_types_Simple) -> u32;
        fn is_pointer(self: &PDB_types_Simple) -> bool;
        fn is_signed(self: &PDB_types_Simple) -> bool;
    }
    impl UniquePtr<PDB_types_Simple> {}
}
