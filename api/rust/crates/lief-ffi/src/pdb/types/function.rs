#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Function.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Function;

        #[Self = "PDB_types_Function"]
        fn classof(type_: &PDB_Type) -> bool;
        fn return_type(self: &PDB_types_Function) -> UniquePtr<PDB_Type>;
        fn parameters(self: &PDB_types_Function) -> UniquePtr<PDB_types_Function_it_parameters>;

        type PDB_types_Function_it_parameters;

        fn next(self: Pin<&mut PDB_types_Function_it_parameters>) -> UniquePtr<PDB_Type>;
        fn size(self: &PDB_types_Function_it_parameters) -> u64;
    }
    impl UniquePtr<PDB_types_Function> {}
    impl UniquePtr<PDB_types_Function_it_parameters> {}
}
