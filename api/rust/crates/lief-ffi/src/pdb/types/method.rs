#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Method.hpp");

        type PDB_types_Method;

        fn name(self: &PDB_types_Method) -> UniquePtr<CxxString>;
        fn get_type(self: &PDB_types_Method) -> u32;
        fn access(self: &PDB_types_Method) -> u8;
    }

    impl UniquePtr<PDB_types_Method> {}
}
