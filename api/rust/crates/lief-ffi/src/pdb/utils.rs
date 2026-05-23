#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/utils.hpp");

        type PDB_Utils;

        #[Self = "PDB_Utils"]
        fn is_pdb(file: &CxxString) -> bool;
    }
}
