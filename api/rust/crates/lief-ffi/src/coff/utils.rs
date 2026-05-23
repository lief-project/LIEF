#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/utils.hpp");

        type COFF_Utils;

        #[Self = "COFF_Utils"]
        fn is_coff(file: &CxxString) -> bool;
    }
}
