#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/utils.hpp");

        type dsc_Utils;

        #[Self = "dsc_Utils"]
        fn is_shared_cache(file: &CxxString) -> bool;
    }
}
