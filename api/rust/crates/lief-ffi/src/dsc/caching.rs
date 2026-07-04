#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/caching.hpp");

        fn dsc_enable_cache() -> bool;
        fn dsc_enable_cache_from_dir(dir: &CxxString) -> bool;
    }
}
