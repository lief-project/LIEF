#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/SubCache.hpp");
        include!("LIEF/rust/DyldSharedCache/DyldSharedCache.hpp");

        type dsc_DyldSharedCache = crate::dsc::dyld_shared_cache::ffi::dsc_DyldSharedCache;

        type dsc_SubCache;

        fn vm_offset(self: &dsc_SubCache) -> u64;
        fn suffix(self: &dsc_SubCache) -> UniquePtr<CxxString>;
        fn uuid(self: &dsc_SubCache) -> UniquePtr<CxxVector<u64>>;
        fn cache(self: &dsc_SubCache) -> UniquePtr<dsc_DyldSharedCache>;
    }

    impl UniquePtr<dsc_SubCache> {}
}
