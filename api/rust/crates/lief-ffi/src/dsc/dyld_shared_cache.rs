#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/DyldSharedCache.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type dsc_Dylib = crate::dsc::dylib::ffi::dsc_Dylib;
        type dsc_MappingInfo = crate::dsc::mapping_info::ffi::dsc_MappingInfo;
        type dsc_SubCache = crate::dsc::sub_cache::ffi::dsc_SubCache;

        type dsc_DyldSharedCache;

        #[Self = "dsc_DyldSharedCache"]
        fn from_path(file: &CxxString, arch: &CxxString) -> UniquePtr<dsc_DyldSharedCache>;
        #[Self = "dsc_DyldSharedCache"]
        unsafe fn from_files(ptr: *const c_char, size: usize) -> UniquePtr<dsc_DyldSharedCache>;
        fn libraries(self: &dsc_DyldSharedCache) -> UniquePtr<dsc_DyldSharedCache_it_libraries>;
        fn mapping_info(
            self: &dsc_DyldSharedCache,
        ) -> UniquePtr<dsc_DyldSharedCache_it_mapping_info>;
        fn subcaches(self: &dsc_DyldSharedCache) -> UniquePtr<dsc_DyldSharedCache_it_subcaches>;
        fn filename(self: &dsc_DyldSharedCache) -> UniquePtr<CxxString>;
        fn version(self: &dsc_DyldSharedCache) -> u32;
        fn filepath(self: &dsc_DyldSharedCache) -> UniquePtr<CxxString>;
        fn load_address(self: &dsc_DyldSharedCache) -> u64;
        fn arch_name(self: &dsc_DyldSharedCache) -> UniquePtr<CxxString>;
        fn platform(self: &dsc_DyldSharedCache) -> u32;
        fn arch(self: &dsc_DyldSharedCache) -> u32;
        fn has_subcaches(self: &dsc_DyldSharedCache) -> bool;
        fn find_lib_from_va(self: &dsc_DyldSharedCache, va: u64) -> UniquePtr<dsc_Dylib>;
        fn find_lib_from_path(self: &dsc_DyldSharedCache, path: &CxxString)
            -> UniquePtr<dsc_Dylib>;
        fn find_lib_from_name(self: &dsc_DyldSharedCache, name: &CxxString)
            -> UniquePtr<dsc_Dylib>;
        fn enable_caching(self: &dsc_DyldSharedCache, dir: &CxxString);
        fn flush_cache(self: &dsc_DyldSharedCache);
        fn disassemble(
            self: &dsc_DyldSharedCache,
            addr: u64,
        ) -> UniquePtr<dsc_DyldSharedCache_it_instructions>;
        fn cache_for_address(
            self: &dsc_DyldSharedCache,
            addr: u64,
        ) -> UniquePtr<dsc_DyldSharedCache>;
        fn main_cache(self: &dsc_DyldSharedCache) -> UniquePtr<dsc_DyldSharedCache>;
        fn find_subcache(
            self: &dsc_DyldSharedCache,
            filename: &CxxString,
        ) -> UniquePtr<dsc_DyldSharedCache>;
        fn va_to_offset(self: &dsc_DyldSharedCache, va: u64, err: Pin<&mut u32>) -> u64;
        fn get_content_from_va(
            self: &dsc_DyldSharedCache,
            va: u64,
            size: u64,
        ) -> UniquePtr<CxxVector<u8>>;

        type dsc_DyldSharedCache_it_instructions;

        fn next(self: Pin<&mut dsc_DyldSharedCache_it_instructions>) -> UniquePtr<asm_Instruction>;

        type dsc_DyldSharedCache_it_libraries;

        fn next(self: Pin<&mut dsc_DyldSharedCache_it_libraries>) -> UniquePtr<dsc_Dylib>;
        fn size(self: &dsc_DyldSharedCache_it_libraries) -> u64;

        type dsc_DyldSharedCache_it_mapping_info;

        fn next(self: Pin<&mut dsc_DyldSharedCache_it_mapping_info>) -> UniquePtr<dsc_MappingInfo>;
        fn size(self: &dsc_DyldSharedCache_it_mapping_info) -> u64;

        type dsc_DyldSharedCache_it_subcaches;

        fn next(self: Pin<&mut dsc_DyldSharedCache_it_subcaches>) -> UniquePtr<dsc_SubCache>;
        fn size(self: &dsc_DyldSharedCache_it_subcaches) -> u64;
    }
    impl UniquePtr<dsc_DyldSharedCache> {}
    impl UniquePtr<dsc_DyldSharedCache_it_instructions> {}
    impl UniquePtr<dsc_DyldSharedCache_it_libraries> {}
    impl UniquePtr<dsc_DyldSharedCache_it_mapping_info> {}
    impl UniquePtr<dsc_DyldSharedCache_it_subcaches> {}
}
