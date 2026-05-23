#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DyldSharedCache/MappingInfo.hpp");

        type dsc_MappingInfo;

        fn address(self: &dsc_MappingInfo) -> u64;
        fn size(self: &dsc_MappingInfo) -> u64;
        fn end_address(self: &dsc_MappingInfo) -> u64;
        fn file_offset(self: &dsc_MappingInfo) -> u64;
        fn max_prot(self: &dsc_MappingInfo) -> u32;
        fn init_prot(self: &dsc_MappingInfo) -> u32;
    }

    impl UniquePtr<dsc_MappingInfo> {}
}
