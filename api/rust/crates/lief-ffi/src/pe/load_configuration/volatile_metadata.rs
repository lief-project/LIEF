#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/VolatileMetadata.hpp");

        type PE_VolatileMetadata;

        fn size(self: &PE_VolatileMetadata) -> u32;
        fn min_version(self: &PE_VolatileMetadata) -> u16;
        fn max_version(self: &PE_VolatileMetadata) -> u16;
        fn access_table_rva(self: &PE_VolatileMetadata) -> u32;
        fn access_table_size(self: &PE_VolatileMetadata) -> u32;
        fn info_range_rva(self: &PE_VolatileMetadata) -> u32;
        fn info_ranges_size(self: &PE_VolatileMetadata) -> u32;
        fn access_table(self: &PE_VolatileMetadata) -> &CxxVector<u32>;
        fn info_ranges(self: &PE_VolatileMetadata) -> UniquePtr<PE_VolatileMetadata_it_ranges>;
        fn to_string(self: &PE_VolatileMetadata) -> UniquePtr<CxxString>;

        type PE_VolatileMetadata_it_ranges;

        fn next(
            self: Pin<&mut PE_VolatileMetadata_it_ranges>,
        ) -> UniquePtr<PE_VolatileMetadata_range_t>;
        fn size(self: &PE_VolatileMetadata_it_ranges) -> u64;

        type PE_VolatileMetadata_range_t;

        fn start(self: &PE_VolatileMetadata_range_t) -> u32;
        fn size(self: &PE_VolatileMetadata_range_t) -> u32;
        fn end(self: &PE_VolatileMetadata_range_t) -> u32;
    }

    impl UniquePtr<PE_VolatileMetadata> {}
    impl UniquePtr<PE_VolatileMetadata_it_ranges> {}
    impl UniquePtr<PE_VolatileMetadata_range_t> {}
}
