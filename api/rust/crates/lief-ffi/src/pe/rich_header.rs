#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/RichHeader.hpp");

        type PE_RichEntry = crate::pe::rich_entry::ffi::PE_RichEntry;

        type PE_RichHeader;

        fn key(self: &PE_RichHeader) -> u32;
        fn raw(self: &PE_RichHeader) -> UniquePtr<CxxVector<u8>>;
        fn raw_with_key(self: &PE_RichHeader, xor_key: u32) -> UniquePtr<CxxVector<u8>>;
        fn entries(self: &PE_RichHeader) -> UniquePtr<PE_RichHeader_it_entries>;
        fn set_key(self: Pin<&mut PE_RichHeader>, key: u32);

        type PE_RichHeader_it_entries;

        fn next(self: Pin<&mut PE_RichHeader_it_entries>) -> UniquePtr<PE_RichEntry>;
        fn size(self: &PE_RichHeader_it_entries) -> u64;
    }

    impl UniquePtr<PE_RichHeader> {}
    impl UniquePtr<PE_RichHeader_it_entries> {}
}
