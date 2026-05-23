#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/RichEntry.hpp");

        type PE_RichEntry;

        fn id(self: &PE_RichEntry) -> u16;
        fn build_id(self: &PE_RichEntry) -> u16;
        fn count(self: &PE_RichEntry) -> u32;
    }

    impl UniquePtr<PE_RichEntry> {}
}
