#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/RelocationEntry.hpp");

        type PE_RelocationEntry;

        fn position(self: &PE_RelocationEntry) -> u64;
        fn get_type(self: &PE_RelocationEntry) -> u32;
        fn data(self: &PE_RelocationEntry) -> u16;
    }

    impl UniquePtr<PE_RelocationEntry> {}
}
