#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/PogoEntry.hpp");

        type PE_PogoEntry;

        fn start_rva(self: &PE_PogoEntry) -> u32;
        fn size(self: &PE_PogoEntry) -> u32;
        fn name(self: &PE_PogoEntry) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_PogoEntry> {}
}
