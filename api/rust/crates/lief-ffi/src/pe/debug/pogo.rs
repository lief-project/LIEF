#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/Pogo.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;
        type PE_PogoEntry = crate::pe::debug::pogo_entry::ffi::PE_PogoEntry;

        type PE_Pogo;

        #[Self = "PE_Pogo"]
        fn classof(entry: &PE_Debug) -> bool;
        fn entries(self: &PE_Pogo) -> UniquePtr<PE_Pogo_it_entries>;
        fn pogo_signature(self: &PE_Pogo) -> u32;

        type PE_Pogo_it_entries;

        fn next(self: Pin<&mut PE_Pogo_it_entries>) -> UniquePtr<PE_PogoEntry>;
        fn size(self: &PE_Pogo_it_entries) -> u64;
    }
    impl UniquePtr<PE_Pogo> {}
    impl UniquePtr<PE_Pogo_it_entries> {}
}
