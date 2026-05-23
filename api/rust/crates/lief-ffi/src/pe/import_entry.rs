#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ImportEntry.hpp");

        type PE_ImportEntry;

        fn is_ordinal(self: &PE_ImportEntry) -> bool;
        fn ordinal(self: &PE_ImportEntry) -> u16;
        fn hint_name_rva(self: &PE_ImportEntry) -> u64;
        fn hint(self: &PE_ImportEntry) -> u16;
        fn iat_value(self: &PE_ImportEntry) -> u64;
        fn ilt_value(self: &PE_ImportEntry) -> u64;
        fn data(self: &PE_ImportEntry) -> u64;
        fn iat_address(self: &PE_ImportEntry) -> u64;
        fn demangled_name(self: &PE_ImportEntry) -> UniquePtr<CxxString>;
        fn set_iat_value(self: Pin<&mut PE_ImportEntry>, value: u64);
        fn set_ilt_value(self: Pin<&mut PE_ImportEntry>, value: u64);
    }

    impl UniquePtr<PE_ImportEntry> {}
}
