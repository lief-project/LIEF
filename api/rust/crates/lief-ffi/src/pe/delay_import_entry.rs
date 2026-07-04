#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/DelayImportEntry.hpp");

        type PE_DelayImportEntry;

        fn is_ordinal(self: &PE_DelayImportEntry) -> bool;
        fn ordinal(self: &PE_DelayImportEntry) -> u16;
        fn hint_name_rva(self: &PE_DelayImportEntry) -> u64;
        fn hint(self: &PE_DelayImportEntry) -> u16;
        fn iat_value(self: &PE_DelayImportEntry) -> u64;
        fn data(self: &PE_DelayImportEntry) -> u64;
        fn demangled_name(self: &PE_DelayImportEntry) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_DelayImportEntry> {}
}
