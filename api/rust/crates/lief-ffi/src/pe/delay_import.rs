#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/DelayImport.hpp");

        type PE_DelayImportEntry = crate::pe::delay_import_entry::ffi::PE_DelayImportEntry;

        type PE_DelayImport;

        fn attribute(self: &PE_DelayImport) -> u32;
        fn name(self: &PE_DelayImport) -> UniquePtr<CxxString>;
        fn handle(self: &PE_DelayImport) -> u32;
        fn iat(self: &PE_DelayImport) -> u32;
        fn names_table(self: &PE_DelayImport) -> u32;
        fn biat(self: &PE_DelayImport) -> u32;
        fn uiat(self: &PE_DelayImport) -> u32;
        fn timestamp(self: &PE_DelayImport) -> u32;
        fn entries(self: &PE_DelayImport) -> UniquePtr<PE_DelayImport_it_entries>;

        type PE_DelayImport_it_entries;

        fn next(self: Pin<&mut PE_DelayImport_it_entries>) -> UniquePtr<PE_DelayImportEntry>;
        fn size(self: &PE_DelayImport_it_entries) -> u64;
    }

    impl UniquePtr<PE_DelayImport> {}
    impl UniquePtr<PE_DelayImport_it_entries> {}
}
