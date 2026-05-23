#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Export.hpp");

        type PE_ExportEntry = crate::pe::export_entry::ffi::PE_ExportEntry;

        type PE_Export;

        #[Self = "PE_Export"]
        fn create() -> UniquePtr<PE_Export>;
        fn export_flags(self: &PE_Export) -> u32;
        fn timestamp(self: &PE_Export) -> u32;
        fn major_version(self: &PE_Export) -> u16;
        fn minor_version(self: &PE_Export) -> u16;
        fn ordinal_base(self: &PE_Export) -> u32;
        fn name_rva(self: &PE_Export) -> u32;
        fn export_addr_table_rva(self: &PE_Export) -> u32;
        fn export_addr_table_cnt(self: &PE_Export) -> u32;
        fn names_addr_table_rva(self: &PE_Export) -> u32;
        fn names_addr_table_cnt(self: &PE_Export) -> u32;
        fn ord_addr_table_rva(self: &PE_Export) -> u32;
        fn name(self: &PE_Export) -> UniquePtr<CxxString>;
        fn entries(self: &PE_Export) -> UniquePtr<PE_Export_it_entries>;
        fn set_name(self: Pin<&mut PE_Export>, name: &CxxString);
        fn entry_by_name(self: &PE_Export, name: &CxxString) -> UniquePtr<PE_ExportEntry>;
        fn add_entry(
            self: Pin<&mut PE_Export>,
            entry: &PE_ExportEntry,
        ) -> UniquePtr<PE_ExportEntry>;
        fn add_entry_by_name(
            self: Pin<&mut PE_Export>,
            name: &CxxString,
            rva: u32,
        ) -> UniquePtr<PE_ExportEntry>;
        fn remove_entry(self: Pin<&mut PE_Export>, entry: UniquePtr<PE_ExportEntry>) -> bool;
        fn remove_entry_by_name(self: Pin<&mut PE_Export>, name: &CxxString) -> bool;
        fn set_export_flags(self: Pin<&mut PE_Export>, flags: u32);
        fn set_timestamp(self: Pin<&mut PE_Export>, ts: u32);
        fn set_major_version(self: Pin<&mut PE_Export>, version: u32);
        fn set_minor_version(self: Pin<&mut PE_Export>, version: u32);
        fn entry_by_ordinal(self: &PE_Export, ord: u32) -> UniquePtr<PE_ExportEntry>;
        fn entry_at_rva(self: &PE_Export, rva: u32) -> UniquePtr<PE_ExportEntry>;
        fn remove_entry_at(self: Pin<&mut PE_Export>, rva: u32) -> bool;

        type PE_Export_it_entries;

        fn next(self: Pin<&mut PE_Export_it_entries>) -> UniquePtr<PE_ExportEntry>;
        fn size(self: &PE_Export_it_entries) -> u64;
    }
    impl UniquePtr<PE_Export> {}
    impl UniquePtr<PE_Export_it_entries> {}
}
