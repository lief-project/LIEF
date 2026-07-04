#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Import.hpp");

        type PE_DataDirectory = crate::pe::data_directories::ffi::PE_DataDirectory;
        type PE_ImportEntry = crate::pe::import_entry::ffi::PE_ImportEntry;

        type PE_Import;

        fn forwarder_chain(self: &PE_Import) -> u32;
        fn timedatestamp(self: &PE_Import) -> u32;
        fn import_address_table_rva(self: &PE_Import) -> u32;
        fn import_lookup_table_rva(self: &PE_Import) -> u32;
        fn name(self: &PE_Import) -> UniquePtr<CxxString>;
        fn name_rva(self: &PE_Import) -> u32;
        fn directory(self: &PE_Import) -> UniquePtr<PE_DataDirectory>;
        fn iat_directory(self: &PE_Import) -> UniquePtr<PE_DataDirectory>;
        fn entries(self: &PE_Import) -> UniquePtr<PE_Import_it_entries>;
        fn entry_by_name(self: &PE_Import, name: &CxxString) -> UniquePtr<PE_ImportEntry>;
        fn remove_entry_by_name(self: Pin<&mut PE_Import>, name: &CxxString) -> bool;
        fn add_entry_by_name(
            self: Pin<&mut PE_Import>,
            name: &CxxString,
        ) -> UniquePtr<PE_ImportEntry>;
        fn set_name(self: Pin<&mut PE_Import>, name: &CxxString);
        fn remove_entry_by_ordinal(self: Pin<&mut PE_Import>, ord: u32) -> bool;

        type PE_Import_it_entries;

        fn next(self: Pin<&mut PE_Import_it_entries>) -> UniquePtr<PE_ImportEntry>;
        fn size(self: &PE_Import_it_entries) -> u64;
    }

    impl UniquePtr<PE_Import> {}
    impl UniquePtr<PE_Import_it_entries> {}
}
