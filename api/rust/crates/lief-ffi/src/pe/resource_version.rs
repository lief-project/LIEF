#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceVersion.hpp");

        type PE_ResourceStringFileInfo;

        fn get_type(self: &PE_ResourceStringFileInfo) -> u16;
        fn key(self: &PE_ResourceStringFileInfo) -> UniquePtr<CxxString>;
        fn children(
            self: &PE_ResourceStringFileInfo,
        ) -> UniquePtr<PE_ResourceStringFileInfo_it_children>;

        type PE_ResourceStringFileInfo_it_children;

        fn next(
            self: Pin<&mut PE_ResourceStringFileInfo_it_children>,
        ) -> UniquePtr<PE_ResourceStringTable>;
        fn size(self: &PE_ResourceStringFileInfo_it_children) -> u64;

        type PE_ResourceStringTable;

        fn get_type(self: &PE_ResourceStringTable) -> u16;
        fn key(self: &PE_ResourceStringTable) -> UniquePtr<CxxString>;
        fn entries(self: &PE_ResourceStringTable) -> UniquePtr<PE_ResourceStringTable_it_entries>;

        type PE_ResourceStringTable_entry_t;

        fn key(self: &PE_ResourceStringTable_entry_t) -> UniquePtr<CxxString>;
        fn value(self: &PE_ResourceStringTable_entry_t) -> UniquePtr<CxxString>;

        type PE_ResourceStringTable_it_entries;

        fn next(
            self: Pin<&mut PE_ResourceStringTable_it_entries>,
        ) -> UniquePtr<PE_ResourceStringTable_entry_t>;
        fn size(self: &PE_ResourceStringTable_it_entries) -> u64;

        type PE_ResourceVar;

        fn get_type(self: &PE_ResourceVar) -> u16;
        fn key(self: &PE_ResourceVar) -> UniquePtr<CxxString>;
        fn values(self: &PE_ResourceVar) -> UniquePtr<CxxVector<u64>>;

        type PE_ResourceVarFileInfo;

        fn get_type(self: &PE_ResourceVarFileInfo) -> u16;
        fn key(self: &PE_ResourceVarFileInfo) -> UniquePtr<CxxString>;
        fn vars(self: &PE_ResourceVarFileInfo) -> UniquePtr<PE_ResourceVarFileInfo_it_vars>;

        type PE_ResourceVarFileInfo_it_vars;

        fn next(self: Pin<&mut PE_ResourceVarFileInfo_it_vars>) -> UniquePtr<PE_ResourceVar>;
        fn size(self: &PE_ResourceVarFileInfo_it_vars) -> u64;

        type PE_ResourceVersion;

        fn get_type(self: &PE_ResourceVersion) -> u16;
        fn key(self: &PE_ResourceVersion) -> UniquePtr<CxxString>;
        fn string_file_info(self: &PE_ResourceVersion) -> UniquePtr<PE_ResourceStringFileInfo>;
        fn var_file_info(self: &PE_ResourceVersion) -> UniquePtr<PE_ResourceVarFileInfo>;
        fn file_info_signature(self: &PE_ResourceVersion) -> u32;
        fn file_info_struct_version(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_version_ms(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_version_ls(self: &PE_ResourceVersion) -> u32;
        fn file_info_product_version_ms(self: &PE_ResourceVersion) -> u32;
        fn file_info_product_version_ls(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_flags_mask(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_flags(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_os(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_type(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_subtype(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_date_ms(self: &PE_ResourceVersion) -> u32;
        fn file_info_file_date_ls(self: &PE_ResourceVersion) -> u32;
    }

    impl UniquePtr<PE_ResourceVersion> {}
    impl UniquePtr<PE_ResourceStringFileInfo> {}
    impl UniquePtr<PE_ResourceStringFileInfo_it_children> {}
    impl UniquePtr<PE_ResourceStringTable> {}
    impl UniquePtr<PE_ResourceStringTable_entry_t> {}
    impl UniquePtr<PE_ResourceStringTable_it_entries> {}
    impl UniquePtr<PE_ResourceVar> {}
    impl UniquePtr<PE_ResourceVarFileInfo> {}
    impl UniquePtr<PE_ResourceVarFileInfo_it_vars> {}
}
