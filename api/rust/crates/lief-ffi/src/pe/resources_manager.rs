#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourcesManager.hpp");

        type PE_ResourceAccelerator = crate::pe::resource_accelerator::ffi::PE_ResourceAccelerator;
        type PE_ResourceIcon = crate::pe::resource_icon::ffi::PE_ResourceIcon;
        type PE_ResourceNode = crate::pe::resource_node::ffi::PE_ResourceNode;
        type PE_ResourceVersion = crate::pe::resource_version::ffi::PE_ResourceVersion;

        type PE_ResourcesManager;

        fn get_types(self: &PE_ResourcesManager) -> UniquePtr<CxxVector<u32>>;
        fn has_type(self: &PE_ResourcesManager, type_: u32) -> bool;
        fn manifest(self: &PE_ResourcesManager) -> UniquePtr<CxxString>;
        fn set_manifest(self: Pin<&mut PE_ResourcesManager>, str_: &CxxString);
        fn print_tree(self: &PE_ResourcesManager) -> UniquePtr<CxxString>;
        fn print_tree_with_depth(self: &PE_ResourcesManager, depth: u32) -> UniquePtr<CxxString>;
        fn html(self: &PE_ResourcesManager) -> UniquePtr<CxxVector<CxxString>>;
        fn icons(self: &PE_ResourcesManager) -> UniquePtr<PE_ResourcesManager_it_icons>;
        fn version(self: &PE_ResourcesManager) -> UniquePtr<PE_ResourcesManager_it_version>;
        fn accelerator(self: &PE_ResourcesManager)
            -> UniquePtr<PE_ResourcesManager_it_accelerator>;
        fn string_table(
            self: &PE_ResourcesManager,
        ) -> UniquePtr<PE_ResourcesManager_it_string_table_entry>;
        fn find_node_type(self: &PE_ResourcesManager, type_: u32) -> UniquePtr<PE_ResourceNode>;

        type PE_ResourcesManager_it_accelerator;

        fn next(
            self: Pin<&mut PE_ResourcesManager_it_accelerator>,
        ) -> UniquePtr<PE_ResourceAccelerator>;
        fn size(self: &PE_ResourcesManager_it_accelerator) -> u64;

        type PE_ResourcesManager_it_icons;

        fn next(self: Pin<&mut PE_ResourcesManager_it_icons>) -> UniquePtr<PE_ResourceIcon>;
        fn size(self: &PE_ResourcesManager_it_icons) -> u64;

        type PE_ResourcesManager_it_string_table_entry;

        fn next(
            self: Pin<&mut PE_ResourcesManager_it_string_table_entry>,
        ) -> UniquePtr<PE_ResourcesManager_string_entry_t>;
        fn size(self: &PE_ResourcesManager_it_string_table_entry) -> u64;

        type PE_ResourcesManager_it_version;

        fn next(self: Pin<&mut PE_ResourcesManager_it_version>) -> UniquePtr<PE_ResourceVersion>;
        fn size(self: &PE_ResourcesManager_it_version) -> u64;

        type PE_ResourcesManager_string_entry_t;

        fn string(self: &PE_ResourcesManager_string_entry_t) -> UniquePtr<CxxString>;
        fn id(self: &PE_ResourcesManager_string_entry_t) -> u32;
    }

    impl UniquePtr<PE_ResourcesManager> {}
    impl UniquePtr<PE_ResourcesManager_it_accelerator> {}
    impl UniquePtr<PE_ResourcesManager_it_icons> {}
    impl UniquePtr<PE_ResourcesManager_it_string_table_entry> {}
    impl UniquePtr<PE_ResourcesManager_it_version> {}
    impl UniquePtr<PE_ResourcesManager_string_entry_t> {}
}
