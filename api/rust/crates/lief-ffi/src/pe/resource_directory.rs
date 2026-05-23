#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceDirectory.hpp");

        type PE_ResourceNode = crate::pe::resource_node::ffi::PE_ResourceNode;

        type PE_ResourceDirectory;

        #[Self = "PE_ResourceDirectory"]
        fn create_from_id(id: u32) -> UniquePtr<PE_ResourceDirectory>;
        #[Self = "PE_ResourceDirectory"]
        fn create() -> UniquePtr<PE_ResourceDirectory>;
        #[Self = "PE_ResourceDirectory"]
        fn classof(node: &PE_ResourceNode) -> bool;
        fn characteristics(self: &PE_ResourceDirectory) -> u32;
        fn time_date_stamp(self: &PE_ResourceDirectory) -> u32;
        fn major_version(self: &PE_ResourceDirectory) -> u32;
        fn minor_version(self: &PE_ResourceDirectory) -> u32;
        fn numberof_name_entries(self: &PE_ResourceDirectory) -> u32;
        fn numberof_id_entries(self: &PE_ResourceDirectory) -> u32;
    }
    impl UniquePtr<PE_ResourceDirectory> {}
}
