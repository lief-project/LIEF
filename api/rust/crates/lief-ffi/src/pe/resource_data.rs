#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceData.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ResourceNode = crate::pe::resource_node::ffi::PE_ResourceNode;

        type PE_ResourceData;

        fn content(self: &PE_ResourceData) -> Span;
        #[Self = "PE_ResourceData"]
        fn create() -> UniquePtr<PE_ResourceData>;
        #[Self = "PE_ResourceData"]
        unsafe fn create_from_data(buffer: *const u8, size: usize) -> UniquePtr<PE_ResourceData>;
        #[Self = "PE_ResourceData"]
        fn classof(node: &PE_ResourceNode) -> bool;
        fn code_page(self: &PE_ResourceData) -> u32;
        fn reserved(self: &PE_ResourceData) -> u32;
        fn offset(self: &PE_ResourceData) -> u32;
        fn set_code_page(self: Pin<&mut PE_ResourceData>, value: u32);
        fn set_reserved(self: Pin<&mut PE_ResourceData>, value: u32);
        unsafe fn set_content(self: Pin<&mut PE_ResourceData>, ptr: *const u8, size: usize);
    }
    impl UniquePtr<PE_ResourceData> {}
}
