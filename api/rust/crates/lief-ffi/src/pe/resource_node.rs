#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceNode.hpp");

        type PE_ResourceNode;

        #[Self = "PE_ResourceNode"]
        unsafe fn from_slice(
            buffer: *const u8,
            size: usize,
            rva: u64,
        ) -> UniquePtr<PE_ResourceNode>;
        fn has_name(self: &PE_ResourceNode) -> bool;
        fn name(self: &PE_ResourceNode) -> UniquePtr<CxxString>;
        fn id(self: &PE_ResourceNode) -> u32;
        fn depth(self: &PE_ResourceNode) -> u32;
        fn is_directory(self: &PE_ResourceNode) -> bool;
        fn is_data(self: &PE_ResourceNode) -> bool;
        fn childs(self: &PE_ResourceNode) -> UniquePtr<PE_ResourceNode_it_childs>;
        fn add_child(
            self: Pin<&mut PE_ResourceNode>,
            node: &PE_ResourceNode,
        ) -> UniquePtr<PE_ResourceNode>;
        fn delete_child(self: Pin<&mut PE_ResourceNode>, id: u32);
        fn print(self: &PE_ResourceNode) -> UniquePtr<CxxString>;

        type PE_ResourceNode_it_childs;

        fn next(self: Pin<&mut PE_ResourceNode_it_childs>) -> UniquePtr<PE_ResourceNode>;
        fn size(self: &PE_ResourceNode_it_childs) -> u64;
    }
    impl UniquePtr<PE_ResourceNode> {}
    impl UniquePtr<PE_ResourceNode_it_childs> {}
}
