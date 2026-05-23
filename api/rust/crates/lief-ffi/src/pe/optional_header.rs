#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/OptionalHeader.hpp");

        type PE_OptionalHeader;

        fn magic(self: &PE_OptionalHeader) -> u16;
        fn major_linker_version(self: &PE_OptionalHeader) -> u8;
        fn minor_linker_version(self: &PE_OptionalHeader) -> u8;
        fn sizeof_code(self: &PE_OptionalHeader) -> u32;
        fn sizeof_initialized_data(self: &PE_OptionalHeader) -> u32;
        fn sizeof_uninitialized_data(self: &PE_OptionalHeader) -> u32;
        fn addressof_entrypoint(self: &PE_OptionalHeader) -> u32;
        fn baseof_code(self: &PE_OptionalHeader) -> u32;
        fn baseof_data(self: &PE_OptionalHeader) -> u32;
        fn imagebase(self: &PE_OptionalHeader) -> u64;
        fn section_alignment(self: &PE_OptionalHeader) -> u32;
        fn file_alignment(self: &PE_OptionalHeader) -> u32;
        fn major_operating_system_version(self: &PE_OptionalHeader) -> u16;
        fn minor_operating_system_version(self: &PE_OptionalHeader) -> u16;
        fn major_image_version(self: &PE_OptionalHeader) -> u16;
        fn minor_image_version(self: &PE_OptionalHeader) -> u16;
        fn major_subsystem_version(self: &PE_OptionalHeader) -> u16;
        fn minor_subsystem_version(self: &PE_OptionalHeader) -> u16;
        fn win32_version_value(self: &PE_OptionalHeader) -> u32;
        fn sizeof_image(self: &PE_OptionalHeader) -> u32;
        fn sizeof_headers(self: &PE_OptionalHeader) -> u32;
        fn checksum(self: &PE_OptionalHeader) -> u32;
        fn subsystem(self: &PE_OptionalHeader) -> u64;
        fn dll_characteristics(self: &PE_OptionalHeader) -> u32;
        fn sizeof_stack_reserve(self: &PE_OptionalHeader) -> u64;
        fn sizeof_stack_commit(self: &PE_OptionalHeader) -> u64;
        fn sizeof_heap_reserve(self: &PE_OptionalHeader) -> u64;
        fn sizeof_heap_commit(self: &PE_OptionalHeader) -> u64;
        fn loader_flags(self: &PE_OptionalHeader) -> u32;
        fn numberof_rva_and_size(self: &PE_OptionalHeader) -> u32;
        fn set_addressof_entrypoint(self: Pin<&mut PE_OptionalHeader>, value: u32);
        fn set_imagebase(self: Pin<&mut PE_OptionalHeader>, value: u64);
        fn add_dll_characteristic(self: Pin<&mut PE_OptionalHeader>, value: u32);
        fn remove_dll_characteristic(self: Pin<&mut PE_OptionalHeader>, value: u32);
    }

    impl UniquePtr<PE_OptionalHeader> {}
}
