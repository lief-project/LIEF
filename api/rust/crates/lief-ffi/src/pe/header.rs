#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/Header.hpp");

        type PE_Header;

        fn signature(self: &PE_Header) -> UniquePtr<CxxVector<u64>>;
        fn machine(self: &PE_Header) -> u32;
        fn numberof_sections(self: &PE_Header) -> u16;
        fn time_date_stamp(self: &PE_Header) -> u32;
        fn pointerto_symbol_table(self: &PE_Header) -> u32;
        fn numberof_symbols(self: &PE_Header) -> u32;
        fn sizeof_optional_header(self: &PE_Header) -> u16;
        fn characteristics(self: &PE_Header) -> u32;
        fn add_characteristic(self: Pin<&mut PE_Header>, value: u32);
        fn remove_characteristic(self: Pin<&mut PE_Header>, value: u32);
        fn set_machine(self: Pin<&mut PE_Header>, value: u32);
        fn set_numberof_sections(self: Pin<&mut PE_Header>, value: u16);
        fn set_time_date_stamp(self: Pin<&mut PE_Header>, value: u32);
        fn set_pointerto_symbol_table(self: Pin<&mut PE_Header>, value: u32);
        fn set_numberof_symbols(self: Pin<&mut PE_Header>, value: u32);
        fn set_sizeof_optional_header(self: Pin<&mut PE_Header>, value: u16);
        fn set_characteristics(self: Pin<&mut PE_Header>, value: u32);
    }

    impl UniquePtr<PE_Header> {}
}
