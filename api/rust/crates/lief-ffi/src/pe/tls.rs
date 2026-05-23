#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/TLS.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_DataDirectory = crate::pe::data_directories::ffi::PE_DataDirectory;
        type PE_Section = crate::pe::section::ffi::PE_Section;

        type PE_TLS;

        fn data_template(self: &PE_TLS) -> Span;
        #[Self = "PE_TLS"]
        fn create() -> UniquePtr<PE_TLS>;
        fn callbacks(self: &PE_TLS) -> UniquePtr<CxxVector<u64>>;
        fn addressof_index(self: &PE_TLS) -> u64;
        fn addressof_callbacks(self: &PE_TLS) -> u64;
        fn sizeof_zero_fill(self: &PE_TLS) -> u32;
        fn characteristics(self: &PE_TLS) -> u32;
        fn addressof_raw_data(self: &PE_TLS) -> UniquePtr<CxxVector<u64>>;
        fn section(self: &PE_TLS) -> UniquePtr<PE_Section>;
        fn data_directory(self: &PE_TLS) -> UniquePtr<PE_DataDirectory>;
        fn add_callback(self: Pin<&mut PE_TLS>, addr: u64);
        fn set_characteristics(self: Pin<&mut PE_TLS>, value: u32);
        fn set_addressof_index(self: Pin<&mut PE_TLS>, value: u64);
        fn set_addressof_callback(self: Pin<&mut PE_TLS>, value: u64);
        fn set_sizeof_zero_fill(self: Pin<&mut PE_TLS>, value: u32);
        unsafe fn set_callbacks(self: Pin<&mut PE_TLS>, ptr: *const u64, size: usize);
        unsafe fn set_data_template(self: Pin<&mut PE_TLS>, ptr: *const u8, size: usize);
    }
    impl UniquePtr<PE_TLS> {}
}
