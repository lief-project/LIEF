#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/Debug.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Section = crate::pe::section::ffi::PE_Section;

        type PE_Debug;

        fn payload(self: &PE_Debug) -> Span;

        fn characteristics(self: &PE_Debug) -> u32;
        fn timestamp(self: &PE_Debug) -> u32;
        fn major_version(self: &PE_Debug) -> u16;
        fn minor_version(self: &PE_Debug) -> u16;
        fn get_type(self: &PE_Debug) -> u32;
        fn sizeof_data(self: &PE_Debug) -> u32;
        fn addressof_rawdata(self: &PE_Debug) -> u32;
        fn pointerto_rawdata(self: &PE_Debug) -> u32;
        fn section(self: &PE_Debug) -> UniquePtr<PE_Section>;
        fn set_characteristics(self: Pin<&mut PE_Debug>, value: u32);
        fn set_timestamp(self: Pin<&mut PE_Debug>, value: u32);
        fn set_major_version(self: Pin<&mut PE_Debug>, value: u16);
        fn set_minor_version(self: Pin<&mut PE_Debug>, value: u16);
    }

    impl UniquePtr<PE_Debug> {}
}
