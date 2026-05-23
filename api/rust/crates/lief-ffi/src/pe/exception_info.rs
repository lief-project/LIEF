#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ExceptionInfo.hpp");

        type PE_ExceptionInfo;

        fn rva_start(self: &PE_ExceptionInfo) -> u32;
        fn offset(self: &PE_ExceptionInfo) -> u64;
        fn to_string(self: &PE_ExceptionInfo) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_ExceptionInfo> {}
}
