#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/ResourceAccelerator.hpp");

        type PE_ResourceAccelerator;

        fn flags(self: &PE_ResourceAccelerator) -> i16;
        fn ansi(self: &PE_ResourceAccelerator) -> i16;
        fn id(self: &PE_ResourceAccelerator) -> u16;
        fn padding(self: &PE_ResourceAccelerator) -> i16;
        fn ansi_str(self: &PE_ResourceAccelerator) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_ResourceAccelerator> {}
}
