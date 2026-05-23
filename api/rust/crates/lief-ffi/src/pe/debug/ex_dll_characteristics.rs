#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/ExDllCharacteristics.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_ExDllCharacteristics;

        #[Self = "PE_ExDllCharacteristics"]
        fn classof(entry: &PE_Debug) -> bool;
        fn characteristics(self: &PE_ExDllCharacteristics) -> u32;
    }
    impl UniquePtr<PE_ExDllCharacteristics> {}
}
