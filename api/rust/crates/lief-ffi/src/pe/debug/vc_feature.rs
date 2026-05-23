#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/VCFeature.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_VCFeature;

        #[Self = "PE_VCFeature"]
        fn classof(entry: &PE_Debug) -> bool;
        fn pre_vcpp(self: &PE_VCFeature) -> u32;
        fn c_cpp(self: &PE_VCFeature) -> u32;
        fn gs(self: &PE_VCFeature) -> u32;
        fn sdl(self: &PE_VCFeature) -> u32;
        fn guards(self: &PE_VCFeature) -> u32;
    }
    impl UniquePtr<PE_VCFeature> {}
}
