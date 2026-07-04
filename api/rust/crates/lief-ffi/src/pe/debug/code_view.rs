#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/CodeView.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_CodeView;

        #[Self = "PE_CodeView"]
        fn classof(entry: &PE_Debug) -> bool;
        fn signature(self: &PE_CodeView) -> u32;
    }
    impl UniquePtr<PE_CodeView> {}
}
