#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/PKCS9TSTInfo.hpp");

        type PE_ContentInfo_Content =
            crate::pe::signature::content_info::ffi::PE_ContentInfo_Content;

        type PE_PKCS9TSTInfo;

        #[Self = "PE_PKCS9TSTInfo"]
        fn classof(info: &PE_ContentInfo_Content) -> bool;
    }
    impl UniquePtr<PE_PKCS9TSTInfo> {}
}
