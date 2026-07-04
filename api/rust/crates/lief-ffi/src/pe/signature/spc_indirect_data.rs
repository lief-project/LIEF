#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/SpcIndirectData.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ContentInfo_Content =
            crate::pe::signature::content_info::ffi::PE_ContentInfo_Content;

        type PE_SpcIndirectData;

        fn digest(self: &PE_SpcIndirectData) -> Span;
        #[Self = "PE_SpcIndirectData"]
        fn classof(info: &PE_ContentInfo_Content) -> bool;
        fn digest_algorithm(self: &PE_SpcIndirectData) -> u32;
        fn file(self: &PE_SpcIndirectData) -> UniquePtr<CxxString>;
        fn url(self: &PE_SpcIndirectData) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_SpcIndirectData> {}
}
