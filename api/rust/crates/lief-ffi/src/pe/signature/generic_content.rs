#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/GenericContent.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ContentInfo_Content =
            crate::pe::signature::content_info::ffi::PE_ContentInfo_Content;

        type PE_GenericContent;

        fn raw(self: &PE_GenericContent) -> Span;
        #[Self = "PE_GenericContent"]
        fn classof(info: &PE_ContentInfo_Content) -> bool;
        fn oid(self: &PE_GenericContent) -> UniquePtr<CxxString>;
    }
    impl UniquePtr<PE_GenericContent> {}
}
