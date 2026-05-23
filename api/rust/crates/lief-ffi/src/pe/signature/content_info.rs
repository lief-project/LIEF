#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/ContentInfo.hpp");

        type PE_ContentInfo;

        fn content_type(self: &PE_ContentInfo) -> UniquePtr<CxxString>;
        fn value(self: &PE_ContentInfo) -> UniquePtr<PE_ContentInfo_Content>;
        fn digest_algorithm(self: &PE_ContentInfo) -> u32;
        fn digest(self: &PE_ContentInfo) -> UniquePtr<CxxVector<u8>>;

        type PE_ContentInfo_Content;

        fn content_type(self: &PE_ContentInfo_Content) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_ContentInfo> {}
    impl UniquePtr<PE_ContentInfo_Content> {}
}
