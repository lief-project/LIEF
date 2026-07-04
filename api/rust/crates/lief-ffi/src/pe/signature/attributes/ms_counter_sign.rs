#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/MsCounterSign.hpp");

        type PE_ContentInfo = crate::pe::signature::content_info::ffi::PE_ContentInfo;
        type PE_SignerInfo = crate::pe::signature::signer_info::ffi::PE_SignerInfo;
        type PE_x509 = crate::pe::signature::x509::ffi::PE_x509;

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_MsCounterSign;
        #[Self = "PE_MsCounterSign"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn version(self: &PE_MsCounterSign) -> u32;
        fn digest_algorithm(self: &PE_MsCounterSign) -> u32;
        fn content_info(self: &PE_MsCounterSign) -> UniquePtr<PE_ContentInfo>;
        fn certificates(self: &PE_MsCounterSign) -> UniquePtr<PE_MsCounterSign_it_certificates>;
        fn signers(self: &PE_MsCounterSign) -> UniquePtr<PE_MsCounterSign_it_signers>;

        type PE_MsCounterSign_it_certificates;

        fn next(self: Pin<&mut PE_MsCounterSign_it_certificates>) -> UniquePtr<PE_x509>;
        fn size(self: &PE_MsCounterSign_it_certificates) -> u64;

        type PE_MsCounterSign_it_signers;

        fn next(self: Pin<&mut PE_MsCounterSign_it_signers>) -> UniquePtr<PE_SignerInfo>;
        fn size(self: &PE_MsCounterSign_it_signers) -> u64;
    }
    impl UniquePtr<PE_MsCounterSign> {}
    impl UniquePtr<PE_MsCounterSign_it_certificates> {}
    impl UniquePtr<PE_MsCounterSign_it_signers> {}
}
