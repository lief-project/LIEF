#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/SigningCertificateV2.hpp");

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_SigningCertificateV2;
        #[Self = "PE_SigningCertificateV2"]
        fn classof(attr: &PE_Attribute) -> bool;

    }
    impl UniquePtr<PE_SigningCertificateV2> {}
}
