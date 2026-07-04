#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/PKCS9CounterSignature.hpp");

        type PE_SignerInfo = crate::pe::signature::signer_info::ffi::PE_SignerInfo;

        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_PKCS9CounterSignature;
        #[Self = "PE_PKCS9CounterSignature"]
        fn classof(attr: &PE_Attribute) -> bool;

        fn signer(self: &PE_PKCS9CounterSignature) -> UniquePtr<PE_SignerInfo>;
    }
    impl UniquePtr<PE_PKCS9CounterSignature> {}
}
