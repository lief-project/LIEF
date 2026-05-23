#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/attributes/PKCS9MessageDigest.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_PKCS9MessageDigest;
        fn digest(self: &PE_PKCS9MessageDigest) -> Span;
        #[Self = "PE_PKCS9MessageDigest"]
        fn classof(attr: &PE_Attribute) -> bool;

    }
    impl UniquePtr<PE_PKCS9MessageDigest> {}
}
