#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/SignerInfo.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_x509 = crate::pe::signature::x509::ffi::PE_x509;
        type PE_Attribute = crate::pe::signature::attributes::attribute::ffi::PE_Attribute;

        type PE_SignerInfo;

        fn serial_number(self: &PE_SignerInfo) -> Span;
        fn raw_auth_data(self: &PE_SignerInfo) -> Span;
        fn version(self: &PE_SignerInfo) -> u32;
        fn issuer(self: &PE_SignerInfo) -> UniquePtr<CxxString>;
        fn digest_algorithm(self: &PE_SignerInfo) -> u32;
        fn encryption_algorithm(self: &PE_SignerInfo) -> u32;
        fn encrypted_digest(self: &PE_SignerInfo) -> UniquePtr<CxxVector<u8>>;
        fn cert(self: &PE_SignerInfo) -> UniquePtr<PE_x509>;
        fn get_attribute(self: &PE_SignerInfo, kind: u32) -> UniquePtr<PE_Attribute>;
        fn get_auth_attribute(self: &PE_SignerInfo, kind: u32) -> UniquePtr<PE_Attribute>;
        fn get_unauth_attribute(self: &PE_SignerInfo, kind: u32) -> UniquePtr<PE_Attribute>;
        fn authenticated_attributes(
            self: &PE_SignerInfo,
        ) -> UniquePtr<PE_SignerInfo_it_authenticated_attributes>;
        fn unauthenticated_attributes(
            self: &PE_SignerInfo,
        ) -> UniquePtr<PE_SignerInfo_it_unauthenticated_attributes>;

        type PE_SignerInfo_it_authenticated_attributes;

        fn next(
            self: Pin<&mut PE_SignerInfo_it_authenticated_attributes>,
        ) -> UniquePtr<PE_Attribute>;
        fn size(self: &PE_SignerInfo_it_authenticated_attributes) -> u64;

        type PE_SignerInfo_it_unauthenticated_attributes;

        fn next(
            self: Pin<&mut PE_SignerInfo_it_unauthenticated_attributes>,
        ) -> UniquePtr<PE_Attribute>;
        fn size(self: &PE_SignerInfo_it_unauthenticated_attributes) -> u64;
    }

    impl UniquePtr<PE_SignerInfo> {}
    impl UniquePtr<PE_SignerInfo_it_authenticated_attributes> {}
    impl UniquePtr<PE_SignerInfo_it_unauthenticated_attributes> {}
}
