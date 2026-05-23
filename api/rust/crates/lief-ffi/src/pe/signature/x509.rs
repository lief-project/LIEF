#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/x509.hpp");

        type PE_RsaInfo = crate::pe::signature::rsa_info::ffi::PE_RsaInfo;

        type PE_x509;

        fn version(self: &PE_x509) -> u32;
        fn serial_number(self: &PE_x509) -> UniquePtr<CxxVector<u8>>;
        fn signature_algorithm(self: &PE_x509) -> UniquePtr<CxxString>;
        fn valid_from(self: &PE_x509) -> UniquePtr<CxxVector<u64>>;
        fn valid_to(self: &PE_x509) -> UniquePtr<CxxVector<u64>>;
        fn issuer(self: &PE_x509) -> UniquePtr<CxxString>;
        fn subject(self: &PE_x509) -> UniquePtr<CxxString>;
        fn raw(self: &PE_x509) -> UniquePtr<CxxVector<u8>>;
        fn key_type(self: &PE_x509) -> u32;
        fn is_ca(self: &PE_x509) -> bool;
        fn signature(self: &PE_x509) -> UniquePtr<CxxVector<u8>>;
        fn rsa_info(self: &PE_x509) -> UniquePtr<PE_RsaInfo>;
        fn verify(self: &PE_x509, ca: &PE_x509) -> u32;
        unsafe fn check_signature(
            self: &PE_x509,
            hash: *const u8,
            hsize: usize,
            signature: *const u8,
            sigsiz: usize,
            algo: u32,
        ) -> u32;
        fn key_usage(self: &PE_x509) -> UniquePtr<CxxVector<u32>>;
        fn ext_key_usage(self: &PE_x509) -> UniquePtr<CxxVector<CxxString>>;
        fn certificate_policies(self: &PE_x509) -> UniquePtr<CxxVector<CxxString>>;
    }

    impl UniquePtr<PE_x509> {}
}
