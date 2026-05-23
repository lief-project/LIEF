#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/signature/Signature.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ContentInfo = crate::pe::signature::content_info::ffi::PE_ContentInfo;
        type PE_SignerInfo = crate::pe::signature::signer_info::ffi::PE_SignerInfo;
        type PE_x509 = crate::pe::signature::x509::ffi::PE_x509;

        type PE_Signature;

        fn raw_der(self: &PE_Signature) -> Span;
        #[Self = "PE_Signature"]
        fn parse(path: &CxxString) -> UniquePtr<PE_Signature>;
        #[Self = "PE_Signature"]
        unsafe fn from_raw(buffer: *mut u8, size: usize) -> UniquePtr<PE_Signature>;
        fn version(self: &PE_Signature) -> u32;
        fn digest_algorithm(self: &PE_Signature) -> u32;
        fn content_info(self: &PE_Signature) -> UniquePtr<PE_ContentInfo>;
        fn certificates(self: &PE_Signature) -> UniquePtr<PE_Signature_it_certificates>;
        fn signers(self: &PE_Signature) -> UniquePtr<PE_Signature_it_signers>;
        fn find_crt_by_subject(self: &PE_Signature, subject: &CxxString) -> UniquePtr<PE_x509>;
        fn find_crt_by_issuer(self: &PE_Signature, issuer: &CxxString) -> UniquePtr<PE_x509>;
        unsafe fn find_crt_by_serial(
            self: &PE_Signature,
            serial: *const u8,
            size: usize,
        ) -> UniquePtr<PE_x509>;
        unsafe fn find_crt_by_subject_and_serial(
            self: &PE_Signature,
            subject: &CxxString,
            serial: *const u8,
            size: usize,
        ) -> UniquePtr<PE_x509>;
        unsafe fn find_crt_by_issuer_and_serial(
            self: &PE_Signature,
            issuer: &CxxString,
            serial: *const u8,
            size: usize,
        ) -> UniquePtr<PE_x509>;
        fn check(self: &PE_Signature, flags: u32) -> u32;

        type PE_Signature_it_certificates;

        fn next(self: Pin<&mut PE_Signature_it_certificates>) -> UniquePtr<PE_x509>;
        fn size(self: &PE_Signature_it_certificates) -> u64;

        type PE_Signature_it_signers;

        fn next(self: Pin<&mut PE_Signature_it_signers>) -> UniquePtr<PE_SignerInfo>;
        fn size(self: &PE_Signature_it_signers) -> u64;
    }
    impl UniquePtr<PE_Signature> {}
    impl UniquePtr<PE_Signature_it_certificates> {}
    impl UniquePtr<PE_Signature_it_signers> {}
}
