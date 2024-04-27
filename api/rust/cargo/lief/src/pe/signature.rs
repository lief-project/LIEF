use bitflags::bitflags;
use lief_ffi as ffi;

pub mod attributes;
pub mod content_info;
pub mod rsa_info;
pub mod signer_info;
pub mod x509;

pub use content_info::ContentInfo;
pub use rsa_info::RsaInfo;
pub use signer_info::{SignerInfo, Signers};
pub use x509::{Certificates, X509};

use crate::common::FromFFI;
use crate::declare_iterator;

use std::marker::PhantomData;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VerificationFlags: u32 {
        const OK = 0;
        const INVALID_SIGNER = 1 << 0;
        const UNSUPPORTED_ALGORITHM = 1 << 1;
        const INCONSISTENT_DIGEST_ALGORITHM = 1 << 2;
        const CERT_NOT_FOUND = 1 << 3;
        const CORRUPTED_CONTENT_INFO = 1 << 4;
        const CORRUPTED_AUTH_DATA = 1 << 5;
        const MISSING_PKCS9_MESSAGE_DIGEST = 1 << 6;
        const BAD_DIGEST = 1 << 7;
        const BAD_SIGNATURE = 1 << 8;
        const NO_SIGNATURE = 1 << 9;
        const CERT_EXPIRED = 1 << 10;
        const CERT_FUTURE = 1 << 11;
    }
}

impl VerificationFlags {
    pub fn from_value(value: u32) -> Self {
        VerificationFlags::from_bits_truncate(value)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VerificationChecks: u32 {
        const DEFAULT = 1 << 0;
        const HASH_ONLY = 1 << 1;
        const LIFETIME_SIGNING = 1 << 2;
        const SKIP_CERT_TIME = 1 << 3;
    }
}

pub struct Signature<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Signature>,
    _owner: PhantomData<&'a ()>,
}

impl std::fmt::Debug for Signature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature").finish()
    }
}

impl FromFFI<ffi::PE_Signature> for Signature<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Signature>) -> Self {
        Signature {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> Signature<'a> {
    pub fn from_file(path: &str) -> Option<Self> {
        let ffi = ffi::PE_Signature::parse(path);
        if ffi.is_null() {
            return None;
        }
        Some(Signature::from_ffi(ffi))
    }
    pub fn content_info(&'a self) -> ContentInfo<'a> {
        ContentInfo::from_ffi(self.ptr.content_info())
    }

    pub fn certificates(&'a self) -> Certificates<'a> {
        Certificates::new(self.ptr.certificates())
    }

    pub fn signers(&'a self) -> Signers<'a> {
        Signers::new(self.ptr.signers())
    }
}

declare_iterator!(
    Signatures,
    Signature<'a>,
    ffi::PE_Signature,
    ffi::PE_Binary,
    ffi::PE_Binary_it_signatures
);
