//! This module wraps the PKCS #7 PE authenticode signature

use bitflags::bitflags;
use lief_ffi as ffi;

pub mod attributes;
pub mod content_info;
pub mod rsa_info;
pub mod signer_info;
pub mod x509;

#[doc(inline)]
pub use content_info::ContentInfo;
#[doc(inline)]
pub use rsa_info::RsaInfo;
#[doc(inline)]
pub use signer_info::{SignerInfo, Signers};
#[doc(inline)]
pub use x509::{Certificates, X509};

use std::io::{Read, Seek};

use crate::pe::Algorithms;
use crate::common::into_optional;
use crate::common::FromFFI;
use crate::declare_iterator;
use crate::to_slice;

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

impl std::fmt::Display for VerificationFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl From<u32> for VerificationFlags {
    fn from(value: u32) -> Self {
        VerificationFlags::from_bits_truncate(value)
    }
}

impl From<VerificationFlags> for u32 {
    fn from(value: VerificationFlags) -> Self {
        value.bits()
    }
}

impl VerificationFlags {
    pub fn is_ok(self) -> bool {
        self == VerificationFlags::OK
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    /// Flags to tweak the verification process of the signature
    ///
    /// See [`Signature::check`] and [`crate::pe::Binary::verify_signature`]
    pub struct VerificationChecks: u32 {
        /// Default behavior that tries to follow the Microsoft verification process as close as
        /// possible
        const DEFAULT = 1 << 0;

        /// Only check that [`crate::pe::Binary::authentihash`] matches
        /// [`ContentInfo::digest`] regardless of the signature's validity
        const HASH_ONLY = 1 << 1;

        /// Same semantic as
        /// [WTD_LIFETIME_SIGNING_FLAG](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data#WTD_LIFETIME_SIGNING_FLAG)
        const LIFETIME_SIGNING = 1 << 2;

        /// Skip the verification of the certificates time validities so that even though a
        /// certificate expired, it returns [`VerificationFlags::OK`]
        const SKIP_CERT_TIME = 1 << 3;
    }
}

impl From<u32> for VerificationChecks {
    fn from(value: u32) -> Self {
        VerificationChecks::from_bits_truncate(value)
    }
}

impl From<VerificationChecks> for u32 {
    fn from(value: VerificationChecks) -> Self {
        value.bits()
    }
}


pub struct Signature<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Signature>,
    _owner: PhantomData<&'a ()>,
}

impl<'b, 'a: 'b> From<&'a Signature<'_>> for &'b ffi::PE_Signature {
    fn from(value: &'a Signature<'_>) -> &'b ffi::PE_Signature {
        value.ptr.as_ref().unwrap()
    }
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
    /// Create a Signature from a PKCS#7 file path
    pub fn from_file(path: &str) -> Option<Self> {
        let ffi = ffi::PE_Signature::parse(path);
        if ffi.is_null() {
            return None;
        }
        Some(Signature::from_ffi(ffi))
    }

    /// Create a Signature from a PKCS#7 *reader* implementing the `Read + Seek` traits
    pub fn from<R: Read + Seek>(reader: &mut R) -> Option<Self> {
        let mut buffer = std::vec::Vec::new();
        if reader.read_to_end(&mut buffer).is_err() {
            return None;
        }
        let ffi_stream =
            unsafe { ffi::PE_Signature::from_raw(buffer.as_mut_ptr(), buffer.len()) };
        Some(Signature::from_ffi(ffi_stream))
    }

    /// Should be 1
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    /// Algorithm used to *digest* the file.
    ///
    /// It should match [`SignerInfo::digest_algorithm`]
    pub fn digest_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.digest_algorithm())
    }

    /// ContentInfo as described in the RFC2315 <https://tools.ietf.org/html/rfc2315#section-7>
    pub fn content_info(&'a self) -> ContentInfo<'a> {
        ContentInfo::from_ffi(self.ptr.content_info())
    }

    /// Return list of [`X509`] certificates associated with this signature
    pub fn certificates(&'a self) -> Certificates<'a> {
        Certificates::new(self.ptr.certificates())
    }

    /// Iterator over the signer [`SignerInfo`] defined in the PKCS #7 signature
    pub fn signers(&'a self) -> Signers<'a> {
        Signers::new(self.ptr.signers())
    }

    /// The original raw signature as a slice of bytes
    pub fn raw_der(&'a self) -> &[u8] {
        to_slice!(self.ptr.raw_der());
    }

    /// Find x509 certificate according to its serial number
    pub fn crt_by_serial(&self, serial: &[u8]) -> Option<X509> {
        unsafe {
            into_optional(self.ptr.find_crt_by_serial(serial.as_ptr(), serial.len()))
        }
    }

    /// Find [`X509`] certificate according to its subject
    pub fn crt_by_subject(&self, subject: &str) -> Option<X509> {
        into_optional(self.ptr.find_crt_by_subject(subject))
    }

    /// Find [`X509`] certificate according to its subject **AND** serial number
    pub fn crt_by_subject_and_serial(&self, subject: &str, serial: &[u8]) -> Option<X509> {
        unsafe {
            into_optional(self.ptr.find_crt_by_subject_and_serial(subject, serial.as_ptr(), serial.len()))
        }
    }

    /// Find [`X509`] certificate according to its issuer
    pub fn crt_by_issuer(&self, issuer: &str) -> Option<X509> {
        into_optional(self.ptr.find_crt_by_issuer(issuer))
    }

    /// Find [`X509`] certificate according to its issuer **AND** serial number
    pub fn find_crt_by_issuer_and_serial(&self, issuer: &str, serial: &[u8]) -> Option<X509> {
        unsafe {
            into_optional(self.ptr.find_crt_by_issuer_and_serial(issuer, serial.as_ptr(), serial.len()))
        }
    }

    /// Check if this signature is valid according to the Authenticode/PKCS #7 verification scheme
    ///
    /// By default, it performs the following verifications:
    ///
    /// 1. It must contain only **one** signer info
    /// 2. [`Signature::digest_algorithm`] must match:
    ///    * [`ContentInfo::digest_algorithm`]
    ///    * [`SignerInfo::digest_algorithm`]
    /// 3. The x509 certificate specified by [`SignerInfo::serial_number`] **and** [`SignerInfo::issuer`]
    ///    must exist within [`Signature::certificates`]
    /// 4. Given the x509 certificate, compare [`SignerInfo::encrypted_digest`] against either:
    ///    * hash of authenticated attributes if present
    ///    * hash of ContentInfo
    /// 5. If authenticated attributes are present, check that a `PKCS9_MESSAGE_DIGEST` attribute exists
    ///    and that its value matches hash of ContentInfo
    /// 6. Check the validity of the PKCS #9 counter signature if present
    /// 7. If the signature doesn't embed a signing-time in the counter signature, check the certificate
    ///    validity.
    ///    (See [`VerificationChecks::LIFETIME_SIGNING`] and [`VerificationChecks::SKIP_CERT_TIME`])
    ///
    /// See: [`VerificationChecks`] to tweak the behavior
    pub fn check(&self, checks: VerificationChecks) -> VerificationFlags {
        VerificationFlags::from(self.ptr.check(checks.into()))
    }
}

declare_iterator!(
    Signatures,
    Signature<'a>,
    ffi::PE_Signature,
    ffi::PE_Binary,
    ffi::PE_Binary_it_signatures
);
