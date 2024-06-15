use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::pe::Algorithms;

use super::{RsaInfo, VerificationFlags};

/// Structure for a x509 certificate
pub struct X509<'a> {
    ptr: cxx::UniquePtr<ffi::PE_x509>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x509")
            .field("version", &self.version())
            .field("signature_algorithm", &self.signature_algorithm())
            .field("valid_from", &self.valid_from())
            .field("valid_to", &self.valid_to())
            .field("issuer", &self.issuer())
            .field("key_type", &self.key_type())
            .field("subject", &self.subject())
            .field("is_ca", &self.is_ca())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_x509> for X509<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_x509>) -> Self {
        X509 {
            ptr,
            _owner: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Public key scheme
pub enum KeyType {
    /// Unknown scheme
    NONE,

    /// RSA Scheme
    RSA,

    /// Elliptic-curve scheme
    ECKEY,

    /// Elliptic-curve Diffie-Hellman
    ECKEY_DH,

    /// Elliptic-curve Digital Signature Algorithm
    ECDSA,

    /// RSA scheme with an alternative implementation for signing and decrypting
    RSA_ALT,

    /// RSA Probabilistic signature scheme
    RSASSA_PSS,
    UNKNOWN(u32),
}

impl From<u32> for KeyType {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => KeyType::NONE,
            0x00000001 => KeyType::RSA,
            0x00000002 => KeyType::ECKEY,
            0x00000003 => KeyType::ECKEY_DH,
            0x00000004 => KeyType::ECDSA,
            0x00000005 => KeyType::RSA_ALT,
            0x00000006 => KeyType::RSASSA_PSS,
            _ => KeyType::UNKNOWN(value),
        }
    }
}

impl X509<'_> {
    /// X.509 version. (1=v1, 2=v2, 3=v3)
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    /// Unique id for certificate issued by a specific CA.
    pub fn serial_number(&self) -> Vec<u8> {
        Vec::from(self.ptr.serial_number().as_slice())
    }

    /// Signature algorithm (OID)
    pub fn signature_algorithm(&self) -> String {
        self.ptr.signature_algorithm().to_string()
    }

    /// Start time of certificate validity
    pub fn valid_from(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_from().as_slice())
    }

    /// End time of certificate validity
    pub fn valid_to(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_to().as_slice())
    }

    /// Issuer information
    pub fn issuer(&self) -> String {
        self.ptr.issuer().to_string()
    }

    /// Subject information
    pub fn subject(&self) -> String {
        self.ptr.subject().to_string()
    }

    /// The raw x509 bytes (DER encoded)
    pub fn raw(&self) -> Vec<u8> {
        Vec::from(self.ptr.raw().as_slice())
    }

    /// Return the underlying public-key scheme
    pub fn key_type(&self) -> KeyType {
        KeyType::from(self.ptr.key_type())
    }
    pub fn is_ca(&self) -> bool {
        self.ptr.is_ca()
    }

    /// The signature of the certificate
    pub fn signature(&self) -> Vec<u8> {
        Vec::from(self.ptr.signature().as_slice())
    }

    /// **If** the underlying public-key scheme is RSA, return the RSA information.
    pub fn rsa_info(&self) -> Option<RsaInfo> {
        into_optional(self.ptr.rsa_info())
    }

    /// Try to decrypt the given signature and check if it matches the given hash according to
    /// the hash algorithm provided
    pub fn check_signature(&self, hash: &[u8], signature: &[u8], digest: Algorithms) -> bool {
        unsafe {
            self.ptr.check_signature(
                hash.as_ptr(),
                hash.len(),
                signature.as_ptr(),
                signature.len(),
                digest.into(),
            )
        }
    }

    /// Verify that this certificate has been used **to trust** the given certificate
    pub fn verify(&self, ca: &X509) -> VerificationFlags {
        VerificationFlags::from(self.ptr.verify(ca.ptr.as_ref().unwrap()))
    }
}

declare_iterator!(
    Certificates,
    X509<'a>,
    ffi::PE_x509,
    ffi::PE_Signature,
    ffi::PE_Signature_it_certificates
);
